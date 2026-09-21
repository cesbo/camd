use std::{
    net::SocketAddr,
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
    time::Duration,
};

use tokio::{
    io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
    net::TcpStream,
    sync::{
        mpsc::{
            self,
            error::TrySendError,
        },
        oneshot,
    },
    time::{
        Instant,
        timeout,
    },
};

use super::{
    crypto::{
        decrypt_message,
        derive_login_key,
        encrypt_message,
        md5_crypt,
        wire_len,
    },
    protocol::{
        CWS_NETMSGSIZE,
        HEADER_SIZE_525,
        LOGIN_INIT_SEQ_LEN,
        Packet,
        encode_payload,
        msg,
        parse_decrypted_525,
        patch_payload_len,
    },
};
use crate::{
    CardData,
    CardProvider,
    Cw,
    Error,
    RawRequest,
    Result,
};

const ECM_QUEUE_CAPACITY: usize = 1;
const EMM_QUEUE_CAPACITY: usize = 32;

#[derive(Debug, Clone)]
pub struct Config {
    pub addr: SocketAddr,
    pub username: String,
    pub password: String,
    pub des_key: [u8; 14],
    pub provider: u32,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], 15000)),
            username: String::new(),
            password: String::new(),
            des_key: [0_u8; 14],
            provider: 0,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
        }
    }
}

pub struct Client {
    ecm_tx: mpsc::Sender<EcmCommand>,
    emm_tx: mpsc::Sender<EmmCommand>,
    ecm_busy: AtomicBool,
    caid: u16,
    default_provider: u32,
}

pub struct Connection {
    stream: TcpStream,
    io_timeout: Duration,
    msg_id: u16,
    session_key: [u8; 16],
    ecm_rx: mpsc::Receiver<EcmCommand>,
    emm_rx: mpsc::Receiver<EmmCommand>,
    pending_ecm: Option<PendingEcm>,
    input_buffer: Vec<u8>,
    pub card_data: CardData,
}

struct EcmCommand {
    header: RawRequest,
    payload: Vec<u8>,
    response_tx: oneshot::Sender<Result<Option<Cw>>>,
}

struct EmmCommand {
    header: RawRequest,
    payload: Vec<u8>,
}

struct PendingEcm {
    msg_id: u16,
    deadline: Instant,
    response_tx: oneshot::Sender<Result<Option<Cw>>>,
}

struct EcmBusyGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for EcmBusyGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

struct HandshakeState {
    stream: TcpStream,
    io_timeout: Duration,
    msg_id: u16,
    session_key: [u8; 16],
    default_provider: u32,
    card_data: CardData,
}

impl Client {
    pub async fn connect(config: Config) -> Result<(Self, Connection)> {
        let handshake = perform_handshake(config).await?;
        let (ecm_tx, ecm_rx) = mpsc::channel(ECM_QUEUE_CAPACITY);
        let (emm_tx, emm_rx) = mpsc::channel(EMM_QUEUE_CAPACITY);

        let client = Self {
            ecm_tx,
            emm_tx,
            ecm_busy: AtomicBool::new(false),
            caid: handshake.card_data.caid,
            default_provider: handshake.default_provider,
        };

        let connection = Connection {
            stream: handshake.stream,
            io_timeout: handshake.io_timeout,
            msg_id: handshake.msg_id,
            session_key: handshake.session_key,
            ecm_rx,
            emm_rx,
            pending_ecm: None,
            input_buffer: Vec::with_capacity(CWS_NETMSGSIZE),
            card_data: handshake.card_data,
        };

        Ok((client, connection))
    }

    /// Sends one ECM and waits for the control words, `None` when the server has
    /// no key for it. Only one ECM may be in flight per connection.
    pub async fn send_ecm(&self, header: RawRequest, section: &[u8]) -> Result<Option<Cw>> {
        check_section(section)?;

        if self
            .ecm_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Protocol("previous ECM request is still pending"));
        }

        let _guard = EcmBusyGuard {
            flag: &self.ecm_busy,
        };

        let mut payload = section.to_vec();
        patch_payload_len(&mut payload);
        let (response_tx, response_rx) = oneshot::channel();
        let command = EcmCommand {
            header: self.resolve(header),
            payload,
            response_tx,
        };

        self.ecm_tx
            .send(command)
            .await
            .map_err(|_| Error::Protocol("connection task is not running"))?;

        response_rx
            .await
            .map_err(|_| Error::Protocol("ECM response channel was closed"))?
    }

    /// Queues an EMM without waiting.
    pub fn send_emm(&self, header: RawRequest, section: &[u8]) -> Result<()> {
        check_section(section)?;

        let mut payload = section.to_vec();
        patch_payload_len(&mut payload);
        let command = EmmCommand {
            header: self.resolve(header),
            payload,
        };

        self.emm_tx.try_send(command).map_err(|err| match err {
            TrySendError::Full(_) => Error::Protocol("EMM queue is full"),
            TrySendError::Closed(_) => Error::Protocol("connection task is not running"),
        })
    }

    /// Zero caid or provider means "the card's own".
    fn resolve(&self, header: RawRequest) -> RawRequest {
        RawRequest {
            sid: header.sid,
            caid: if header.caid == 0 {
                self.caid
            } else {
                header.caid
            },
            provider: if header.provider == 0 {
                self.default_provider
            } else {
                header.provider
            },
        }
    }
}

/// Rejects a section the connection task could not send, so a bad packet fails
/// the caller instead of the connection.
fn check_section(section: &[u8]) -> Result<()> {
    if section.len() < 3 {
        return Err(Error::InvalidData(
            "section must include at least 3 bytes".to_string(),
        ));
    }

    if wire_len(HEADER_SIZE_525 + section.len()) >= CWS_NETMSGSIZE {
        return Err(Error::InvalidData(format!(
            "section of {} bytes does not fit a newcamd message",
            section.len()
        )));
    }

    Ok(())
}

impl Connection {
    /// Serves the connection until the server fails or the `Client` is dropped,
    /// which closes both command channels.
    pub async fn run(mut self) -> Result<()> {
        loop {
            while let Some(packet) = self.read_buffered_network_message()? {
                self.handle_server_packet(packet).await?;
            }

            tokio::select! {
                read = read_into_buffer(&mut self.stream, &mut self.input_buffer, None) => {
                    read?;
                }
                () = tokio::time::sleep_until(self.pending_ecm.as_ref().map(|pending| pending.deadline).unwrap_or_else(Instant::now)), if self.pending_ecm.is_some() => {
                    let pending = self.pending_ecm.take().expect("ECM is pending while its timeout branch is enabled");
                    let _ = pending.response_tx.send(Err(Error::Timeout));
                }
                command = self.ecm_rx.recv() => {
                    let Some(command) = command else { return Ok(()) };
                    self.send_ecm_command(command).await?;
                }
                command = self.emm_rx.recv() => {
                    let Some(command) = command else { return Ok(()) };
                    self.send_emm_command(command).await?;
                }
            }
        }
    }

    fn read_buffered_network_message(&mut self) -> Result<Option<Packet>> {
        let Some(packet) =
            parse_buffered_network_message(&mut self.input_buffer, &self.session_key)?
        else {
            return Ok(None);
        };

        Ok(Some(packet))
    }

    async fn handle_server_packet(&mut self, packet: Packet) -> Result<()> {
        if packet.command == msg::MSG_KEEPALIVE {
            self.send_keepalive_response(&packet).await?;
            return Ok(());
        }

        if msg::EMM_TABLE_ID_RANGE.contains(&packet.command) {
            return Ok(());
        }

        let should_consume_ecm = self
            .pending_ecm
            .as_ref()
            .map(|pending| pending.msg_id == packet.header.msg_id)
            .unwrap_or(false);

        if !should_consume_ecm {
            // Unknown or unexpected packet, ignore it instead of killing the connection.
            return Ok(());
        }

        let pending = self.pending_ecm.take().unwrap();
        let response = decode_ecm_response(packet);
        let _ = pending.response_tx.send(response);
        Ok(())
    }

    async fn send_keepalive_response(&mut self, packet: &Packet) -> Result<()> {
        let payload = encode_payload(msg::MSG_KEEPALIVE, &[]);
        let _ = send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &payload,
            RawRequest {
                sid: packet.header.sid,
                caid: packet.header.caid,
                provider: packet.header.provider,
            },
            self.io_timeout,
        )
        .await?;

        Ok(())
    }

    async fn send_ecm_command(&mut self, command: EcmCommand) -> Result<()> {
        if self.pending_ecm.is_some() {
            return Err(Error::Protocol(
                "received a new ECM while another is pending",
            ));
        }

        let msg_id = send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &command.payload,
            command.header,
            self.io_timeout,
        )
        .await?;

        self.pending_ecm = Some(PendingEcm {
            msg_id,
            deadline: Instant::now() + self.io_timeout,
            response_tx: command.response_tx,
        });

        Ok(())
    }

    async fn send_emm_command(&mut self, command: EmmCommand) -> Result<()> {
        let _ = send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &command.payload,
            command.header,
            self.io_timeout,
        )
        .await?;

        Ok(())
    }
}

async fn perform_handshake(config: Config) -> Result<HandshakeState> {
    if config.username.is_empty() || config.password.is_empty() {
        return Err(Error::InvalidData(
            "username and password must not be empty".to_string(),
        ));
    }

    let configured_provider = config.provider;
    let mut stream = timeout(config.connect_timeout, TcpStream::connect(config.addr)).await??;

    let mut keymod = [0_u8; LOGIN_INIT_SEQ_LEN];
    timeout(config.io_timeout, stream.read_exact(&mut keymod)).await??;

    let login_key = derive_login_key(&config.des_key, &keymod)?;
    let password_crypt = md5_crypt(&config.password, "abcdefgh");

    let mut login_data = Vec::with_capacity(config.username.len() + password_crypt.len() + 2);
    login_data.extend_from_slice(config.username.as_bytes());
    login_data.push(0);
    login_data.extend_from_slice(password_crypt.as_bytes());
    login_data.push(0);

    let login_payload = encode_payload(msg::MSG_CLIENT_2_SERVER_LOGIN, &login_data);
    let _ = send_network_message(
        &mut stream,
        None,
        &login_key,
        &login_payload,
        RawRequest::default(),
        config.io_timeout,
    )
    .await?;

    let login_answer =
        read_network_handshake_msg(&mut stream, &login_key, Some(config.io_timeout)).await?;
    let mut msg_id = login_answer.header.msg_id;

    if login_answer.command == msg::MSG_CLIENT_2_SERVER_LOGIN_NAK {
        return Err(Error::AuthenticationFailed);
    }
    if login_answer.command != msg::MSG_CLIENT_2_SERVER_LOGIN_ACK {
        return Err(Error::Protocol("expected LOGIN_ACK packet"));
    }

    let session_key = derive_login_key(&config.des_key, password_crypt.as_bytes())?;
    let card_data_req = encode_payload(msg::MSG_CARD_DATA_REQ, &[]);
    let _ = send_network_message(
        &mut stream,
        Some(&mut msg_id),
        &session_key,
        &card_data_req,
        RawRequest::default(),
        config.io_timeout,
    )
    .await?;

    let card_data_answer =
        read_network_handshake_msg(&mut stream, &session_key, Some(config.io_timeout)).await?;
    if card_data_answer.command != msg::MSG_CARD_DATA {
        return Err(Error::Protocol("expected CARD_DATA packet"));
    }

    let card_caid = card_data_answer
        .data
        .get(1 .. 3)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .ok_or(Error::Protocol("invalid CARD_DATA payload"))?;

    let ua = card_data_answer
        .data
        .get(3 .. 11)
        .ok_or(Error::Protocol("invalid CARD_DATA payload"))?
        .try_into()
        .map_err(|_| Error::Protocol("invalid CARD_DATA payload"))?;

    let provider_count = card_data_answer
        .data
        .get(11)
        .copied()
        .ok_or(Error::Protocol("invalid CARD_DATA payload"))? as usize;
    let provider_data = card_data_answer
        .data
        .get(12 ..)
        .ok_or(Error::Protocol("invalid CARD_DATA payload"))?;
    let providers = provider_data
        .chunks_exact(11)
        .take(provider_count)
        .map(|entry| CardProvider {
            ident: [entry[0], entry[1], entry[2]],
            sa: entry[3 .. 11]
                .try_into()
                .expect("provider entry has 8-byte SA"),
        })
        .collect::<Vec<_>>();
    if providers.len() != provider_count {
        return Err(Error::Protocol("invalid CARD_DATA provider data"));
    }
    let default_provider = configured_provider;

    Ok(HandshakeState {
        stream,
        io_timeout: config.io_timeout,
        msg_id,
        session_key,
        default_provider,
        card_data: CardData {
            caid: card_caid,
            au: card_data_answer.data[0] == 1,
            ua,
            providers,
        },
    })
}

fn decode_ecm_response(packet: Packet) -> Result<Option<Cw>> {
    if packet.data.is_empty() {
        return Ok(None);
    }
    let cw = packet.data.get(.. 16).ok_or(Error::Protocol(
        "ECM response payload is shorter than 16-byte CW",
    ))?;
    Ok(Some(cw.try_into().expect("16-byte slice")))
}

async fn send_network_message(
    stream: &mut TcpStream,
    msg_id: Option<&mut u16>,
    des_key: &[u8; 16],
    payload: &[u8],
    header: RawRequest,
    io_timeout: Duration,
) -> Result<u16> {
    if payload.len() < 3 {
        return Err(Error::Protocol("payload must be at least 3 bytes"));
    }

    let mut netbuf = Vec::with_capacity(CWS_NETMSGSIZE);
    netbuf.resize(HEADER_SIZE_525, 0);
    netbuf.extend_from_slice(payload);

    let current_msg_id = if let Some(counter) = msg_id {
        *counter = counter.wrapping_add(1);
        *counter
    } else {
        0
    };

    netbuf[2 .. 4].copy_from_slice(&current_msg_id.to_be_bytes());
    netbuf[4 .. 6].copy_from_slice(&header.sid.to_be_bytes());
    netbuf[6 .. 8].copy_from_slice(&header.caid.to_be_bytes());
    netbuf[8 .. 11].copy_from_slice(&header.provider.to_be_bytes()[1 ..]);

    let mut to_encrypt = netbuf;
    let plain_len = to_encrypt.len();
    let wire_len = plain_len - 2;
    to_encrypt[0] = ((wire_len >> 8) & 0xFF) as u8;
    to_encrypt[1] = (wire_len & 0xFF) as u8;

    encrypt_message(&mut to_encrypt, des_key)?;

    let encrypted_wire_len = to_encrypt.len() - 2;
    to_encrypt[0] = ((encrypted_wire_len >> 8) & 0xFF) as u8;
    to_encrypt[1] = (encrypted_wire_len & 0xFF) as u8;

    timeout(io_timeout, stream.write_all(&to_encrypt)).await??;

    Ok(current_msg_id)
}

async fn read_network_handshake_msg(
    stream: &mut TcpStream,
    des_key: &[u8; 16],
    io_timeout: Option<Duration>,
) -> Result<Packet> {
    let mut input_buffer = Vec::with_capacity(CWS_NETMSGSIZE);

    loop {
        if let Some(packet) = parse_buffered_network_message(&mut input_buffer, des_key)? {
            return Ok(packet);
        }

        read_into_buffer(stream, &mut input_buffer, io_timeout).await?;
    }
}

async fn read_into_buffer(
    stream: &mut TcpStream,
    input_buffer: &mut Vec<u8>,
    io_timeout: Option<Duration>,
) -> Result<()> {
    let read = if let Some(timeout_duration) = io_timeout {
        timeout(timeout_duration, stream.read_buf(input_buffer)).await??
    } else {
        stream.read_buf(input_buffer).await?
    };

    if read == 0 {
        return Err(Error::Protocol("connection closed while reading packet"));
    }

    Ok(())
}

fn parse_buffered_network_message(
    input_buffer: &mut Vec<u8>,
    des_key: &[u8; 16],
) -> Result<Option<Packet>> {
    if input_buffer.len() < 2 {
        return Ok(None);
    }

    let frame_len = u16::from_be_bytes([input_buffer[0], input_buffer[1]]) as usize;
    let total_len = frame_len + 2;
    if total_len > CWS_NETMSGSIZE {
        return Err(Error::Protocol(
            "received frame is larger than CWS_NETMSGSIZE",
        ));
    }
    if input_buffer.len() < total_len {
        return Ok(None);
    }

    let plain_len = decrypt_message(&mut input_buffer[.. total_len], des_key)?;
    let packet = parse_decrypted_525(&input_buffer[.. plain_len]).ok_or(Error::Protocol(
        "failed to parse decrypted newcamd525 packet",
    ))?;
    input_buffer.drain(.. total_len);

    Ok(Some(packet))
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn send_emm_reports_full_and_closed_queue() {
        let (ecm_tx, _ecm_rx) = mpsc::channel(1);
        let (emm_tx, emm_rx) = mpsc::channel(1);
        let client = Client {
            ecm_tx,
            emm_tx,
            ecm_busy: AtomicBool::new(false),
            caid: 0x0100,
            default_provider: 0,
        };
        let emm = [0x82, 0x70, 0x00, 0xAA];

        assert!(client.send_emm(RawRequest::default(), &emm).is_ok());
        assert!(matches!(
            client.send_emm(RawRequest::default(), &emm),
            Err(Error::Protocol("EMM queue is full"))
        ));

        drop(emm_rx);
        assert!(matches!(
            client.send_emm(RawRequest::default(), &emm),
            Err(Error::Protocol("connection task is not running"))
        ));
    }

    #[tokio::test]
    async fn run_exits_when_client_is_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_server, _) = listener.accept().await.unwrap();

        let (ecm_tx, ecm_rx) = mpsc::channel(1);
        let (emm_tx, emm_rx) = mpsc::channel(1);
        let connection = Connection {
            stream,
            io_timeout: Duration::from_secs(1),
            msg_id: 0,
            session_key: [0; 16],
            ecm_rx,
            emm_rx,
            pending_ecm: None,
            input_buffer: Vec::new(),
            card_data: CardData {
                caid: 0,
                au: false,
                ua: [0; 8],
                providers: Vec::new(),
            },
        };
        let task = tokio::spawn(connection.run());

        drop((ecm_tx, emm_tx));
        let result = timeout(Duration::from_secs(1), task)
            .await
            .expect("run must exit once the senders are gone")
            .unwrap();
        assert!(result.is_ok());
    }
}
