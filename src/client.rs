use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout};

use crate::crypto::{decrypt_message, derive_login_key, encrypt_message, md5_crypt};
use crate::error::{NewcamdError, Result};
use crate::protocol::msg;
use crate::protocol::{
    CWS_NETMSGSIZE, HEADER_SIZE_525, LOGIN_INIT_SEQ_LEN, NewcamdPacket, encode_payload,
    parse_decrypted_525, patch_payload_len,
};

const ECM_QUEUE_CAPACITY: usize = 1;
const EMM_QUEUE_CAPACITY: usize = 32;

#[derive(Debug, Clone)]
pub struct NewcamdConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub des_key_14: [u8; 14],
    pub provider: u32,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Default for NewcamdConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 15000,
            username: String::new(),
            password: String::new(),
            des_key_14: [0_u8; 14],
            provider: 0,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RawRequest {
    pub sid: u16,
    pub caid: u16,
    pub provider: u32,
}

#[derive(Debug, Clone)]
pub struct EcmRequest {
    pub sid: u16,
    pub caid: u16,
    pub provider: u32,
    pub section: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EcmResponse {
    pub found: bool,
    pub cw: [u8; 16],
    pub packet: NewcamdPacket,
}

#[derive(Debug, Clone)]
pub struct CardData {
    pub caid: u16,
    pub au: bool,
    pub ua: [u8; 8],
    pub providers: Vec<CardProvider>,
    pub provider_count: usize,
    pub raw_payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct CardProvider {
    pub ident: [u8; 3],
    pub sa: [u8; 8],
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
    read_timeout: Duration,
    msg_id: u16,
    session_key: [u8; 16],
    ecm_rx: mpsc::Receiver<EcmCommand>,
    emm_rx: mpsc::Receiver<EmmCommand>,
    pending_ecm: Option<PendingEcm>,
    input_buffer: Vec<u8>,
    pub card_data: CardData,
}

struct EcmCommand {
    sid: u16,
    caid: u16,
    provider: u32,
    payload: Vec<u8>,
    response_tx: oneshot::Sender<Result<EcmResponse>>,
}

struct EmmCommand {
    sid: u16,
    caid: u16,
    provider: u32,
    payload: Vec<u8>,
}

struct PendingEcm {
    msg_id: u16,
    deadline: Instant,
    response_tx: oneshot::Sender<Result<EcmResponse>>,
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
    read_timeout: Duration,
    msg_id: u16,
    session_key: [u8; 16],
    default_provider: u32,
    card_data: CardData,
}

impl Client {
    pub async fn connect(config: NewcamdConfig) -> Result<(Self, Connection)> {
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
            read_timeout: handshake.read_timeout,
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

    pub fn caid(&self) -> u16 {
        self.caid
    }

    pub fn default_provider(&self) -> u32 {
        self.default_provider
    }

    pub async fn send_ecm(&self, req: &EcmRequest) -> Result<EcmResponse> {
        if req.section.len() < 3 {
            return Err(NewcamdError::InvalidData(
                "ECM section must include at least 3 bytes".to_string(),
            ));
        }

        if self
            .ecm_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(NewcamdError::Protocol(
                "previous ECM request is still pending",
            ));
        }

        let _guard = EcmBusyGuard {
            flag: &self.ecm_busy,
        };

        let mut payload = req.section.clone();
        patch_payload_len(&mut payload);
        let (response_tx, response_rx) = oneshot::channel();
        let command = EcmCommand {
            sid: req.sid,
            caid: self.resolve_caid(req.caid),
            provider: self.resolve_provider(req.provider),
            payload,
            response_tx,
        };

        self.ecm_tx
            .send(command)
            .await
            .map_err(|_| NewcamdError::Protocol("connection task is not running"))?;

        response_rx
            .await
            .map_err(|_| NewcamdError::Protocol("ECM response channel was closed"))?
    }

    pub async fn send_emm(&self, section: &[u8], sid: u16, caid: u16, provider: u32) -> Result<()> {
        if section.len() < 3 {
            return Err(NewcamdError::InvalidData(
                "EMM section must include at least 3 bytes".to_string(),
            ));
        }

        let mut payload = section.to_vec();
        patch_payload_len(&mut payload);
        let command = EmmCommand {
            sid,
            caid: self.resolve_caid(caid),
            provider: self.resolve_provider(provider),
            payload,
        };

        self.emm_tx
            .send(command)
            .await
            .map_err(|_| NewcamdError::Protocol("connection task is not running"))
    }

    fn resolve_caid(&self, request_caid: u16) -> u16 {
        if request_caid == 0 {
            self.caid
        } else {
            request_caid
        }
    }

    fn resolve_provider(&self, request_provider: u32) -> u32 {
        if request_provider == 0 {
            self.default_provider
        } else {
            request_provider
        }
    }
}

impl Connection {
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
                    let _ = pending.response_tx.send(Err(NewcamdError::Protocol("timeout while waiting for ECM response")));
                }
                Some(command) = self.ecm_rx.recv() => {
                    self.send_ecm_command(command).await?;
                }
                Some(command) = self.emm_rx.recv() => {
                    self.send_emm_command(command).await?;
                }
            }
        }
    }

    fn read_buffered_network_message(&mut self) -> Result<Option<NewcamdPacket>> {
        let Some(packet) =
            parse_buffered_network_message(&mut self.input_buffer, &self.session_key)?
        else {
            return Ok(None);
        };

        Ok(Some(packet))
    }

    async fn handle_server_packet(&mut self, packet: NewcamdPacket) -> Result<()> {
        if packet.command == msg::MSG_KEEPALIVE {
            self.send_keepalive_response(&packet).await?;
            return Ok(());
        }

        if msg::EMM_TABLE_ID_RANGE.contains(&packet.command) {
            // EMM packet received, but we don't have any EMM requests pending, so we just ignore it ???
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

    async fn send_keepalive_response(&mut self, packet: &NewcamdPacket) -> Result<()> {
        let payload = encode_payload(msg::MSG_KEEPALIVE, &[]);
        let _ = send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &payload,
            packet.header.sid,
            packet.header.caid,
            packet.header.provider,
        )
        .await?;

        Ok(())
    }

    async fn send_ecm_command(&mut self, command: EcmCommand) -> Result<()> {
        if self.pending_ecm.is_some() {
            return Err(NewcamdError::Protocol(
                "received a new ECM while another is pending",
            ));
        }

        let msg_id = send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &command.payload,
            command.sid,
            command.caid,
            command.provider,
        )
        .await?;

        self.pending_ecm = Some(PendingEcm {
            msg_id,
            deadline: Instant::now() + self.read_timeout,
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
            command.sid,
            command.caid,
            command.provider,
        )
        .await?;

        Ok(())
    }
}

async fn perform_handshake(config: NewcamdConfig) -> Result<HandshakeState> {
    if config.username.is_empty() || config.password.is_empty() {
        return Err(NewcamdError::InvalidData(
            "username and password must not be empty".to_string(),
        ));
    }

    let endpoint = format!("{}:{}", config.host, config.port);
    let configured_provider = config.provider;
    let mut stream = timeout(config.connect_timeout, TcpStream::connect(endpoint))
        .await
        .map_err(|_| NewcamdError::Protocol("connect timeout"))??;

    let mut keymod = [0_u8; LOGIN_INIT_SEQ_LEN];
    timeout(config.read_timeout, stream.read_exact(&mut keymod))
        .await
        .map_err(|_| NewcamdError::Protocol("timeout while reading server init sequence"))??;

    let login_key = derive_login_key(&config.des_key_14, &keymod)?;
    let password_crypt = md5_crypt(&config.password, "abcdefgh");

    let mut login_data = Vec::with_capacity(config.username.len() + password_crypt.len() + 2);
    login_data.extend_from_slice(config.username.as_bytes());
    login_data.push(0);
    login_data.extend_from_slice(password_crypt.as_bytes());
    login_data.push(0);

    let login_payload = encode_payload(msg::MSG_CLIENT_2_SERVER_LOGIN, &login_data);
    let _ = send_network_message(&mut stream, None, &login_key, &login_payload, 0, 0, 0).await?;

    let login_answer =
        read_network_handshake_msg(&mut stream, &login_key, Some(config.read_timeout)).await?;
    let mut msg_id = login_answer.header.msg_id;

    if login_answer.command == msg::MSG_CLIENT_2_SERVER_LOGIN_NAK {
        return Err(NewcamdError::AuthenticationFailed);
    }
    if login_answer.command != msg::MSG_CLIENT_2_SERVER_LOGIN_ACK {
        return Err(NewcamdError::Protocol("expected LOGIN_ACK packet"));
    }

    let session_key = derive_login_key(&config.des_key_14, password_crypt.as_bytes())?;
    let card_data_req = encode_payload(msg::MSG_CARD_DATA_REQ, &[]);
    let _ = send_network_message(
        &mut stream,
        Some(&mut msg_id),
        &session_key,
        &card_data_req,
        0,
        0,
        0,
    )
    .await?;

    let card_data_answer =
        read_network_handshake_msg(&mut stream, &session_key, Some(config.read_timeout)).await?;
    if card_data_answer.command != msg::MSG_CARD_DATA {
        return Err(NewcamdError::Protocol("expected CARD_DATA packet"));
    }

    let card_caid = card_data_answer
        .data
        .get(1..3)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .ok_or(NewcamdError::Protocol("invalid CARD_DATA payload"))?;

    let ua = card_data_answer
        .data
        .get(3..11)
        .ok_or(NewcamdError::Protocol("invalid CARD_DATA payload"))?
        .try_into()
        .map_err(|_| NewcamdError::Protocol("invalid CARD_DATA payload"))?;

    let provider_count = card_data_answer
        .data
        .get(11)
        .copied()
        .ok_or(NewcamdError::Protocol("invalid CARD_DATA payload"))?
        as usize;
    let provider_data = card_data_answer
        .data
        .get(12..)
        .ok_or(NewcamdError::Protocol("invalid CARD_DATA payload"))?;
    let providers = provider_data
        .chunks_exact(11)
        .take(provider_count)
        .map(|entry| CardProvider {
            ident: [entry[0], entry[1], entry[2]],
            sa: entry[3..11].try_into().expect("provider entry has 8-byte SA"),
        })
        .collect::<Vec<_>>();
    if providers.len() != provider_count {
        return Err(NewcamdError::Protocol("invalid CARD_DATA provider data"));
    }
    let default_provider = configured_provider;

    Ok(HandshakeState {
        stream,
        read_timeout: config.read_timeout,
        msg_id,
        session_key,
        default_provider,
        card_data: CardData {
            caid: card_caid,
            au: card_data_answer.data[0] == 1,
            ua,
            providers,
            provider_count,
            raw_payload: card_data_answer.data,
        },
    })
}

fn decode_ecm_response(packet: NewcamdPacket) -> Result<EcmResponse> {
    let mut cw = [0_u8; 16];
    if packet.data.is_empty() {
        return Ok(EcmResponse {
            found: false,
            cw,
            packet,
        });
    }

    if packet.data.len() < 16 {
        return Err(NewcamdError::Protocol(
            "ECM response payload is shorter than 16-byte CW",
        ));
    }

    cw.copy_from_slice(&packet.data[..16]);
    Ok(EcmResponse {
        found: true,
        cw,
        packet,
    })
}

async fn send_network_message(
    stream: &mut TcpStream,
    msg_id: Option<&mut u16>,
    des_key: &[u8; 16],
    payload: &[u8],
    sid: u16,
    caid: u16,
    provider: u32,
) -> Result<u16> {
    if payload.len() < 3 {
        return Err(NewcamdError::Protocol("payload must be at least 3 bytes"));
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

    netbuf[2..4].copy_from_slice(&current_msg_id.to_be_bytes());
    netbuf[4..6].copy_from_slice(&sid.to_be_bytes());
    netbuf[6..8].copy_from_slice(&caid.to_be_bytes());
    netbuf[8] = ((provider >> 16) & 0xFF) as u8;
    netbuf[9] = ((provider >> 8) & 0xFF) as u8;
    netbuf[10] = (provider & 0xFF) as u8;

    let mut to_encrypt = netbuf;
    let plain_len = to_encrypt.len();
    let wire_len = plain_len - 2;
    to_encrypt[0] = ((wire_len >> 8) & 0xFF) as u8;
    to_encrypt[1] = (wire_len & 0xFF) as u8;

    encrypt_message(&mut to_encrypt, des_key)?;

    let encrypted_wire_len = to_encrypt.len() - 2;
    to_encrypt[0] = ((encrypted_wire_len >> 8) & 0xFF) as u8;
    to_encrypt[1] = (encrypted_wire_len & 0xFF) as u8;

    stream.write_all(&to_encrypt).await?;

    Ok(current_msg_id)
}

async fn read_network_handshake_msg(
    stream: &mut TcpStream,
    des_key: &[u8; 16],
    read_timeout: Option<Duration>,
) -> Result<NewcamdPacket> {
    let mut input_buffer = Vec::with_capacity(CWS_NETMSGSIZE);

    loop {
        if let Some(packet) = parse_buffered_network_message(&mut input_buffer, des_key)? {
            return Ok(packet);
        }

        read_into_buffer(stream, &mut input_buffer, read_timeout).await?;
    }
}

async fn read_into_buffer(
    stream: &mut TcpStream,
    input_buffer: &mut Vec<u8>,
    read_timeout: Option<Duration>,
) -> Result<()> {
    let read = if let Some(timeout_duration) = read_timeout {
        timeout(timeout_duration, stream.read_buf(input_buffer))
            .await
            .map_err(|_| NewcamdError::Protocol("timeout while reading packet"))??
    } else {
        stream.read_buf(input_buffer).await?
    };

    if read == 0 {
        return Err(NewcamdError::Protocol(
            "connection closed while reading packet",
        ));
    }

    Ok(())
}

fn parse_buffered_network_message(
    input_buffer: &mut Vec<u8>,
    des_key: &[u8; 16],
) -> Result<Option<NewcamdPacket>> {
    if input_buffer.len() < 2 {
        return Ok(None);
    }

    let frame_len = u16::from_be_bytes([input_buffer[0], input_buffer[1]]) as usize;
    let total_len = frame_len + 2;
    if total_len > CWS_NETMSGSIZE {
        return Err(NewcamdError::Protocol(
            "received frame is larger than CWS_NETMSGSIZE",
        ));
    }
    if input_buffer.len() < total_len {
        return Ok(None);
    }

    let plain_len = decrypt_message(&mut input_buffer[..total_len], des_key)?;
    let packet = parse_decrypted_525(&input_buffer[..plain_len]).ok_or(NewcamdError::Protocol(
        "failed to parse decrypted newcamd525 packet",
    ))?;
    input_buffer.drain(..total_len);

    Ok(Some(packet))
}
