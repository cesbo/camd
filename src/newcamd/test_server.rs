//! A card server for tests: accepts the login of one account, reports one card and holds the
//! connection until the client closes it. ECM and EMM are read and not answered.

use std::{
    io,
    net::SocketAddr,
    time::Duration,
};

use tokio::{
    io::AsyncWriteExt,
    net::{
        TcpListener,
        TcpStream,
    },
    task::JoinHandle,
};

use super::{
    client::{
        LOGIN_SALT,
        read_network_handshake_msg,
        send_network_message,
    },
    crypto::{
        derive_login_key,
        md5_crypt,
    },
    protocol::{
        LOGIN_INIT_SEQ_LEN,
        encode_payload,
        msg,
    },
};
use crate::{
    CardData,
    Error,
    RawRequest,
    Result,
};

const KEYMOD: [u8; LOGIN_INIT_SEQ_LEN] = [0xA5; LOGIN_INIT_SEQ_LEN];
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The account the server accepts and the card it reports.
#[derive(Debug, Clone)]
pub struct TestCard {
    pub username: String,
    pub password: String,
    pub des_key: [u8; 14],
    pub card: CardData,
}

/// Listens on a free loopback port until dropped; connections already served outlive it.
pub struct TestServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl TestServer {
    pub async fn start(card: TestCard) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let card = card.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, &card).await;
                });
            }
        });

        Ok(Self { addr, task })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn send(stream: &mut TcpStream, key: &[u8; 16], command: u8, data: &[u8]) -> Result<()> {
    let payload = encode_payload(command, data);
    send_network_message(
        stream,
        None,
        key,
        &payload,
        RawRequest::default(),
        IO_TIMEOUT,
    )
    .await?;
    Ok(())
}

async fn serve(mut stream: TcpStream, card: &TestCard) -> Result<()> {
    stream.write_all(&KEYMOD).await?;

    let login_key = derive_login_key(&card.des_key, &KEYMOD)?;
    let login = read_network_handshake_msg(&mut stream, &login_key, Some(IO_TIMEOUT)).await?;
    let password = md5_crypt(&card.password, LOGIN_SALT);
    let mut fields = login.data.split(|&byte| byte == 0);
    let accepted = login.command == msg::MSG_CLIENT_2_SERVER_LOGIN
        && fields.next() == Some(card.username.as_bytes())
        && fields.next() == Some(password.as_bytes());
    if !accepted {
        return send(
            &mut stream,
            &login_key,
            msg::MSG_CLIENT_2_SERVER_LOGIN_NAK,
            &[],
        )
        .await;
    }
    send(
        &mut stream,
        &login_key,
        msg::MSG_CLIENT_2_SERVER_LOGIN_ACK,
        &[],
    )
    .await?;

    let session_key = derive_login_key(&card.des_key, password.as_bytes())?;
    let request = read_network_handshake_msg(&mut stream, &session_key, Some(IO_TIMEOUT)).await?;
    if request.command != msg::MSG_CARD_DATA_REQ {
        return Err(Error::Protocol("expected CARD_DATA_REQ packet"));
    }

    let mut data = vec![u8::from(card.card.au)];
    data.extend_from_slice(&card.card.caid.to_be_bytes());
    data.extend_from_slice(&card.card.ua);
    data.push(card.card.providers.len() as u8);
    for provider in &card.card.providers {
        data.extend_from_slice(&provider.ident);
        data.extend_from_slice(&provider.sa);
    }
    send(&mut stream, &session_key, msg::MSG_CARD_DATA, &data).await?;

    while read_network_handshake_msg(&mut stream, &session_key, None)
        .await
        .is_ok()
    {}
    Ok(())
}
