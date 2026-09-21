# camd

Async Rust client for conditional access card server protocols.

Protocols:

- newcamd (newcamd525): login with the 14-byte DES key and md5-crypt
  password, 3DES-EDE2-CBC session, CARD_DATA, ECM and EMM exchange,
  server keepalive.

The crate implements the client side of the protocol only.

## Usage

```rust
use camd::{RawRequest, newcamd};

let config = newcamd::Config {
    addr: "10.0.0.5:15000".parse()?,
    username: "user".into(),
    password: "pass".into(),
    des_key: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
    ..Default::default()
};

let (client, connection) = newcamd::Client::connect(config).await?;
let card = connection.card_data.clone();
tokio::spawn(connection.run());

let header = RawRequest { sid: 1, caid: card.caid, provider: 0 };
if let Some(cw) = client.send_ecm(header, &ecm_section).await? {
    // cw[..8] even, cw[8..] odd
}
client.send_emm(RawRequest { sid: 0, ..header }, &emm_section)?;
```

`Connection::run` serves the socket until the server fails or the `Client`
is dropped. One ECM is in flight at a time; queueing, reconnection and EMM
filtering by `CardData` belong to the caller.
