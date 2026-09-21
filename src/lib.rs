mod error;
pub mod newcamd;

pub use error::{
    Error,
    Result,
};

/// Control word pair as the server returns it: even and odd, 8 bytes each.
pub type Cw = [u8; 16];

/// Addressing of an ECM or EMM: the service, CA system and provider it belongs to.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawRequest {
    pub sid: u16,
    pub caid: u16,
    pub provider: u32,
}

/// What the server reports about the card behind the connection.
#[derive(Debug, Clone)]
pub struct CardData {
    pub caid: u16,
    pub au: bool,
    pub ua: [u8; 8],
    pub providers: Vec<CardProvider>,
}

#[derive(Debug, Clone, Copy)]
pub struct CardProvider {
    pub ident: [u8; 3],
    pub sa: [u8; 8],
}
