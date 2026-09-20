use std::fmt::{Display, Formatter};

pub type Result<T> = std::result::Result<T, NewcamdError>;

#[derive(Debug)]
pub enum NewcamdError {
    Io(std::io::Error),
    Protocol(&'static str),
    AuthenticationFailed,
    InvalidData(String),
    Crypto(&'static str),
}

impl Display for NewcamdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Protocol(msg) => write!(f, "Protocol error: {msg}"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::InvalidData(msg) => write!(f, "Invalid data: {msg}"),
            Self::Crypto(msg) => write!(f, "Crypto error: {msg}"),
        }
    }
}

impl std::error::Error for NewcamdError {}

impl From<std::io::Error> for NewcamdError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
