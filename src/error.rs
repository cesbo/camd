use std::fmt::{
    Display,
    Formatter,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Protocol(&'static str),
    AuthenticationFailed,
    InvalidData(String),
    /// Connect, read, write or ECM reply did not complete within `io_timeout`.
    Timeout,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Protocol(msg) => write!(f, "Protocol error: {msg}"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::InvalidData(msg) => write!(f, "Invalid data: {msg}"),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::Timeout
    }
}
