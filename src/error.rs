//! Public error type returned by the high-level DTLS API.

#[derive(Debug)]
/// Errors returned by DTLS processing functions.
pub enum Error {
    /// Parser requested more data
    ParseIncomplete,
    /// Parser encountered an error kind from nom
    ParseError(nom::error::ErrorKind),
    /// Unexpected DTLS message
    UnexpectedMessage(String),
    /// Cryptographic operation failed
    CryptoError(String),
    /// Certificate validation failed
    CertificateError(String),
    /// Security policy violation
    SecurityError(String),
    /// Incoming queue exceeded capacity
    ReceiveQueueFull,
    /// Outgoing queue exceeded capacity
    TransmitQueueFull,
    /// Missing fields when parsing ServerHello
    IncompleteServerHello,
    /// Something timed out
    Timeout(&'static str),
    /// Configuration error (e.g., invalid crypto provider)
    ConfigError(String),
}

impl<'a> From<nom::Err<nom::error::Error<&'a [u8]>>> for Error {
    fn from(value: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        match value {
            nom::Err::Incomplete(_) => Error::ParseIncomplete,
            nom::Err::Error(x) => Error::ParseError(x.code),
            nom::Err::Failure(x) => Error::ParseError(x.code),
        }
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ParseIncomplete => write!(f, "parse incomplete"),
            Error::ParseError(kind) => write!(f, "parse error: {:?}", kind),
            Error::UnexpectedMessage(msg) => write!(f, "unexpected message: {}", msg),
            Error::CryptoError(msg) => write!(f, "crypto error: {}", msg),
            Error::CertificateError(msg) => write!(f, "certificate error: {}", msg),
            Error::SecurityError(msg) => write!(f, "security error: {}", msg),
            Error::ReceiveQueueFull => write!(f, "receive queue full"),
            Error::TransmitQueueFull => write!(f, "transmit queue full"),
            Error::IncompleteServerHello => write!(f, "incomplete ServerHello"),
            Error::Timeout(what) => write!(f, "timeout: {}", what),
            Error::ConfigError(msg) => write!(f, "config error: {}", msg),
        }
    }
}
