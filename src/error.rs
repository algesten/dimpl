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
