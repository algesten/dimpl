use thiserror::Error;

use crate::types::ctype::ContentType;
use crate::types::version::ProtocolVersion;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Too short")]
    TooShort,

    #[error("Invalid content type {0}")]
    InvalidContentType(u8),

    #[error("Epoch is not allowed to wrap")]
    WrappedEpoch,

    #[error("Too big length field {0}")]
    TooBigLength(u64),

    #[error("Unsupported TLS version {0}, {1}")]
    UnsupportedTlsVersion(u8, u8),

    #[error("Expected content type {0} but got: {1}")]
    BadContentType(ContentType, ContentType),

    #[error("Expected protocol version {0} but got: {1}")]
    BadProtocolVersion(ProtocolVersion, ProtocolVersion),

    #[error("Variable vector length must be even multiple of element")]
    IncorrectVariableVecLength,

    #[error("Incorrect number of elements in variable vector: {0}")]
    BadVariableVecSize(&'static str),

    #[error("An incoming extension is malformed")]
    BadIncomingExtension,
}
