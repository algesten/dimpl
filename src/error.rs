use thiserror::Error;

use crate::types::ctype::ContentType;
use crate::types::version::ProtocolVersion;

#[derive(Debug, Clone, Error)]
pub enum DimplError {
    #[error("Too short")]
    TooShort,

    #[error("Invalid content type {0}")]
    InvalidContentType(u8),

    #[error("Epoch is not allowed to wrap")]
    WrappedEpoch,

    #[error("Too big length field (> 16_384) {0}")]
    TooBigLength(usize),

    #[error("Too big dtls sequene field (max 48 bits) {0}")]
    TooBigDtlsSeq(u64),

    #[error("Unsupported TLS version {0}, {1}")]
    UnsupportedTlsVersion(u8, u8),

    #[error("Expected content type {0} but got: {1}")]
    BadContentType(ContentType, ContentType),

    #[error("Expected protocol version {0} but got: {1}")]
    BadProtocolVersion(ProtocolVersion, ProtocolVersion),

    #[error("Variable vector length must be even multiple of element")]
    IncorrectVariableVecLength,

    #[error("Incorrect number of elements in variable vector")]
    BadVariableVecSize,
}
