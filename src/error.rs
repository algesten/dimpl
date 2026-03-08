//! Public error type returned by the high-level DTLS API.

#[derive(Debug)]
#[non_exhaustive]
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
    /// Too many records in a single packet
    TooManyRecords,
    /// Peer attempted renegotiation (not supported)
    RenegotiationAttempt,
    /// Application data cannot be sent because the handshake is not yet complete.
    ///
    /// For auto-sense instances this means the version has not yet been
    /// resolved.  Callers should buffer the data and retry once the
    /// handshake advances.
    HandshakePending,
    /// If we are in auto-sense mode for a server and we received too
    /// many client hello fragments that haven't made a packet.
    TooManyClientHelloFragments,
    /// The DTLS 1.3 server received a ClientHello that does not offer
    /// DTLS 1.3 in `supported_versions`. In auto-sense mode the caller
    /// should fall back to a DTLS 1.2 server and replay the buffered
    /// packets.
    ///
    /// This value should never be seen outside dimpl. It's an internal
    /// value to communicate from dtls13/server.rs to lib.rs
    #[doc(hidden)]
    Dtls12Fallback,
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
            Error::TooManyRecords => write!(f, "too many records in packet"),
            Error::RenegotiationAttempt => write!(f, "peer attempted renegotiation"),
            Error::HandshakePending => {
                write!(f, "handshake pending: cannot send application data yet")
            }
            Error::TooManyClientHelloFragments => write!(f, "too many client hello fragments"),
            Error::Dtls12Fallback => {
                write!(f, "dtls 1.2 fallback (internal)")
            }
        }
    }
}
