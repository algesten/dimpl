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
    /// PSK (Pre-Shared Key) error
    PskError(String),
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
    /// The connection has been closed (close_notify sent or received).
    ConnectionClosed,
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
    /// Application data exceeds the DTLS record-size ceiling.
    ///
    /// RFC 6347 §4.1.1 / RFC 9146 §5 cap `DTLSPlaintext` /
    /// `DTLSInnerPlaintext` at `2^14` bytes. Callers must fragment larger
    /// payloads before calling `send_application_data`.
    Oversized(usize),
    /// Configured MTU is too small to hold even a single record header plus
    /// a handshake-header byte of body. Encountered when negotiated CID
    /// bytes + AEAD overhead + handshake/record headers already fill or
    /// exceed `Config::mtu()`. Terminal for this association: the caller
    /// must either raise MTU or renegotiate with a shorter peer CID
    /// (dimpl rejects renegotiation, so in practice the association
    /// cannot make handshake progress).
    MtuTooSmall {
        /// Overhead bytes consumed by headers + CID + AEAD + handshake.
        overhead: usize,
        /// Configured MTU as reported by `Config::mtu()`.
        mtu: usize,
    },
    /// DTLS 1.2 sequence-number space is exhausted for this epoch.
    ///
    /// RFC 6347 §4.1: implementations MUST abandon the association or
    /// rehandshake before the 48-bit wire sequence number wraps. dimpl
    /// does not implement renegotiation or rekey, so this is terminal.
    SequenceNumberExhausted {
        /// The epoch whose sequence space is exhausted.
        epoch: u16,
        /// The next sequence number that would have been emitted.
        sequence: u64,
    },
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
            Error::PskError(msg) => write!(f, "psk error: {}", msg),
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
            Error::ConnectionClosed => write!(f, "connection closed"),
            Error::Dtls12Fallback => {
                write!(f, "dtls 1.2 fallback (internal)")
            }
            Error::Oversized(n) => {
                write!(
                    f,
                    "payload {} bytes exceeds DTLS record-size ceiling (16384)",
                    n
                )
            }
            Error::MtuTooSmall { overhead, mtu } => {
                write!(
                    f,
                    "MTU {} cannot fit DTLS record overhead of {} bytes",
                    mtu, overhead
                )
            }
            Error::SequenceNumberExhausted { epoch, sequence } => {
                write!(
                    f,
                    "DTLS 1.2 sequence number exhausted (epoch={}, seq={})",
                    epoch, sequence
                )
            }
        }
    }
}
