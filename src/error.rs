//! Public error type returned by the high-level DTLS API.

use std::fmt;

use crate::dtls12::message::Dtls12CipherSuite;
use crate::types::CompressionMethod;
use crate::types::Dtls13CipherSuite;
use crate::types::HashAlgorithm;
use crate::types::NamedGroup;
use crate::types::ProtocolVersion;
use crate::types::SignatureAlgorithm;
use crate::types::SignatureScheme;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Errors returned by DTLS processing functions.
pub enum Error {
    /// Unexpected DTLS message.
    UnexpectedMessage(UnexpectedMessageError),
    /// Local state was missing data required for the requested operation.
    InvalidState(InvalidStateError),
    /// Cryptographic operation failed.
    CryptoError(CryptoError),
    /// Certificate validation failed.
    CertificateError(CertificateError),
    /// Security policy violation.
    SecurityError(SecurityError),
    /// PSK (Pre-Shared Key) error.
    PskError(PskError),
    /// Incoming queue exceeded capacity.
    ReceiveQueueFull,
    /// Outgoing queue exceeded capacity.
    TransmitQueueFull,
    /// Missing fields when parsing ServerHello.
    IncompleteServerHello,
    /// Something timed out.
    Timeout(TimeoutError),
    /// Configuration error (e.g., invalid crypto provider).
    ConfigError(ConfigError),
    /// Peer attempted renegotiation (not supported).
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
    /// value to communicate from dtls13/server.rs to lib.rs.
    #[doc(hidden)]
    Dtls12Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum UnexpectedMessageError {
    UnrecognizedAutoServerResponse,
    ServerKeyExchangeWithoutSignature,
    PskServerKeyExchangeInEcdhePath,
    EcdheServerKeyExchangeInPskPath,
    PskClientKeyExchangeInEcdhePath,
    EcdheClientKeyExchangeInPskPath,
    CertificateRequestContextTruncated,
    CertificateRequestExtensionsTruncated,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum InvalidStateError {
    NoCipherSuiteSelected,
    NoCipherSuite,
    NoClientRandom,
    NoServerRandom,
    NoSharedSecretForHandshakeKeyDerivation,
    NoServerHandshakeTrafficSecret,
    NoServerHandshakeTrafficSecretForFinished,
    NoClientHandshakeTrafficSecret,
    NoClientHandshakeTrafficSecretForFinished,
    NoHandshakeSecretForApplicationKeyDerivation,
    NoActiveKeyExchange,
    NoCurrentAppSendKeysForKeyUpdate,
    NoCurrentAppRecvKeysForKeyUpdate,
    ExporterMasterSecretNotDerived,
    Other(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CryptoError {
    NoSupportedKeyExchangeGroups,
    NoDtls12KeyExchangeGroupsConfigured,
    Epoch0SequenceNumberExhausted,
    SendSequenceNumberExhausted {
        epoch: u16,
    },
    SendKeysNotAvailable {
        epoch: u16,
    },
    RecvKeysNotAvailable {
        epoch: u16,
    },
    KeyExchangeGroupNotFound(NamedGroup),
    KeyExchangeNotInitialized,
    UnsupportedKeyExchangeGroup(NamedGroup),
    UnsupportedEcdheNamedGroup(NamedGroup),
    UnsupportedCipherSuite(Dtls12CipherSuite),
    UnsupportedHmacHash(HashAlgorithm),
    UnsupportedSignatureAlgorithm(SignatureAlgorithm),
    SignatureAlgorithmNotOfferedByClient,
    SignatureAlgorithmMismatch {
        expected: SignatureAlgorithm,
        actual: SignatureAlgorithm,
    },
    UnsupportedSignaturePair {
        signature: SignatureAlgorithm,
        hash: HashAlgorithm,
    },
    UnsupportedSignatureVerification {
        signature: SignatureAlgorithm,
        hash: HashAlgorithm,
        group: NamedGroup,
    },
    UnsupportedPublicKeyAlgorithm,
    UnsupportedEcCurve(String),
    MissingEcCurveParameter,
    InvalidEcCurveParameter,
    InvalidSubjectPublicKey,
    InvalidSignatureFormat,
    InvalidPublicKey(NamedGroup),
    InvalidPrivateKey,
    SigningKeyHashMismatch {
        key_hash: HashAlgorithm,
        requested: HashAlgorithm,
    },
    SigningKeyUnsupportedHash {
        group: NamedGroup,
        hash: HashAlgorithm,
    },
    InvalidAesGcmKeySize {
        actual: usize,
    },
    InvalidChacha20Poly1305KeySize {
        actual: usize,
    },
    InvalidAes128Ccm8KeySize {
        actual: usize,
    },
    InvalidNonce,
    InvalidNonceLength {
        expected: usize,
        actual: usize,
    },
    CiphertextTooShort {
        minimum: usize,
        actual: usize,
    },
    HkdfOutputTooLong,
    HkdfLabelTooLong,
    HkdfContextTooLong,
    HkdfOutputLengthTooLarge,
    InvalidVerifyDataLength,
    VerifyDataTooLong,
    MasterSecretTooLong,
    KeyingMaterialTooLong,
    PreMasterSecretNotAvailable,
    MasterSecretNotAvailable,
    ClientRandomNotAvailable,
    ServerRandomNotAvailable,
    ClientCipherNotInitialized,
    ServerCipherNotInitialized,
    WriteIvNotAvailable {
        is_client: bool,
    },
    UnsupportedDtls12RecordIvLen {
        len: usize,
        suite: Dtls12CipherSuite,
    },
    NoPrivateKeyConfigured,
    PskNotSet,
    ExporterMasterSecretNotDerived,
    OperationFailed(CryptoOperation),
    ProviderFailure {
        operation: CryptoOperation,
        reason: String,
    },
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CryptoOperation {
    CreateCipher,
    Encrypt,
    Decrypt,
    Sign,
    VerifySignature,
    LoadPrivateKey,
    StartKeyExchange,
    CompleteKeyExchange,
    GenerateEphemeralKey,
    ComputePublicKey,
    FillRandom,
    ComputeHmac,
    Prf,
    HkdfExtract,
    HkdfExpand,
    HkdfExpandLabel,
    DeriveEarlySecret,
    DeriveDerivedSecret,
    DeriveHandshakeSecret,
    DeriveTrafficSecret,
    DeriveMasterSecret,
    DeriveExporterMasterSecret,
    DeriveNextTrafficSecret,
    DeriveKey,
    DeriveIv,
    DeriveSequenceNumberKey,
    DeriveFinishedKey,
    ComputeVerifyData,
    VerifyData,
    ComputePskPreMasterSecret,
    ComputeCookie,
    ExtractSrtpKeyingMaterial,
    EncodeKey,
    DecodeKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CertificateError {
    NoServerCertificateReceived,
    NoClientCertificateForVerification,
    NoServerCertificateForVerification,
    ServerCertificateContextMustBeEmpty,
    ClientCertificateContextMustBeEmpty,
    UnsupportedHashAlgorithm(HashAlgorithm),
    ParseFailed,
    MissingEcCurveParameter,
    InvalidEcCurveParameter,
    UnsupportedEcCurve(String),
    InvalidSubjectPublicKey,
    PrivateKey(CryptoError),
    Verification(CryptoError),
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum SecurityError {
    UnsupportedHelloVerifyRequestVersion(ProtocolVersion),
    UnsupportedServerVersion(ProtocolVersion),
    UnsupportedClientVersion(ProtocolVersion),
    UnsupportedServerCompression(CompressionMethod),
    UnsupportedClientCompression,
    UnsupportedKeyExchangeAlgorithm,
    ServerSelectedUnknownCipherSuite,
    ServerSelectedIncompatibleCipherSuite(Dtls12CipherSuite),
    ServerSelectedDisallowedCipherSuite(Dtls12CipherSuite),
    ServerSelectedDisallowedDtls13CipherSuite(Dtls13CipherSuite),
    ExtendedMasterSecretNotNegotiated,
    NoMutuallyAcceptableCipherSuite,
    ClientHelloLegacyVersionNotDtls12,
    ServerHelloLegacyVersionNotDtls12,
    ClientHelloMissingDtls13SupportedVersions,
    ClientHelloMustOfferNullCompression,
    InvalidCookieInClientHello,
    CannotSendSecondHelloRetryRequest,
    NoCommonCipherSuite,
    NoCommonKeyExchangeGroup,
    HrrSelectedDisallowedCipherSuite,
    HrrDidNotSelectDtls13,
    ServerHelloCompressionMustBeNull,
    ServerDidNotNegotiateDtls13,
    ServerMissingKeyShare,
    ServerKeyShareGroupMismatch {
        selected: NamedGroup,
        actual: NamedGroup,
    },
    SignatureTooLarge,
    SignatureSchemeNotOffered(SignatureScheme),
    SignatureAlgorithmMismatch {
        expected: SignatureAlgorithm,
        actual: SignatureAlgorithm,
    },
    UnsupportedSignatureScheme(SignatureScheme),
    SignatureSchemeCertificateCurveMismatch {
        scheme: SignatureScheme,
        expected: NamedGroup,
        actual: NamedGroup,
    },
    ServerFinishedVerificationFailed,
    ClientFinishedVerificationFailed,
    FatalAlert {
        level: u8,
        description: u8,
    },
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum PskError {
    NoPskResolverConfigured,
    NoPskIdentityConfigured,
    ResolverReturnedNoKey,
    Other(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum TimeoutError {
    HybridClientHello,
    Connect,
    Handshake,
    Other(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ConfigError {
    NoCryptoProvider,
    MtuTooSmall { mtu: usize, minimum: usize },
    AeadEncryptionLimitTooSmall,
    NoCipherSuitesAfterFiltering,
    PskConfiguredWithoutPskCipherSuite,
    NoDtls12KeyExchangeGroupsAfterFiltering,
    NoDtls13KeyExchangeGroupsAfterFiltering,
    CryptoProvider(CryptoProviderValidationError),
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CryptoProviderValidationError {
    NoCipherSuites,
    EcdhCipherSuitesWithoutKeyExchangeGroups,
    NoDtls13CipherSuites,
    MissingHashTestVector(HashAlgorithm),
    HashProviderIncorrect(HashAlgorithm),
    PrfFailed {
        hash: HashAlgorithm,
        source: CryptoError,
    },
    PrfWrongLength {
        hash: HashAlgorithm,
        expected: usize,
        actual: usize,
    },
    MissingPrfTestVector(HashAlgorithm),
    PrfIncorrect(HashAlgorithm),
    NoSignatureValidationVector {
        hash: HashAlgorithm,
        signature: SignatureAlgorithm,
    },
    SignatureVerificationFailed {
        hash: HashAlgorithm,
        signature: SignatureAlgorithm,
        source: CryptoError,
    },
    HkdfFailed {
        suite: Dtls13CipherSuite,
        source: CryptoError,
    },
    HkdfEmptyOutput(Dtls13CipherSuite),
    NoAeadTestVector(Dtls13CipherSuite),
    AeadCreateFailed {
        suite: Dtls13CipherSuite,
        source: CryptoError,
    },
    AeadEncryptFailed {
        suite: Dtls13CipherSuite,
        source: CryptoError,
    },
    AeadEncryptWrongOutput(Dtls13CipherSuite),
    AeadDecryptFailed {
        suite: Dtls13CipherSuite,
        source: CryptoError,
    },
    AeadDecryptWrongOutput(Dtls13CipherSuite),
    NoRecordNumberEncryptionTestVector(Dtls13CipherSuite),
    RecordNumberEncryptionWrongMask(Dtls13CipherSuite),
    KeyExchangeStartFailed {
        group: NamedGroup,
        source: CryptoError,
    },
    KeyExchangeCompleteFailed {
        group: NamedGroup,
        source: CryptoError,
    },
    KeyExchangeMismatchedSharedSecret(NamedGroup),
    HmacFailed(CryptoError),
    HmacWrongLength {
        expected: usize,
        actual: usize,
    },
    HmacIncorrect,
    Other(String),
}

#[derive(Debug)]
pub(crate) enum InternalError {
    Transient(TransientError),
    Fatal(Error),
}

#[derive(Debug)]
pub(crate) enum TransientError {
    ParseIncomplete,
    Parse(nom::error::ErrorKind),
    TooManyRecords,
}

impl InternalError {
    pub(crate) fn parse_incomplete() -> Self {
        Self::Transient(TransientError::ParseIncomplete)
    }

    pub(crate) fn parse(kind: nom::error::ErrorKind) -> Self {
        Self::Transient(TransientError::Parse(kind))
    }

    pub(crate) fn too_many_records() -> Self {
        Self::Transient(TransientError::TooManyRecords)
    }

    pub(crate) fn into_public_error(self) -> Option<Error> {
        match self {
            Self::Transient(_) => None,
            Self::Fatal(err) => Some(err),
        }
    }
}

impl From<Error> for InternalError {
    fn from(value: Error) -> Self {
        Self::Fatal(value)
    }
}

impl<'a> From<nom::Err<nom::error::Error<&'a [u8]>>> for InternalError {
    fn from(value: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        match value {
            nom::Err::Incomplete(_) => InternalError::parse_incomplete(),
            nom::Err::Error(x) => InternalError::parse(x.code),
            nom::Err::Failure(x) => InternalError::parse(x.code),
        }
    }
}

impl From<CryptoError> for Error {
    fn from(value: CryptoError) -> Self {
        Self::CryptoError(value)
    }
}

impl From<CertificateError> for Error {
    fn from(value: CertificateError) -> Self {
        Self::CertificateError(value)
    }
}

impl From<SecurityError> for Error {
    fn from(value: SecurityError) -> Self {
        Self::SecurityError(value)
    }
}

impl From<PskError> for Error {
    fn from(value: PskError) -> Self {
        Self::PskError(value)
    }
}

impl From<ConfigError> for Error {
    fn from(value: ConfigError) -> Self {
        Self::ConfigError(value)
    }
}

impl From<String> for UnexpectedMessageError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&'static str> for UnexpectedMessageError {
    fn from(value: &'static str) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<String> for CryptoError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&'static str> for CryptoError {
    fn from(value: &'static str) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<String> for CertificateError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&'static str> for CertificateError {
    fn from(value: &'static str) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<String> for SecurityError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&'static str> for SecurityError {
    fn from(value: &'static str) -> Self {
        Self::Other(value.to_string())
    }
}

impl From<String> for ConfigError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

impl From<&'static str> for ConfigError {
    fn from(value: &'static str) -> Self {
        Self::Other(value.to_string())
    }
}

impl std::error::Error for Error {}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalError::Transient(err) => err.fmt(f),
            InternalError::Fatal(err) => err.fmt(f),
        }
    }
}

impl fmt::Display for TransientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransientError::ParseIncomplete => write!(f, "parse incomplete"),
            TransientError::Parse(kind) => write!(f, "parse error: {:?}", kind),
            TransientError::TooManyRecords => write!(f, "too many records in packet"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedMessage(err) => write!(f, "unexpected message: {err}"),
            Error::InvalidState(err) => write!(f, "invalid state: {err}"),
            Error::CryptoError(err) => write!(f, "crypto error: {err}"),
            Error::CertificateError(err) => write!(f, "certificate error: {err}"),
            Error::SecurityError(err) => write!(f, "security error: {err}"),
            Error::PskError(err) => write!(f, "psk error: {err}"),
            Error::ReceiveQueueFull => write!(f, "receive queue full"),
            Error::TransmitQueueFull => write!(f, "transmit queue full"),
            Error::IncompleteServerHello => write!(f, "incomplete ServerHello"),
            Error::Timeout(err) => write!(f, "timeout: {err}"),
            Error::ConfigError(err) => write!(f, "config error: {err}"),
            Error::RenegotiationAttempt => write!(f, "peer attempted renegotiation"),
            Error::HandshakePending => {
                write!(f, "handshake pending: cannot send application data yet")
            }
            Error::TooManyClientHelloFragments => write!(f, "too many client hello fragments"),
            Error::ConnectionClosed => write!(f, "connection closed"),
            Error::Dtls12Fallback => write!(f, "dtls 1.2 fallback (internal)"),
        }
    }
}

impl fmt::Display for UnexpectedMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnrecognizedAutoServerResponse => write!(f, "unrecognized response from server"),
            Self::ServerKeyExchangeWithoutSignature => {
                write!(f, "ServerKeyExchange without signature")
            }
            Self::PskServerKeyExchangeInEcdhePath => {
                write!(f, "PSK ServerKeyExchange in ECDHE path")
            }
            Self::EcdheServerKeyExchangeInPskPath => {
                write!(f, "ECDHE ServerKeyExchange in PSK path")
            }
            Self::PskClientKeyExchangeInEcdhePath => {
                write!(f, "PSK ClientKeyExchange in ECDHE path")
            }
            Self::EcdheClientKeyExchangeInPskPath => {
                write!(f, "ECDHE ClientKeyExchange in PSK path")
            }
            Self::CertificateRequestContextTruncated => {
                write!(f, "CertificateRequest context truncated")
            }
            Self::CertificateRequestExtensionsTruncated => {
                write!(f, "CertificateRequest extensions truncated")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for InvalidStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCipherSuiteSelected => write!(f, "no cipher suite selected"),
            Self::NoCipherSuite => write!(f, "no cipher suite"),
            Self::NoClientRandom => write!(f, "no client random"),
            Self::NoServerRandom => write!(f, "no server random"),
            Self::NoSharedSecretForHandshakeKeyDerivation => {
                write!(f, "no shared secret for handshake key derivation")
            }
            Self::NoServerHandshakeTrafficSecret => {
                write!(f, "no server handshake traffic secret")
            }
            Self::NoServerHandshakeTrafficSecretForFinished => {
                write!(f, "no server handshake traffic secret for Finished")
            }
            Self::NoClientHandshakeTrafficSecret => {
                write!(f, "no client handshake traffic secret")
            }
            Self::NoClientHandshakeTrafficSecretForFinished => {
                write!(f, "no client handshake traffic secret for Finished")
            }
            Self::NoHandshakeSecretForApplicationKeyDerivation => {
                write!(f, "no handshake secret for application key derivation")
            }
            Self::NoActiveKeyExchange => write!(f, "no active key exchange"),
            Self::NoCurrentAppSendKeysForKeyUpdate => {
                write!(f, "no current app send keys for KeyUpdate")
            }
            Self::NoCurrentAppRecvKeysForKeyUpdate => {
                write!(f, "no current app recv keys for KeyUpdate")
            }
            Self::ExporterMasterSecretNotDerived => {
                write!(f, "exporter master secret not yet derived")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSupportedKeyExchangeGroups => write!(f, "no supported key exchange groups"),
            Self::NoDtls12KeyExchangeGroupsConfigured => {
                write!(f, "no DTLS 1.2 key exchange groups configured")
            }
            Self::Epoch0SequenceNumberExhausted => {
                write!(f, "epoch 0 sequence number exhausted")
            }
            Self::SendSequenceNumberExhausted { epoch } => {
                write!(f, "send sequence number exhausted for epoch {epoch}")
            }
            Self::SendKeysNotAvailable { epoch } => {
                write!(f, "send keys not available for epoch {epoch}")
            }
            Self::RecvKeysNotAvailable { epoch } => {
                write!(f, "recv keys not available for epoch {epoch}")
            }
            Self::KeyExchangeGroupNotFound(group) => {
                write!(f, "key exchange group not found: {group:?}")
            }
            Self::KeyExchangeNotInitialized => write!(f, "key exchange not initialized"),
            Self::UnsupportedKeyExchangeGroup(group) => {
                write!(f, "unsupported key exchange group: {group:?}")
            }
            Self::UnsupportedEcdheNamedGroup(group) => {
                write!(f, "unsupported ECDHE named group: {group:?}")
            }
            Self::UnsupportedCipherSuite(suite) => {
                write!(f, "unsupported cipher suite: {suite:?}")
            }
            Self::UnsupportedHmacHash(hash) => {
                write!(f, "unsupported HMAC hash algorithm: {hash:?}")
            }
            Self::UnsupportedSignatureAlgorithm(sig) => {
                write!(f, "unsupported signature algorithm: {sig:?}")
            }
            Self::SignatureAlgorithmNotOfferedByClient => {
                write!(f, "signature algorithm not offered by client")
            }
            Self::SignatureAlgorithmMismatch { expected, actual } => {
                write!(
                    f,
                    "signature algorithm mismatch: {actual:?} != {expected:?}"
                )
            }
            Self::UnsupportedSignaturePair { signature, hash } => {
                write!(f, "unsupported signature algorithm: {signature:?}/{hash:?}")
            }
            Self::UnsupportedSignatureVerification {
                signature,
                hash,
                group,
            } => write!(
                f,
                "unsupported signature verification: {signature:?} + {hash:?} + {group:?}"
            ),
            Self::UnsupportedPublicKeyAlgorithm => write!(f, "unsupported public key algorithm"),
            Self::UnsupportedEcCurve(curve) => write!(f, "unsupported EC curve: {curve}"),
            Self::MissingEcCurveParameter => {
                write!(f, "missing EC curve parameter in certificate")
            }
            Self::InvalidEcCurveParameter => {
                write!(f, "invalid EC curve parameter in certificate")
            }
            Self::InvalidSubjectPublicKey => {
                write!(f, "invalid EC subject_public_key bitstring")
            }
            Self::InvalidSignatureFormat => write!(f, "invalid signature format"),
            Self::InvalidPublicKey(group) => write!(f, "invalid {group:?} public key"),
            Self::InvalidPrivateKey => {
                write!(f, "failed to parse private key in any supported format")
            }
            Self::SigningKeyHashMismatch {
                key_hash,
                requested,
            } => write!(
                f,
                "signing key is locked to {key_hash:?} but {requested:?} was requested"
            ),
            Self::SigningKeyUnsupportedHash { group, hash } => {
                write!(f, "{group:?} key does not support hash algorithm {hash:?}")
            }
            Self::InvalidAesGcmKeySize { actual } => {
                write!(f, "invalid key size for AES-GCM: {actual}")
            }
            Self::InvalidChacha20Poly1305KeySize { actual } => {
                write!(f, "invalid key size for CHACHA20-POLY1305: {actual}")
            }
            Self::InvalidAes128Ccm8KeySize { actual } => {
                write!(f, "invalid key size for AES-128-CCM-8: {actual}")
            }
            Self::InvalidNonce => write!(f, "invalid nonce"),
            Self::InvalidNonceLength { expected, actual } => {
                write!(f, "invalid nonce length: expected {expected}, got {actual}")
            }
            Self::CiphertextTooShort { minimum, actual } => {
                write!(f, "ciphertext too short: got {actual}, minimum {minimum}")
            }
            Self::HkdfOutputTooLong => write!(f, "HKDF output too long"),
            Self::HkdfLabelTooLong => write!(f, "label too long for HKDF-Expand-Label"),
            Self::HkdfContextTooLong => write!(f, "context too long for HKDF-Expand-Label"),
            Self::HkdfOutputLengthTooLarge => {
                write!(f, "output length too large for HKDF-Expand-Label")
            }
            Self::InvalidVerifyDataLength => write!(f, "invalid verify data length"),
            Self::VerifyDataTooLong => write!(f, "verify data too long"),
            Self::MasterSecretTooLong => write!(f, "master secret too long"),
            Self::KeyingMaterialTooLong => write!(f, "keying material too long"),
            Self::PreMasterSecretNotAvailable => write!(f, "pre-master secret not available"),
            Self::MasterSecretNotAvailable => write!(f, "master secret not available"),
            Self::ClientRandomNotAvailable => write!(f, "client random not available"),
            Self::ServerRandomNotAvailable => write!(f, "server random not available"),
            Self::ClientCipherNotInitialized => write!(f, "client cipher not initialized"),
            Self::ServerCipherNotInitialized => write!(f, "server cipher not initialized"),
            Self::WriteIvNotAvailable { is_client } => {
                let side = if *is_client { "client" } else { "server" };
                write!(f, "{side} write IV not available")
            }
            Self::UnsupportedDtls12RecordIvLen { len, suite } => {
                write!(f, "unsupported DTLS 1.2 record_iv_len={len} for {suite:?}")
            }
            Self::NoPrivateKeyConfigured => write!(f, "no private key configured"),
            Self::PskNotSet => write!(f, "PSK not set"),
            Self::ExporterMasterSecretNotDerived => {
                write!(f, "exporter master secret not yet derived")
            }
            Self::OperationFailed(op) => write!(f, "{op} failed"),
            Self::ProviderFailure { operation, reason } => {
                write!(f, "{operation} failed: {reason}")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for CryptoOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::CreateCipher => "cipher creation",
            Self::Encrypt => "encryption",
            Self::Decrypt => "decryption",
            Self::Sign => "signing",
            Self::VerifySignature => "signature verification",
            Self::LoadPrivateKey => "private key loading",
            Self::StartKeyExchange => "key exchange start",
            Self::CompleteKeyExchange => "key exchange completion",
            Self::GenerateEphemeralKey => "ephemeral key generation",
            Self::ComputePublicKey => "public key computation",
            Self::FillRandom => "random generation",
            Self::ComputeHmac => "HMAC computation",
            Self::Prf => "PRF",
            Self::HkdfExtract => "HKDF extract",
            Self::HkdfExpand => "HKDF expand",
            Self::HkdfExpandLabel => "HKDF expand label",
            Self::DeriveEarlySecret => "early secret derivation",
            Self::DeriveDerivedSecret => "derived secret derivation",
            Self::DeriveHandshakeSecret => "handshake secret derivation",
            Self::DeriveTrafficSecret => "traffic secret derivation",
            Self::DeriveMasterSecret => "master secret derivation",
            Self::DeriveExporterMasterSecret => "exporter master secret derivation",
            Self::DeriveNextTrafficSecret => "next traffic secret derivation",
            Self::DeriveKey => "key derivation",
            Self::DeriveIv => "IV derivation",
            Self::DeriveSequenceNumberKey => "sequence number key derivation",
            Self::DeriveFinishedKey => "Finished key derivation",
            Self::ComputeVerifyData => "verify data computation",
            Self::VerifyData => "verify data verification",
            Self::ComputePskPreMasterSecret => "PSK pre-master secret computation",
            Self::ComputeCookie => "cookie computation",
            Self::ExtractSrtpKeyingMaterial => "SRTP keying material extraction",
            Self::EncodeKey => "key encoding",
            Self::DecodeKey => "key decoding",
        };
        write!(f, "{text}")
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoServerCertificateReceived => write!(f, "no server certificate received"),
            Self::NoClientCertificateForVerification => {
                write!(f, "no client certificate for verification")
            }
            Self::NoServerCertificateForVerification => {
                write!(f, "no server certificate for verification")
            }
            Self::ServerCertificateContextMustBeEmpty => {
                write!(f, "server certificate context must be empty")
            }
            Self::ClientCertificateContextMustBeEmpty => {
                write!(f, "client certificate context must be empty")
            }
            Self::UnsupportedHashAlgorithm(hash) => {
                write!(f, "unsupported hash algorithm: {hash:?}")
            }
            Self::ParseFailed => write!(f, "failed to parse certificate"),
            Self::MissingEcCurveParameter => {
                write!(f, "missing EC curve parameter in certificate")
            }
            Self::InvalidEcCurveParameter => {
                write!(f, "invalid EC curve parameter in certificate")
            }
            Self::UnsupportedEcCurve(curve) => write!(f, "unsupported EC curve: {curve}"),
            Self::InvalidSubjectPublicKey => {
                write!(f, "invalid EC subject_public_key bitstring")
            }
            Self::PrivateKey(err) => write!(f, "private key error: {err}"),
            Self::Verification(err) => write!(f, "verification failed: {err}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHelloVerifyRequestVersion(version) => {
                write!(
                    f,
                    "unsupported DTLS version in HelloVerifyRequest: {version:?}"
                )
            }
            Self::UnsupportedServerVersion(version) => {
                write!(f, "unsupported DTLS version from server: {version:?}")
            }
            Self::UnsupportedClientVersion(version) => {
                write!(f, "unsupported DTLS version from client: {version:?}")
            }
            Self::UnsupportedServerCompression(compression) => {
                write!(
                    f,
                    "unsupported compression method from server: {compression:?}"
                )
            }
            Self::UnsupportedClientCompression => {
                write!(f, "client did not offer null compression")
            }
            Self::UnsupportedKeyExchangeAlgorithm => {
                write!(f, "unsupported key exchange algorithm")
            }
            Self::ServerSelectedUnknownCipherSuite => {
                write!(f, "server selected unknown cipher suite")
            }
            Self::ServerSelectedIncompatibleCipherSuite(suite) => {
                write!(f, "server selected incompatible cipher suite: {suite:?}")
            }
            Self::ServerSelectedDisallowedCipherSuite(suite) => {
                write!(f, "server selected disallowed cipher suite: {suite:?}")
            }
            Self::ServerSelectedDisallowedDtls13CipherSuite(suite) => {
                write!(f, "server selected disallowed cipher suite: {suite:?}")
            }
            Self::ExtendedMasterSecretNotNegotiated => {
                write!(f, "extended master secret not negotiated")
            }
            Self::NoMutuallyAcceptableCipherSuite => {
                write!(f, "no mutually acceptable cipher suite")
            }
            Self::ClientHelloLegacyVersionNotDtls12 => {
                write!(f, "ClientHello legacy_version must be DTLS 1.2")
            }
            Self::ServerHelloLegacyVersionNotDtls12 => {
                write!(f, "ServerHello legacy_version must be DTLS 1.2")
            }
            Self::ClientHelloMissingDtls13SupportedVersions => {
                write!(f, "ClientHello missing DTLS 1.3 supported_versions")
            }
            Self::ClientHelloMustOfferNullCompression => {
                write!(f, "ClientHello must offer null compression")
            }
            Self::InvalidCookieInClientHello => write!(f, "invalid cookie in ClientHello"),
            Self::CannotSendSecondHelloRetryRequest => {
                write!(f, "cannot send second HelloRetryRequest")
            }
            Self::NoCommonCipherSuite => write!(f, "no common cipher suite found"),
            Self::NoCommonKeyExchangeGroup => write!(f, "no common key exchange group"),
            Self::HrrSelectedDisallowedCipherSuite => {
                write!(f, "HRR selected disallowed cipher suite")
            }
            Self::HrrDidNotSelectDtls13 => write!(f, "HRR did not select DTLS 1.3"),
            Self::ServerHelloCompressionMustBeNull => {
                write!(f, "ServerHello compression must be null")
            }
            Self::ServerDidNotNegotiateDtls13 => {
                write!(f, "server did not negotiate DTLS 1.3")
            }
            Self::ServerMissingKeyShare => write!(f, "server missing key_share"),
            Self::ServerKeyShareGroupMismatch { selected, actual } => {
                write!(
                    f,
                    "server key_share group mismatch: selected {selected:?}, actual {actual:?}"
                )
            }
            Self::SignatureTooLarge => write!(f, "signature too large"),
            Self::SignatureSchemeNotOffered(scheme) => {
                write!(f, "signature scheme {scheme:?} was not offered")
            }
            Self::SignatureAlgorithmMismatch { expected, actual } => {
                write!(
                    f,
                    "signature algorithm mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::UnsupportedSignatureScheme(scheme) => {
                write!(f, "unsupported signature scheme: {scheme:?}")
            }
            Self::SignatureSchemeCertificateCurveMismatch {
                scheme,
                expected,
                actual,
            } => write!(
                f,
                "signature scheme {scheme:?} requires {expected:?} but certificate uses {actual:?}"
            ),
            Self::ServerFinishedVerificationFailed => {
                write!(f, "server Finished verification failed")
            }
            Self::ClientFinishedVerificationFailed => {
                write!(f, "client Finished verification failed")
            }
            Self::FatalAlert { level, description } => {
                write!(
                    f,
                    "received fatal alert: level={level}, description={description}"
                )
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for PskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPskResolverConfigured => write!(f, "no PSK resolver configured"),
            Self::NoPskIdentityConfigured => write!(f, "no PSK identity configured"),
            Self::ResolverReturnedNoKey => write!(f, "PSK resolver returned no key"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HybridClientHello => write!(f, "hybrid ClientHello"),
            Self::Connect => write!(f, "connect"),
            Self::Handshake => write!(f, "handshake"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCryptoProvider => write!(
                f,
                concat!(
                    "no crypto provider available; set one explicitly, install a default, ",
                    "or enable a crypto feature"
                )
            ),
            Self::MtuTooSmall { mtu, minimum } => {
                write!(f, "MTU {mtu} is too small (minimum {minimum})")
            }
            Self::AeadEncryptionLimitTooSmall => {
                write!(f, "aead_encryption_limit must be at least 1")
            }
            Self::NoCipherSuitesAfterFiltering => write!(
                f,
                concat!(
                    "no cipher suites remain after filtering; at least one DTLS 1.2 or ",
                    "DTLS 1.3 cipher suite must be available"
                )
            ),
            Self::PskConfiguredWithoutPskCipherSuite => write!(
                f,
                "PSK is configured but no PSK cipher suite remains after filtering DTLS 1.2 suites"
            ),
            Self::NoDtls12KeyExchangeGroupsAfterFiltering => write!(
                f,
                concat!(
                    "DTLS 1.2 cipher suites are enabled but no compatible key exchange ",
                    "groups remain after filtering"
                )
            ),
            Self::NoDtls13KeyExchangeGroupsAfterFiltering => write!(
                f,
                "DTLS 1.3 cipher suites are enabled but no key exchange groups remain after filtering"
            ),
            Self::CryptoProvider(err) => write!(f, "crypto provider validation failed: {err}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for CryptoProviderValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCipherSuites => {
                write!(f, "CryptoProvider has no cipher suites supported by dimpl")
            }
            Self::EcdhCipherSuitesWithoutKeyExchangeGroups => write!(
                f,
                "CryptoProvider has ECDH cipher suites but no supported key exchange groups"
            ),
            Self::NoDtls13CipherSuites => {
                write!(f, "CryptoProvider has no DTLS 1.3 cipher suites")
            }
            Self::MissingHashTestVector(hash) => {
                write!(f, "no expected hash data for hash algorithm: {hash:?}")
            }
            Self::HashProviderIncorrect(hash) => {
                write!(f, "hash provider {hash:?} produced incorrect result")
            }
            Self::PrfFailed { hash, source } => write!(f, "PRF failed for {hash:?}: {source}"),
            Self::PrfWrongLength {
                hash,
                expected,
                actual,
            } => write!(
                f,
                "PRF {hash:?} returned wrong length: expected {expected}, got {actual}"
            ),
            Self::MissingPrfTestVector(hash) => {
                write!(f, "no expected PRF data for hash algorithm: {hash:?}")
            }
            Self::PrfIncorrect(hash) => write!(f, "PRF {hash:?} produced incorrect result"),
            Self::NoSignatureValidationVector { hash, signature } => {
                write!(f, "no validation test vectors for {hash:?} + {signature:?}")
            }
            Self::SignatureVerificationFailed {
                hash,
                signature,
                source,
            } => write!(
                f,
                "signature verification failed for {hash:?} + {signature:?}: {source}"
            ),
            Self::HkdfFailed { suite, source } => {
                write!(f, "HKDF failed for DTLS 1.3 suite {suite:?}: {source}")
            }
            Self::HkdfEmptyOutput(suite) => {
                write!(f, "HKDF returned empty output for {suite:?}")
            }
            Self::NoAeadTestVector(suite) => {
                write!(f, "no AEAD test vector for DTLS 1.3 suite {suite:?}")
            }
            Self::AeadCreateFailed { suite, source } => {
                write!(f, "failed to create cipher for {suite:?}: {source}")
            }
            Self::AeadEncryptFailed { suite, source } => {
                write!(f, "AEAD encrypt failed for {suite:?}: {source}")
            }
            Self::AeadEncryptWrongOutput(suite) => {
                write!(f, "AEAD encrypt produced wrong output for {suite:?}")
            }
            Self::AeadDecryptFailed { suite, source } => {
                write!(f, "AEAD decrypt failed for {suite:?}: {source}")
            }
            Self::AeadDecryptWrongOutput(suite) => {
                write!(f, "AEAD decrypt produced wrong output for {suite:?}")
            }
            Self::NoRecordNumberEncryptionTestVector(suite) => {
                write!(f, "no encrypt_sn test vector for DTLS 1.3 suite {suite:?}")
            }
            Self::RecordNumberEncryptionWrongMask(suite) => {
                write!(f, "encrypt_sn produced wrong mask for {suite:?}")
            }
            Self::KeyExchangeStartFailed { group, source } => {
                write!(f, "key exchange start failed for {group:?}: {source}")
            }
            Self::KeyExchangeCompleteFailed { group, source } => {
                write!(f, "key exchange complete failed for {group:?}: {source}")
            }
            Self::KeyExchangeMismatchedSharedSecret(group) => {
                write!(f, "key exchange produced different secrets for {group:?}")
            }
            Self::HmacFailed(source) => write!(f, "HMAC provider failed: {source}"),
            Self::HmacWrongLength { expected, actual } => {
                write!(
                    f,
                    "HMAC provider returned wrong length: expected {expected} bytes, got {actual}"
                )
            }
            Self::HmacIncorrect => {
                write!(f, "HMAC provider produced incorrect result for HMAC-SHA256")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}
