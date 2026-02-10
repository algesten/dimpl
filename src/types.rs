//! Shared types used by both DTLS 1.2 and DTLS 1.3.
//!
//! These types represent cryptographic primitives and protocol elements
//! that are common across DTLS versions.

use std::cmp::Ordering;
use std::fmt;
use std::time::Instant;

use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

use crate::buffer::Buf;
use crate::time_tricks::InstantExt;
use crate::SeededRng;

pub type NamedGroupVec = ArrayVec<NamedGroup, { NamedGroup::supported().len() }>;

// ============================================================================
// Random
// ============================================================================

/// ClientHello / ServerHello random value (32 bytes on the wire).
///
/// Used by both DTLS 1.2 and DTLS 1.3. Construction differs:
/// - DTLS 1.2: first 4 bytes are `gmt_unix_time` ([`Random::new_with_time`]).
/// - DTLS 1.3: all 32 bytes are random ([`Random::new`]).
///
/// After construction neither version accesses sub-fields — all consumers
/// use [`bytes`](Self::bytes) or [`serialize`](Self::serialize).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Random {
    /// The 32 raw bytes of the random value.
    pub bytes: [u8; 32],
}

impl Random {
    /// All-random (DTLS 1.3 / hybrid style).
    pub fn new(rng: &mut SeededRng) -> Self {
        Self {
            bytes: rng.random(),
        }
    }

    /// Timestamp in first 4 bytes (DTLS 1.2 style).
    pub fn new_with_time(now: Instant, rng: &mut SeededRng) -> Self {
        let gmt_duration = now.to_unix_duration();
        // This is valid until year 2106, at which point I will be beyond caring.
        let gmt_unix_time = gmt_duration.as_secs() as u32;

        let random_bytes: [u8; 28] = rng.random();

        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&gmt_unix_time.to_be_bytes());
        bytes[4..].copy_from_slice(&random_bytes);

        Self { bytes }
    }

    /// Parse a 32-byte `Random` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Random> {
        let (input, data) = take(32_usize)(input)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(data);
        Ok((input, Random { bytes }))
    }

    /// Serialize this `Random` to wire format.
    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.bytes);
    }
}

// ============================================================================
// Named Groups (Key Exchange)
// ============================================================================

/// Elliptic curves and key exchange groups (RFC 8422, RFC 8446).
///
/// Used for Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange.
/// The same named groups are used in both DTLS 1.2 and DTLS 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// sect163k1 (deprecated).
    Sect163k1,
    /// sect163r1 (deprecated).
    Sect163r1,
    /// sect163r2 (deprecated).
    Sect163r2,
    /// sect193r1 (deprecated).
    Sect193r1,
    /// sect193r2 (deprecated).
    Sect193r2,
    /// sect233k1 (deprecated).
    Sect233k1,
    /// sect233r1 (deprecated).
    Sect233r1,
    /// sect239k1 (deprecated).
    Sect239k1,
    /// sect283k1 (deprecated).
    Sect283k1,
    /// sect283r1 (deprecated).
    Sect283r1,
    /// sect409k1 (deprecated).
    Sect409k1,
    /// sect409r1 (deprecated).
    Sect409r1,
    /// sect571k1 (deprecated).
    Sect571k1,
    /// sect571r1 (deprecated).
    Sect571r1,
    /// secp160k1 (deprecated).
    Secp160k1,
    /// secp160r1 (deprecated).
    Secp160r1,
    /// secp160r2 (deprecated).
    Secp160r2,
    /// secp192k1 (deprecated).
    Secp192k1,
    /// secp192r1 (deprecated).
    Secp192r1,
    /// secp224k1.
    Secp224k1,
    /// secp224r1.
    Secp224r1,
    /// secp256k1.
    Secp256k1,
    /// secp256r1 / P-256 (supported by dimpl).
    Secp256r1,
    /// secp384r1 / P-384 (supported by dimpl).
    Secp384r1,
    /// secp521r1 / P-521.
    Secp521r1,
    /// X25519 (Curve25519 for ECDHE).
    X25519,
    /// X448 (Curve448 for ECDHE).
    X448,
    /// Unknown or unsupported group.
    Unknown(u16),
}

impl NamedGroup {
    /// Convert a wire format u16 value to a `NamedGroup`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => NamedGroup::Sect163k1,
            2 => NamedGroup::Sect163r1,
            3 => NamedGroup::Sect163r2,
            4 => NamedGroup::Sect193r1,
            5 => NamedGroup::Sect193r2,
            6 => NamedGroup::Sect233k1,
            7 => NamedGroup::Sect233r1,
            8 => NamedGroup::Sect239k1,
            9 => NamedGroup::Sect283k1,
            10 => NamedGroup::Sect283r1,
            11 => NamedGroup::Sect409k1,
            12 => NamedGroup::Sect409r1,
            13 => NamedGroup::Sect571k1,
            14 => NamedGroup::Sect571r1,
            15 => NamedGroup::Secp160k1,
            16 => NamedGroup::Secp160r1,
            17 => NamedGroup::Secp160r2,
            18 => NamedGroup::Secp192k1,
            19 => NamedGroup::Secp192r1,
            20 => NamedGroup::Secp224k1,
            21 => NamedGroup::Secp224r1,
            22 => NamedGroup::Secp256k1,
            23 => NamedGroup::Secp256r1,
            24 => NamedGroup::Secp384r1,
            25 => NamedGroup::Secp521r1,
            29 => NamedGroup::X25519,
            30 => NamedGroup::X448,
            _ => NamedGroup::Unknown(value),
        }
    }

    /// Convert this `NamedGroup` to its wire format u16 value.
    pub fn as_u16(&self) -> u16 {
        match self {
            NamedGroup::Sect163k1 => 1,
            NamedGroup::Sect163r1 => 2,
            NamedGroup::Sect163r2 => 3,
            NamedGroup::Sect193r1 => 4,
            NamedGroup::Sect193r2 => 5,
            NamedGroup::Sect233k1 => 6,
            NamedGroup::Sect233r1 => 7,
            NamedGroup::Sect239k1 => 8,
            NamedGroup::Sect283k1 => 9,
            NamedGroup::Sect283r1 => 10,
            NamedGroup::Sect409k1 => 11,
            NamedGroup::Sect409r1 => 12,
            NamedGroup::Sect571k1 => 13,
            NamedGroup::Sect571r1 => 14,
            NamedGroup::Secp160k1 => 15,
            NamedGroup::Secp160r1 => 16,
            NamedGroup::Secp160r2 => 17,
            NamedGroup::Secp192k1 => 18,
            NamedGroup::Secp192r1 => 19,
            NamedGroup::Secp224k1 => 20,
            NamedGroup::Secp224r1 => 21,
            NamedGroup::Secp256k1 => 22,
            NamedGroup::Secp256r1 => 23,
            NamedGroup::Secp384r1 => 24,
            NamedGroup::Secp521r1 => 25,
            NamedGroup::X25519 => 29,
            NamedGroup::X448 => 30,
            NamedGroup::Unknown(value) => *value,
        }
    }

    /// Parse a `NamedGroup` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], NamedGroup> {
        let (input, value) = be_u16(input)?;
        Ok((input, NamedGroup::from_u16(value)))
    }

    /// Returns true if this named group is supported by this implementation.
    pub fn is_supported(&self) -> bool {
        Self::supported().contains(self)
    }

    /// All recognized named groups (every non-`Unknown` variant).
    pub const fn all() -> &'static [NamedGroup; 27] {
        &[
            NamedGroup::Sect163k1,
            NamedGroup::Sect163r1,
            NamedGroup::Sect163r2,
            NamedGroup::Sect193r1,
            NamedGroup::Sect193r2,
            NamedGroup::Sect233k1,
            NamedGroup::Sect233r1,
            NamedGroup::Sect239k1,
            NamedGroup::Sect283k1,
            NamedGroup::Sect283r1,
            NamedGroup::Sect409k1,
            NamedGroup::Sect409r1,
            NamedGroup::Sect571k1,
            NamedGroup::Sect571r1,
            NamedGroup::Secp160k1,
            NamedGroup::Secp160r1,
            NamedGroup::Secp160r2,
            NamedGroup::Secp192k1,
            NamedGroup::Secp192r1,
            NamedGroup::Secp224k1,
            NamedGroup::Secp224r1,
            NamedGroup::Secp256k1,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
            NamedGroup::X25519,
            NamedGroup::X448,
        ]
    }

    /// Supported named groups in preference order.
    pub const fn supported() -> &'static [NamedGroup; 4] {
        &[
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
        ]
    }
}

// ============================================================================
// Hash Algorithms
// ============================================================================

/// Hash algorithms used in DTLS (RFC 5246, RFC 8446).
///
/// Specifies the hash algorithm to be used in digital signatures,
/// PRF/HKDF operations, and transcript hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum HashAlgorithm {
    /// No hash (not typically used).
    None,
    /// MD5 hash (deprecated, not supported).
    MD5,
    /// SHA-1 hash (deprecated, not supported).
    SHA1,
    /// SHA-224 hash.
    SHA224,
    /// SHA-256 hash (supported by dimpl).
    SHA256,
    /// SHA-384 hash (supported by dimpl).
    SHA384,
    /// SHA-512 hash.
    SHA512,
    /// Unknown or unsupported hash algorithm.
    Unknown(u8),
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl HashAlgorithm {
    /// Convert a wire format u8 value to a `HashAlgorithm`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => HashAlgorithm::None,
            1 => HashAlgorithm::MD5,
            2 => HashAlgorithm::SHA1,
            3 => HashAlgorithm::SHA224,
            4 => HashAlgorithm::SHA256,
            5 => HashAlgorithm::SHA384,
            6 => HashAlgorithm::SHA512,
            _ => HashAlgorithm::Unknown(value),
        }
    }

    /// Convert this `HashAlgorithm` to its wire format u8 value.
    pub fn as_u8(&self) -> u8 {
        match self {
            HashAlgorithm::None => 0,
            HashAlgorithm::MD5 => 1,
            HashAlgorithm::SHA1 => 2,
            HashAlgorithm::SHA224 => 3,
            HashAlgorithm::SHA256 => 4,
            HashAlgorithm::SHA384 => 5,
            HashAlgorithm::SHA512 => 6,
            HashAlgorithm::Unknown(value) => *value,
        }
    }

    /// Parse a `HashAlgorithm` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], HashAlgorithm> {
        let (input, value) = be_u8(input)?;
        Ok((input, HashAlgorithm::from_u8(value)))
    }

    /// Returns the output length in bytes for this hash algorithm.
    pub fn output_len(&self) -> usize {
        match self {
            HashAlgorithm::None => 0,
            HashAlgorithm::MD5 => 16,
            HashAlgorithm::SHA1 => 20,
            HashAlgorithm::SHA224 => 28,
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            HashAlgorithm::SHA512 => 64,
            HashAlgorithm::Unknown(_) => 0,
        }
    }
}

// ============================================================================
// Signature Algorithms
// ============================================================================

/// Signature algorithms used in DTLS handshakes.
///
/// Represents the underlying signature primitive (RSA, ECDSA, etc.).
/// Used internally for signing operations across both DTLS versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum SignatureAlgorithm {
    /// Anonymous (no certificate).
    Anonymous,
    /// RSA signatures.
    RSA,
    /// DSA signatures.
    DSA,
    /// ECDSA signatures.
    ECDSA,
    /// Unknown or unsupported signature algorithm.
    Unknown(u8),
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl SignatureAlgorithm {
    /// Convert an 8-bit value into a `SignatureAlgorithm`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => SignatureAlgorithm::Anonymous,
            1 => SignatureAlgorithm::RSA,
            2 => SignatureAlgorithm::DSA,
            3 => SignatureAlgorithm::ECDSA,
            _ => SignatureAlgorithm::Unknown(value),
        }
    }

    /// Convert this `SignatureAlgorithm` into its 8-bit representation.
    pub fn as_u8(&self) -> u8 {
        match self {
            SignatureAlgorithm::Anonymous => 0,
            SignatureAlgorithm::RSA => 1,
            SignatureAlgorithm::DSA => 2,
            SignatureAlgorithm::ECDSA => 3,
            SignatureAlgorithm::Unknown(value) => *value,
        }
    }

    /// Parse a `SignatureAlgorithm` from network bytes.
    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAlgorithm> {
        let (input, value) = be_u8(input)?;
        Ok((input, SignatureAlgorithm::from_u8(value)))
    }
}

// ============================================================================
// Content Type
// ============================================================================

/// DTLS record content types.
///
/// Identifies the type of data in a DTLS record. These values are the same
/// for both DTLS 1.2 and DTLS 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Change Cipher Spec (used in DTLS 1.2, compatibility-only in 1.3).
    ChangeCipherSpec,
    /// Alert message.
    Alert,
    /// Handshake message.
    Handshake,
    /// Application data.
    ApplicationData,
    /// ACK (DTLS 1.3 only, RFC 9147 Section 7).
    Ack,
    /// Unknown content type.
    Unknown(u8),
}

impl Default for ContentType {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl ContentType {
    /// Convert a u8 value to a `ContentType`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            26 => ContentType::Ack,
            _ => ContentType::Unknown(value),
        }
    }

    /// Convert this `ContentType` to its u8 value.
    pub fn as_u8(&self) -> u8 {
        match self {
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert => 21,
            ContentType::Handshake => 22,
            ContentType::ApplicationData => 23,
            ContentType::Ack => 26,
            ContentType::Unknown(value) => *value,
        }
    }

    /// Parse a `ContentType` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], ContentType> {
        let (input, byte) = be_u8(input)?;
        Ok((input, Self::from_u8(byte)))
    }
}

// ============================================================================
// Sequence Number
// ============================================================================

/// DTLS record sequence number (epoch + sequence).
///
/// Both DTLS 1.2 and DTLS 1.3 use an epoch and sequence number for
/// replay protection and AEAD nonce construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sequence {
    /// The epoch (incremented on key change).
    pub epoch: u16,
    /// The sequence number within the epoch (technically u48).
    pub sequence_number: u64,
}

impl Sequence {
    /// Create a new sequence with the given epoch and sequence number 0.
    pub fn new(epoch: u16) -> Self {
        Self {
            epoch,
            sequence_number: 0,
        }
    }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[epoch: {}, sequence_number: {}]",
            self.epoch, self.sequence_number,
        )
    }
}

impl Ord for Sequence {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.epoch < other.epoch {
            Ordering::Less
        } else if self.epoch > other.epoch {
            Ordering::Greater
        } else {
            self.sequence_number.cmp(&other.sequence_number)
        }
    }
}

impl PartialOrd for Sequence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================================
// Signature Schemes (TLS 1.3)
// ============================================================================

/// Signature schemes used in TLS 1.3/DTLS 1.3 (RFC 8446).
///
/// In TLS 1.3, signature schemes combine the signature algorithm with the
/// hash algorithm into a single identifier, unlike TLS 1.2 where they were
/// separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum SignatureScheme {
    /// ECDSA with P-256 and SHA-256.
    ECDSA_SECP256R1_SHA256,
    /// ECDSA with P-384 and SHA-384.
    ECDSA_SECP384R1_SHA384,
    /// ECDSA with P-521 and SHA-512.
    ECDSA_SECP521R1_SHA512,
    /// Ed25519.
    ED25519,
    /// Ed448.
    ED448,
    /// RSA-PSS with SHA-256 (rsaEncryption OID).
    RSA_PSS_RSAE_SHA256,
    /// RSA-PSS with SHA-384 (rsaEncryption OID).
    RSA_PSS_RSAE_SHA384,
    /// RSA-PSS with SHA-512 (rsaEncryption OID).
    RSA_PSS_RSAE_SHA512,
    /// RSA-PSS with SHA-256 (id-rsassa-pss OID).
    RSA_PSS_PSS_SHA256,
    /// RSA-PSS with SHA-384 (id-rsassa-pss OID).
    RSA_PSS_PSS_SHA384,
    /// RSA-PSS with SHA-512 (id-rsassa-pss OID).
    RSA_PSS_PSS_SHA512,
    /// RSA PKCS#1 v1.5 with SHA-256 (legacy).
    RSA_PKCS1_SHA256,
    /// RSA PKCS#1 v1.5 with SHA-384 (legacy).
    RSA_PKCS1_SHA384,
    /// RSA PKCS#1 v1.5 with SHA-512 (legacy).
    RSA_PKCS1_SHA512,
    /// Unknown or unsupported signature scheme.
    Unknown(u16),
}

impl SignatureScheme {
    /// Convert a wire format u16 value to a `SignatureScheme`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0403 => SignatureScheme::ECDSA_SECP256R1_SHA256,
            0x0503 => SignatureScheme::ECDSA_SECP384R1_SHA384,
            0x0603 => SignatureScheme::ECDSA_SECP521R1_SHA512,
            0x0807 => SignatureScheme::ED25519,
            0x0808 => SignatureScheme::ED448,
            0x0804 => SignatureScheme::RSA_PSS_RSAE_SHA256,
            0x0805 => SignatureScheme::RSA_PSS_RSAE_SHA384,
            0x0806 => SignatureScheme::RSA_PSS_RSAE_SHA512,
            0x0809 => SignatureScheme::RSA_PSS_PSS_SHA256,
            0x080a => SignatureScheme::RSA_PSS_PSS_SHA384,
            0x080b => SignatureScheme::RSA_PSS_PSS_SHA512,
            0x0401 => SignatureScheme::RSA_PKCS1_SHA256,
            0x0501 => SignatureScheme::RSA_PKCS1_SHA384,
            0x0601 => SignatureScheme::RSA_PKCS1_SHA512,
            _ => SignatureScheme::Unknown(value),
        }
    }

    /// Convert this `SignatureScheme` to its wire format u16 value.
    pub fn as_u16(&self) -> u16 {
        match self {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => 0x0403,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => 0x0503,
            SignatureScheme::ECDSA_SECP521R1_SHA512 => 0x0603,
            SignatureScheme::ED25519 => 0x0807,
            SignatureScheme::ED448 => 0x0808,
            SignatureScheme::RSA_PSS_RSAE_SHA256 => 0x0804,
            SignatureScheme::RSA_PSS_RSAE_SHA384 => 0x0805,
            SignatureScheme::RSA_PSS_RSAE_SHA512 => 0x0806,
            SignatureScheme::RSA_PSS_PSS_SHA256 => 0x0809,
            SignatureScheme::RSA_PSS_PSS_SHA384 => 0x080a,
            SignatureScheme::RSA_PSS_PSS_SHA512 => 0x080b,
            SignatureScheme::RSA_PKCS1_SHA256 => 0x0401,
            SignatureScheme::RSA_PKCS1_SHA384 => 0x0501,
            SignatureScheme::RSA_PKCS1_SHA512 => 0x0601,
            SignatureScheme::Unknown(value) => *value,
        }
    }

    /// Parse a `SignatureScheme` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureScheme> {
        let (input, value) = be_u16(input)?;
        Ok((input, SignatureScheme::from_u16(value)))
    }

    /// Returns true if this signature scheme is supported by this implementation.
    pub fn is_supported(&self) -> bool {
        Self::SUPPORTED.contains(self)
    }

    /// All recognized signature schemes (every non-`Unknown` variant).
    pub fn all() -> &'static [SignatureScheme] {
        &[
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }

    const SUPPORTED: &[SignatureScheme] = &[
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
    ];

    /// Supported signature schemes in preference order.
    pub fn supported() -> ArrayVec<SignatureScheme, 2> {
        let mut schemes = ArrayVec::new();
        schemes.push(SignatureScheme::ECDSA_SECP256R1_SHA256);
        schemes.push(SignatureScheme::ECDSA_SECP384R1_SHA384);
        schemes
    }

    /// Returns the hash algorithm associated with this signature scheme.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            SignatureScheme::ECDSA_SECP256R1_SHA256
            | SignatureScheme::RSA_PSS_RSAE_SHA256
            | SignatureScheme::RSA_PSS_PSS_SHA256
            | SignatureScheme::RSA_PKCS1_SHA256 => HashAlgorithm::SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384
            | SignatureScheme::RSA_PSS_RSAE_SHA384
            | SignatureScheme::RSA_PSS_PSS_SHA384
            | SignatureScheme::RSA_PKCS1_SHA384 => HashAlgorithm::SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512
            | SignatureScheme::RSA_PSS_RSAE_SHA512
            | SignatureScheme::RSA_PSS_PSS_SHA512
            | SignatureScheme::RSA_PKCS1_SHA512 => HashAlgorithm::SHA512,
            // Ed25519 and Ed448 have intrinsic hash algorithms
            SignatureScheme::ED25519 | SignatureScheme::ED448 => HashAlgorithm::None,
            SignatureScheme::Unknown(_) => HashAlgorithm::Unknown(0),
        }
    }
}

// ============================================================================
// DTLS 1.3 Cipher Suites
// ============================================================================

/// Cipher suites for DTLS 1.3 (RFC 9147).
///
/// Unlike DTLS 1.2, TLS 1.3 cipher suites only specify the AEAD algorithm
/// and hash function. Key exchange is negotiated separately via key_share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Dtls13CipherSuite {
    /// TLS_AES_128_GCM_SHA256.
    AES_128_GCM_SHA256,
    /// TLS_AES_256_GCM_SHA384.
    AES_256_GCM_SHA384,
    /// TLS_CHACHA20_POLY1305_SHA256.
    CHACHA20_POLY1305_SHA256,
    /// TLS_AES_128_CCM_SHA256.
    AES_128_CCM_SHA256,
    /// TLS_AES_128_CCM_8_SHA256 (shorter tag, for constrained devices).
    AES_128_CCM_8_SHA256,
    /// Unknown or unsupported cipher suite.
    Unknown(u16),
}

impl Dtls13CipherSuite {
    /// Convert a wire format u16 value to a `Dtls13CipherSuite`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x1301 => Dtls13CipherSuite::AES_128_GCM_SHA256,
            0x1302 => Dtls13CipherSuite::AES_256_GCM_SHA384,
            0x1303 => Dtls13CipherSuite::CHACHA20_POLY1305_SHA256,
            0x1304 => Dtls13CipherSuite::AES_128_CCM_SHA256,
            0x1305 => Dtls13CipherSuite::AES_128_CCM_8_SHA256,
            _ => Dtls13CipherSuite::Unknown(value),
        }
    }

    /// Convert this `Dtls13CipherSuite` to its wire format u16 value.
    pub fn as_u16(&self) -> u16 {
        match self {
            Dtls13CipherSuite::AES_128_GCM_SHA256 => 0x1301,
            Dtls13CipherSuite::AES_256_GCM_SHA384 => 0x1302,
            Dtls13CipherSuite::CHACHA20_POLY1305_SHA256 => 0x1303,
            Dtls13CipherSuite::AES_128_CCM_SHA256 => 0x1304,
            Dtls13CipherSuite::AES_128_CCM_8_SHA256 => 0x1305,
            Dtls13CipherSuite::Unknown(value) => *value,
        }
    }

    /// Parse a `Dtls13CipherSuite` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Dtls13CipherSuite> {
        let (input, value) = be_u16(input)?;
        Ok((input, Dtls13CipherSuite::from_u16(value)))
    }

    /// Returns the hash algorithm used by this cipher suite.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Dtls13CipherSuite::AES_128_GCM_SHA256
            | Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
            | Dtls13CipherSuite::AES_128_CCM_SHA256
            | Dtls13CipherSuite::AES_128_CCM_8_SHA256 => HashAlgorithm::SHA256,
            Dtls13CipherSuite::AES_256_GCM_SHA384 => HashAlgorithm::SHA384,
            Dtls13CipherSuite::Unknown(_) => HashAlgorithm::Unknown(0),
        }
    }

    /// Returns true if this cipher suite is supported by this implementation.
    pub fn is_supported(&self) -> bool {
        Self::supported().contains(self)
    }

    /// All recognized DTLS 1.3 cipher suites (every non-`Unknown` variant).
    pub fn all() -> &'static [Dtls13CipherSuite] {
        &[
            Dtls13CipherSuite::AES_128_GCM_SHA256,
            Dtls13CipherSuite::AES_256_GCM_SHA384,
            Dtls13CipherSuite::CHACHA20_POLY1305_SHA256,
            Dtls13CipherSuite::AES_128_CCM_SHA256,
            Dtls13CipherSuite::AES_128_CCM_8_SHA256,
        ]
    }

    /// Supported DTLS 1.3 cipher suites in preference order.
    pub fn supported() -> &'static [Dtls13CipherSuite] {
        &[
            Dtls13CipherSuite::AES_128_GCM_SHA256,
            Dtls13CipherSuite::AES_256_GCM_SHA384,
        ]
    }

    /// Length in bytes of verify_data for Finished messages.
    pub fn verify_data_length(&self) -> usize {
        self.hash_algorithm().output_len()
    }
}

// ============================================================================
// Protocol Version
// ============================================================================

/// DTLS protocol version identifiers.
///
/// Used in record headers and handshake messages for both DTLS 1.2 and 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// DTLS 1.0.
    DTLS1_0,
    /// DTLS 1.2.
    DTLS1_2,
    /// DTLS 1.3.
    DTLS1_3,
    /// Unknown protocol version.
    Unknown(u16),
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl ProtocolVersion {
    /// Convert this `ProtocolVersion` to its wire format u16 value.
    pub fn as_u16(&self) -> u16 {
        match self {
            ProtocolVersion::DTLS1_0 => 0xFEFF,
            ProtocolVersion::DTLS1_2 => 0xFEFD,
            ProtocolVersion::DTLS1_3 => 0xFEFC,
            ProtocolVersion::Unknown(value) => *value,
        }
    }

    /// Parse a `ProtocolVersion` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], ProtocolVersion> {
        let (input, version) = be_u16(input)?;
        let protocol_version = match version {
            0xFEFF => ProtocolVersion::DTLS1_0,
            0xFEFD => ProtocolVersion::DTLS1_2,
            0xFEFC => ProtocolVersion::DTLS1_3,
            _ => ProtocolVersion::Unknown(version),
        };
        Ok((input, protocol_version))
    }

    /// Serialize this `ProtocolVersion` to wire format.
    pub fn serialize(&self, output: &mut crate::buffer::Buf) {
        output.extend_from_slice(&self.as_u16().to_be_bytes());
    }
}

// ============================================================================
// Compression Method
// ============================================================================

/// TLS compression methods.
///
/// Used in ClientHello/ServerHello for both DTLS 1.2 and 1.3.
/// TLS 1.3 only uses Null compression but includes it for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// No compression.
    Null,
    /// DEFLATE compression.
    Deflate,
    /// Unknown compression method.
    Unknown(u8),
}

impl Default for CompressionMethod {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl CompressionMethod {
    /// Convert a u8 value to a `CompressionMethod`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => CompressionMethod::Null,
            0x01 => CompressionMethod::Deflate,
            _ => CompressionMethod::Unknown(value),
        }
    }

    /// Returns true if this compression method is supported by this implementation.
    pub fn is_supported(&self) -> bool {
        Self::supported().contains(self)
    }

    /// All recognized compression methods (every non-`Unknown` variant).
    pub const fn all() -> &'static [CompressionMethod; 2] {
        &[CompressionMethod::Null, CompressionMethod::Deflate]
    }

    /// Supported compression methods.
    ///
    /// Only null compression is supported. TLS 1.3 / DTLS 1.3 (RFC 8446
    /// §4.1.2) mandates exactly one compression method (null). DEFLATE
    /// is recognized by parsing but not accepted.
    pub const fn supported() -> &'static [CompressionMethod; 1] {
        &[CompressionMethod::Null]
    }

    /// Convert this `CompressionMethod` to its u8 value.
    pub fn as_u8(&self) -> u8 {
        match self {
            CompressionMethod::Null => 0x00,
            CompressionMethod::Deflate => 0x01,
            CompressionMethod::Unknown(value) => *value,
        }
    }

    /// Parse a `CompressionMethod` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], CompressionMethod> {
        let (input, value) = be_u8(input)?;
        Ok((input, CompressionMethod::from_u8(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_parse() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];

        let expected = Random { bytes: data };

        let (_, parsed) = Random::parse(&data).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn random_serialize() {
        let random = Random {
            bytes: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20,
            ],
        };

        let mut serialized = Buf::new();
        random.serialize(&mut serialized);

        assert_eq!(&*serialized, &random.bytes);
    }

    #[test]
    fn compression_supported_has_only_null() {
        let supported = CompressionMethod::supported();
        assert_eq!(
            supported,
            &[CompressionMethod::Null],
            "Only Null compression should be supported"
        );
    }

    #[test]
    fn random_parse_roundtrip() {
        let data = [
            0x5F, 0x37, 0xA9, 0x4B, // could be gmt_unix_time in 1.2
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        ];

        let (_, parsed) = Random::parse(&data).unwrap();
        let mut serialized = Buf::new();
        parsed.serialize(&mut serialized);

        assert_eq!(&*serialized, &data[..]);
    }
}
