//! Low-level DTLS message parsing and serialization types.
//!
//! This module exposes enums and helpers used by the public API for negotiating
//! cipher suites and signature algorithms, as well as parsing wire formats.
//! Only the public items are documented here; the rest are internal helpers.

mod certificate;
mod certificate_request;
mod certificate_verify;
mod client_hello;
mod client_key_exchange;
mod digitally_signed;
mod extension;
mod extensions;
mod finished;
mod handshake;
mod hello_verify;
mod id;
mod named_group;
mod random;
mod record;
mod server_hello;
mod server_key_exchange;
mod wrapped;

use arrayvec::ArrayVec;
pub use certificate::Certificate;
pub use certificate_request::CertificateRequest;
pub use certificate_verify::CertificateVerify;
pub use client_hello::ClientHello;
pub use client_key_exchange::{ClientKeyExchange, ExchangeKeys};
pub use digitally_signed::DigitallySigned;
pub use extension::{Extension, ExtensionType};
pub use extensions::signature_algorithms::SignatureAlgorithmsExtension;
pub use extensions::supported_groups::SupportedGroupsExtension;
pub use extensions::use_srtp::{SrtpProfileId, SrtpProfileVec, UseSrtpExtension};
pub use finished::Finished;
pub use handshake::{Body, Handshake, Header, MessageType};
pub use hello_verify::HelloVerifyRequest;
pub use id::{Cookie, SessionId};
pub use named_group::CurveType;
pub use random::Random;
pub use record::DTLSRecord;

// Re-export shared types for backwards compatibility
pub use crate::types::{
    ContentType, HashAlgorithm, NamedGroup, NamedGroupVec, Sequence, SignatureAlgorithm,
};
pub use server_hello::ServerHello;
pub use server_key_exchange::{ServerKeyExchange, ServerKeyExchangeParams};
pub use wrapped::{Asn1Cert, DistinguishedName};

use crate::buffer::Buf;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    DTLS1_0,
    DTLS1_2,
    DTLS1_3,
    Unknown(u16),
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl ProtocolVersion {
    pub fn as_u16(&self) -> u16 {
        match self {
            ProtocolVersion::DTLS1_0 => 0xFEFF,
            ProtocolVersion::DTLS1_2 => 0xFEFD,
            ProtocolVersion::DTLS1_3 => 0xFEFC,
            ProtocolVersion::Unknown(value) => *value,
        }
    }

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

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.as_u16().to_be_bytes());
    }
}

pub type CipherSuiteVec = ArrayVec<Dtls12CipherSuite, { Dtls12CipherSuite::supported().len() }>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
/// Supported TLS 1.2 cipher suites for DTLS.
pub enum Dtls12CipherSuite {
    // ECDHE with AES-GCM
    /// ECDHE with ECDSA authentication, AES-256-GCM, SHA-384
    ECDHE_ECDSA_AES256_GCM_SHA384, // 0xC02C
    /// ECDHE with ECDSA authentication, AES-128-GCM, SHA-256
    ECDHE_ECDSA_AES128_GCM_SHA256, // 0xC02B

    /// Unknown or unsupported cipher suite by its IANA value
    Unknown(u16),
}

impl Default for Dtls12CipherSuite {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl Dtls12CipherSuite {
    /// Convert the 16-bit IANA value to a `Dtls12CipherSuite`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            // ECDHE with AES-GCM
            0xC02C => Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
            0xC02B => Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,

            _ => Dtls12CipherSuite::Unknown(value),
        }
    }

    /// Return the 16-bit IANA value for this cipher suite.
    pub fn as_u16(&self) -> u16 {
        match self {
            // ECDHE with AES-GCM
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => 0xC02C,
            Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => 0xC02B,

            Dtls12CipherSuite::Unknown(value) => *value,
        }
    }

    /// Parse a `Dtls12CipherSuite` from network byte order.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Dtls12CipherSuite> {
        let (input, value) = be_u16(input)?;
        Ok((input, Dtls12CipherSuite::from_u16(value)))
    }

    /// Length in bytes of verify_data for Finished MACs.
    pub fn verify_data_length(&self) -> usize {
        match self {
            // AES-GCM suites
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
            | Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => 12,

            Dtls12CipherSuite::Unknown(_) => 12, // Default length for unknown cipher suites
        }
    }

    /// The key exchange algorithm family for this cipher suite.
    pub fn as_key_exchange_algorithm(&self) -> KeyExchangeAlgorithm {
        match self {
            // All ECDHE ciphers
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
            | Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => KeyExchangeAlgorithm::EECDH,

            Dtls12CipherSuite::Unknown(_) => KeyExchangeAlgorithm::Unknown,
        }
    }

    /// Whether this cipher suite uses ECC-based key exchange.
    pub fn has_ecc(&self) -> bool {
        matches!(
            self,
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
                | Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
        )
    }

    /// All supported cipher suites in server preference order.
    pub const fn all() -> &'static [Dtls12CipherSuite; 2] {
        &[
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
            Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
        ]
    }

    /// Cipher suites compatible with a given certificate's signature algorithm.
    pub fn compatible_with_certificate(
        cert_type: SignatureAlgorithm,
    ) -> &'static [Dtls12CipherSuite; 2] {
        match cert_type {
            SignatureAlgorithm::ECDSA => &[
                Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
                Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
            ],
            _ => panic!("Need either RSA or ECDSA certificate"),
        }
    }

    fn need_encrypt_then_mac(&self) -> bool {
        // We do not support and ciphers such as:
        // ECDHE-RSA-AES128-SHA
        // ECDHE-RSA-AES256-SHA
        // DHE-RSA-AES128-SHA256
        false
    }

    /// The hash algorithm used by this cipher suite.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => HashAlgorithm::SHA384,
            Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => HashAlgorithm::SHA256,
            Dtls12CipherSuite::Unknown(_) => HashAlgorithm::Unknown(0),
        }
    }

    /// The signature algorithm associated with the suite's key exchange.
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        match self {
            Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => SignatureAlgorithm::ECDSA,
            Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => SignatureAlgorithm::ECDSA,
            Dtls12CipherSuite::Unknown(_) => SignatureAlgorithm::Unknown(0),
        }
    }

    /// Returns true if this cipher suite is supported by this implementation.
    pub fn is_supported(&self) -> bool {
        Self::supported().contains(self)
    }

    /// Supported DTLS 1.2 cipher suites in server preference order.
    pub const fn supported() -> &'static [CipherSuite; 2] {
        Self::all()
    }
}

pub type CompressionMethodVec =
    ArrayVec<CompressionMethod, { CompressionMethod::supported().len() }>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Null,
    Deflate,
    Unknown(u8),
}

impl Default for CompressionMethod {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl CompressionMethod {
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
    pub const fn supported() -> &'static [CompressionMethod; 2] {
        Self::all()
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            CompressionMethod::Null => 0x00,
            CompressionMethod::Deflate => 0x01,
            CompressionMethod::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], CompressionMethod> {
        let (input, value) = be_u8(input)?;
        Ok((input, CompressionMethod::from_u8(value)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum KeyExchangeAlgorithm {
    EECDH,
    Unknown,
}

pub type CertificateTypeVec =
    ArrayVec<ClientCertificateType, { ClientCertificateType::supported().len() }>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum ClientCertificateType {
    RSA_SIGN,
    DSS_SIGN,
    RSA_FIXED_DH,
    DSS_FIXED_DH,
    RSA_EPHEMERAL_DH,
    DSS_EPHEMERAL_DH,
    FORTEZZA_DMS,
    ECDSA_SIGN,
    Unknown(u8),
}

impl Default for ClientCertificateType {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl ClientCertificateType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => ClientCertificateType::RSA_SIGN,
            2 => ClientCertificateType::DSS_SIGN,
            3 => ClientCertificateType::RSA_FIXED_DH,
            4 => ClientCertificateType::DSS_FIXED_DH,
            5 => ClientCertificateType::RSA_EPHEMERAL_DH,
            6 => ClientCertificateType::DSS_EPHEMERAL_DH,
            20 => ClientCertificateType::FORTEZZA_DMS,
            64 => ClientCertificateType::ECDSA_SIGN,
            _ => ClientCertificateType::Unknown(value),
        }
    }

    /// Returns true if this certificate type is supported by this implementation.
    /// Currently only ECDSA_SIGN is supported.
    pub fn is_supported(&self) -> bool {
        Self::supported().contains(self)
    }

    /// Supported client certificate types.
    pub const fn supported() -> &'static [ClientCertificateType; 1] {
        &[ClientCertificateType::ECDSA_SIGN]
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            ClientCertificateType::RSA_SIGN => 1,
            ClientCertificateType::DSS_SIGN => 2,
            ClientCertificateType::RSA_FIXED_DH => 3,
            ClientCertificateType::DSS_FIXED_DH => 4,
            ClientCertificateType::RSA_EPHEMERAL_DH => 5,
            ClientCertificateType::DSS_EPHEMERAL_DH => 6,
            ClientCertificateType::FORTEZZA_DMS => 20,
            ClientCertificateType::ECDSA_SIGN => 64,
            ClientCertificateType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ClientCertificateType> {
        let (input, value) = be_u8(input)?;
        Ok((input, ClientCertificateType::from_u8(value)))
    }
}

// SignatureAlgorithm and HashAlgorithm are now in crate::types

pub type SignatureAndHashAlgorithmVec =
    ArrayVec<SignatureAndHashAlgorithm, { SignatureAndHashAlgorithm::supported().len() }>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}

impl SignatureAndHashAlgorithm {
    pub const fn new(hash: HashAlgorithm, signature: SignatureAlgorithm) -> Self {
        SignatureAndHashAlgorithm { hash, signature }
    }

    pub fn from_u16(value: u16) -> Self {
        let hash = HashAlgorithm::from_u8((value >> 8) as u8);
        let signature = SignatureAlgorithm::from_u8(value as u8);
        SignatureAndHashAlgorithm { hash, signature }
    }

    pub fn as_u16(&self) -> u16 {
        ((self.hash.as_u8() as u16) << 8) | (self.signature.as_u8() as u16)
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAndHashAlgorithm> {
        let (input, value) = be_u16(input)?;
        Ok((input, SignatureAndHashAlgorithm::from_u16(value)))
    }

    /// All recognized signature+hash combinations (same as `supported()`).
    #[allow(dead_code)]
    pub const fn all() -> &'static [SignatureAndHashAlgorithm; 4] {
        Self::supported()
    }

    /// Supported signature+hash combinations.
    pub const fn supported() -> &'static [SignatureAndHashAlgorithm; 4] {
        const SUPPORTED: &[SignatureAndHashAlgorithm; 4] = &[
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::ECDSA),
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA384, SignatureAlgorithm::ECDSA),
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA384, SignatureAlgorithm::RSA),
        ];

        SUPPORTED
    }

    /// Returns true if this signature+hash combination is supported.
    pub fn is_supported(&self) -> bool {
        Self::supported().contains(self)
    }
}
