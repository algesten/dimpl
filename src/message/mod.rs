// TODO(martin): remove these once we use all the parsers.
#![allow(unused_imports)]
#![allow(unused)]

mod certificate;
mod certificate_request;
mod certificate_verify;
mod client_diffie_hellman;
mod client_hello;
mod client_key_exchange;
mod digitally_signed;
mod extension;
mod extensions;
mod finished;
mod handshake;
mod hello_verify;
mod id;
mod named_curve;
mod random;
mod record;
mod server_hello;
mod server_key_exchange;
mod wrapped;

pub use certificate::Certificate;
pub use certificate_request::CertificateRequest;
pub use certificate_verify::CertificateVerify;
pub use client_diffie_hellman::ClientDiffieHellmanPublic;
pub use client_hello::ClientHello;
pub use client_key_exchange::{ClientEcdhKeys, ClientKeyExchange, ExchangeKeys};
pub use digitally_signed::DigitallySigned;
pub use extension::{Extension, ExtensionType};
pub use extensions::use_srtp::{SrtpProfileId, UseSrtpExtension};
pub use finished::Finished;
pub use handshake::{Body, Handshake, Header, MessageType};
pub use hello_verify::HelloVerifyRequest;
pub use id::{Cookie, SessionId};
pub use named_curve::{CurveType, NamedCurve};
pub use nom::error::{Error, ErrorKind};
pub use random::Random;
pub use record::{ContentType, DTLSRecord, Sequence};
pub use server_hello::ServerHello;
pub use server_key_exchange::{DhParams, EcdhParams, ServerKeyExchange, ServerKeyExchangeParams};
use tinyvec::{array_vec, ArrayVec};
pub use wrapped::{Asn1Cert, DistinguishedName};

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
    pub fn from_u16(value: u16) -> Self {
        match value {
            0xFEFF => ProtocolVersion::DTLS1_0,
            0xFEFD => ProtocolVersion::DTLS1_2,
            0xFEFC => ProtocolVersion::DTLS1_3,
            _ => ProtocolVersion::Unknown(value),
        }
    }

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

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.as_u16().to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CipherSuite {
    EECDH_AESGCM,
    EDH_AESGCM,
    AES256_EECDH,
    AES256_EDH,
    Unknown(u16),
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl CipherSuite {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0xC02F => CipherSuite::EECDH_AESGCM,
            0xC030 => CipherSuite::EDH_AESGCM,
            0xC031 => CipherSuite::AES256_EECDH,
            0xC032 => CipherSuite::AES256_EDH,
            _ => CipherSuite::Unknown(value),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            CipherSuite::EECDH_AESGCM => 0xC02F,
            CipherSuite::EDH_AESGCM => 0xC030,
            CipherSuite::AES256_EECDH => 0xC031,
            CipherSuite::AES256_EDH => 0xC032,
            CipherSuite::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], CipherSuite> {
        let (input, value) = be_u16(input)?;
        Ok((input, CipherSuite::from_u16(value)))
    }

    pub fn verify_data_length(&self) -> usize {
        match self {
            CipherSuite::EECDH_AESGCM | CipherSuite::EDH_AESGCM => 12,
            CipherSuite::AES256_EECDH | CipherSuite::AES256_EDH => 12,
            CipherSuite::Unknown(_) => 12, // Default to 12 for unknown suites
        }
    }

    pub fn as_key_exchange_algorithm(&self) -> KeyExchangeAlgorithm {
        match self {
            CipherSuite::EECDH_AESGCM | CipherSuite::AES256_EECDH => KeyExchangeAlgorithm::EECDH,
            CipherSuite::EDH_AESGCM | CipherSuite::AES256_EDH => KeyExchangeAlgorithm::EDH,
            CipherSuite::Unknown(_) => KeyExchangeAlgorithm::Unknown,
        }
    }

    pub fn has_ecc(&self) -> bool {
        matches!(
            self,
            CipherSuite::EECDH_AESGCM
                | CipherSuite::EDH_AESGCM
                | CipherSuite::AES256_EECDH
                | CipherSuite::AES256_EDH
        )
    }

    pub(crate) fn all() -> ArrayVec<[CipherSuite; 32]> {
        let mut suites = ArrayVec::new();
        suites.push(CipherSuite::EECDH_AESGCM);
        suites.push(CipherSuite::EDH_AESGCM);
        suites.push(CipherSuite::AES256_EECDH);
        suites.push(CipherSuite::AES256_EDH);
        suites
    }
}

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
pub enum KeyExchangeAlgorithm {
    EECDH,
    EDH,
    Unknown,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum SignatureAlgorithm {
    Anonymous,
    RSA,
    DSA,
    ECDSA,
    Unknown(u8),
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl SignatureAlgorithm {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => SignatureAlgorithm::Anonymous,
            1 => SignatureAlgorithm::RSA,
            2 => SignatureAlgorithm::DSA,
            3 => SignatureAlgorithm::ECDSA,
            _ => SignatureAlgorithm::Unknown(value),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            SignatureAlgorithm::Anonymous => 0,
            SignatureAlgorithm::RSA => 1,
            SignatureAlgorithm::DSA => 2,
            SignatureAlgorithm::ECDSA => 3,
            SignatureAlgorithm::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAlgorithm> {
        let (input, value) = be_u8(input)?;
        Ok((input, SignatureAlgorithm::from_u8(value)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum HashAlgorithm {
    None,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    Unknown(u8),
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl HashAlgorithm {
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], HashAlgorithm> {
        let (input, value) = be_u8(input)?;
        Ok((input, HashAlgorithm::from_u8(value)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}

impl SignatureAndHashAlgorithm {
    pub fn new(hash: HashAlgorithm, signature: SignatureAlgorithm) -> Self {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicValueEncoding {
    Implicit,
    Explicit,
    Unknown(u8),
}

impl PublicValueEncoding {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => PublicValueEncoding::Implicit,
            1 => PublicValueEncoding::Explicit,
            _ => PublicValueEncoding::Unknown(value),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            PublicValueEncoding::Implicit => 0,
            PublicValueEncoding::Explicit => 1,
            PublicValueEncoding::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], PublicValueEncoding> {
        let (input, value) = be_u8(input)?;
        Ok((input, PublicValueEncoding::from_u8(value)))
    }
}
