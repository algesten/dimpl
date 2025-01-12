mod client_hello;
mod error;
mod id;
mod util;

use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    EECDH_AESGCM,
    EDH_AESGCM,
    AES256_EECDH,
    AES256_EDH,
    Unknown(u16),
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

    pub fn to_u16(&self) -> u16 {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    EECDH,
    EDH,
    Unknown,
}

impl KeyExchangeAlgorithm {
    pub fn from_cipher_suite(cipher_suite: CipherSuite) -> Self {
        match cipher_suite {
            CipherSuite::EECDH_AESGCM | CipherSuite::AES256_EECDH => KeyExchangeAlgorithm::EECDH,
            CipherSuite::EDH_AESGCM | CipherSuite::AES256_EDH => KeyExchangeAlgorithm::EDH,
            _ => KeyExchangeAlgorithm::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Null,
    Deflate,
    Unknown(u8),
}

impl CompressionMethod {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => CompressionMethod::Null,
            0x01 => CompressionMethod::Deflate,
            _ => CompressionMethod::Unknown(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
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
pub enum ProtocolVersion {
    DTLS1_0,
    DTLS1_2,
    DTLS1_3,
    Unknown(u16),
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

    pub fn to_u16(&self) -> u16 {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    HelloRequest,
    ClientHello,
    HelloVerifyRequest,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    Unknown(u8),
}

impl MessageType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => MessageType::HelloRequest, // empty
            1 => MessageType::ClientHello,
            3 => MessageType::HelloVerifyRequest,
            2 => MessageType::ServerHello,
            11 => MessageType::Certificate,
            12 => MessageType::ServerKeyExchange,
            13 => MessageType::CertificateRequest,
            14 => MessageType::ServerHelloDone, // empty
            15 => MessageType::CertificateVerify,
            16 => MessageType::ClientKeyExchange,
            20 => MessageType::Finished,
            _ => MessageType::Unknown(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            MessageType::HelloRequest => 0,
            MessageType::ClientHello => 1,
            MessageType::HelloVerifyRequest => 3,
            MessageType::ServerHello => 2,
            MessageType::Certificate => 11,
            MessageType::ServerKeyExchange => 12,
            MessageType::CertificateRequest => 13,
            MessageType::ServerHelloDone => 14,
            MessageType::CertificateVerify => 15,
            MessageType::ClientKeyExchange => 16,
            MessageType::Finished => 20,
            MessageType::Unknown(value) => *value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    pub fn to_u8(&self) -> u8 {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Anonymous,
    RSA,
    DSA,
    ECDSA,
    Unknown(u8),
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

    pub fn to_u8(&self) -> u8 {
        match self {
            SignatureAlgorithm::Anonymous => 0,
            SignatureAlgorithm::RSA => 1,
            SignatureAlgorithm::DSA => 2,
            SignatureAlgorithm::ECDSA => 3,
            SignatureAlgorithm::Unknown(value) => *value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    pub fn to_u8(&self) -> u8 {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    pub fn to_u16(&self) -> u16 {
        ((self.hash.to_u8() as u16) << 8) | (self.signature.to_u8() as u16)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistinguishedName<'a>(pub &'a [u8]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyEncrypted<'a>(pub &'a [u8]);

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

    pub fn to_u8(&self) -> u8 {
        match self {
            PublicValueEncoding::Implicit => 0,
            PublicValueEncoding::Explicit => 1,
            PublicValueEncoding::Unknown(value) => *value,
        }
    }
}
