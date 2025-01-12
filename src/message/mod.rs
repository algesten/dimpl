mod certificate;
mod certificate_request;
mod certificate_verify;
mod client_diffie_hellman;
mod client_hello;
mod client_key_exchange;
mod digitally_signed;
mod extension;
mod finished;
mod handshake;
mod hello_verify;
mod id;
mod named_curve;
mod server_hello;
mod server_key_exchange;
mod util;
mod wrapped;

pub use certificate::Certificate;
pub use certificate_request::CertificateRequest;
pub use certificate_verify::CertificateVerify;
pub use client_diffie_hellman::ClientDiffieHellmanPublic;
pub use client_hello::ClientHello;
pub use client_key_exchange::ClientKeyExchange;
pub use digitally_signed::DigitallySigned;
pub use extension::{Extension, ExtensionType};
pub use finished::Finished;
pub use hello_verify::HelloVerifyRequest;
pub use id::{Cookie, Random, SessionId};
pub use named_curve::{CurveType, NamedCurve};
pub use nom::error::{Error, ErrorKind};
pub use server_hello::ServerHello;
pub use server_key_exchange::ServerKeyExchange;
pub use wrapped::{Asn1Cert, DistinguishedName};

use nom::number::complete::{be_u16, be_u8};
use nom::{Err, IResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    HelloRequest, // empty
    ClientHello,
    HelloVerifyRequest,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone, // empty
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], MessageType> {
        let (input, byte) = be_u8(input)?;
        Ok((input, Self::from_u8(byte)))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Message<'a> {
    HelloRequest, // empty
    ClientHello(ClientHello),
    HelloVerifyRequest(HelloVerifyRequest),
    ServerHello(ServerHello<'a>),
    Certificate(Certificate<'a>),
    ServerKeyExchange(ServerKeyExchange<'a>),
    CertificateRequest(CertificateRequest<'a>),
    ServerHelloDone, // empty
    CertificateVerify(CertificateVerify<'a>),
    ClientKeyExchange(ClientKeyExchange<'a>),
    Finished(Finished<'a>),
    Unknown(u8),
    Fragment(&'a [u8]),
}

impl<'a> Message<'a> {
    pub fn parse(
        input: &'a [u8],
        m: MessageType,
        c: Option<CipherSuite>,
    ) -> IResult<&'a [u8], Message<'a>> {
        match m {
            MessageType::HelloRequest => Ok((input, Message::HelloRequest)),
            MessageType::ClientHello => {
                let (input, client_hello) = ClientHello::parse(input)?;
                Ok((input, Message::ClientHello(client_hello)))
            }
            MessageType::HelloVerifyRequest => {
                let (input, hello_verify_request) = HelloVerifyRequest::parse(input)?;
                Ok((input, Message::HelloVerifyRequest(hello_verify_request)))
            }
            MessageType::ServerHello => {
                let (input, server_hello) = ServerHello::parse(input)?;
                Ok((input, Message::ServerHello(server_hello)))
            }
            MessageType::Certificate => {
                let (input, certificate) = Certificate::parse(input)?;
                Ok((input, Message::Certificate(certificate)))
            }
            MessageType::ServerKeyExchange => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let algo = cipher_suite.to_key_exchange_algorithm();
                let (input, server_key_exchange) = ServerKeyExchange::parse(input, algo)?;
                Ok((input, Message::ServerKeyExchange(server_key_exchange)))
            }
            MessageType::CertificateRequest => {
                let (input, certificate_request) = CertificateRequest::parse(input)?;
                Ok((input, Message::CertificateRequest(certificate_request)))
            }
            MessageType::ServerHelloDone => Ok((input, Message::ServerHelloDone)),
            MessageType::CertificateVerify => {
                let (input, certificate_verify) = CertificateVerify::parse(input)?;
                Ok((input, Message::CertificateVerify(certificate_verify)))
            }
            MessageType::ClientKeyExchange => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let algo = cipher_suite.to_key_exchange_algorithm();
                let (input, client_key_exchange) = ClientKeyExchange::parse(input, algo)?;
                Ok((input, Message::ClientKeyExchange(client_key_exchange)))
            }
            MessageType::Finished => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let (input, finished) = Finished::parse(input, cipher_suite)?;
                Ok((input, Message::Finished(finished)))
            }
            MessageType::Unknown(value) => Ok((input, Message::Unknown(value))),
        }
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        match self {
            Message::HelloRequest => {
                // Serialize HelloRequest (empty)
            }
            Message::ClientHello(client_hello) => {
                client_hello.serialize(output);
            }
            Message::HelloVerifyRequest(hello_verify_request) => {
                hello_verify_request.serialize(output);
            }
            Message::ServerHello(server_hello) => {
                server_hello.serialize(output);
            }
            Message::Certificate(certificate) => {
                certificate.serialize(output);
            }
            Message::ServerKeyExchange(server_key_exchange) => {
                server_key_exchange.serialize(output);
            }
            Message::CertificateRequest(certificate_request) => {
                certificate_request.serialize(output);
            }
            Message::ServerHelloDone => {
                // Serialize ServerHelloDone (empty)
            }
            Message::CertificateVerify(certificate_verify) => {
                certificate_verify.serialize(output);
            }
            Message::ClientKeyExchange(client_key_exchange) => {
                client_key_exchange.serialize(output);
            }
            Message::Finished(finished) => {
                finished.serialize(output);
            }
            Message::Unknown(value) => {
                output.push(*value);
            }
            Message::Fragment(_) => unreachable!(),
        }
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

    pub fn verify_data_length(&self) -> usize {
        match self {
            CipherSuite::EECDH_AESGCM | CipherSuite::EDH_AESGCM => 12,
            CipherSuite::AES256_EECDH | CipherSuite::AES256_EDH => 12,
            CipherSuite::Unknown(_) => 12, // Default length for unknown cipher suites
        }
    }

    pub fn to_key_exchange_algorithm(&self) -> KeyExchangeAlgorithm {
        match self {
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
pub enum KeyExchangeAlgorithm {
    EECDH,
    EDH,
    Unknown,
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], ClientCertificateType> {
        let (input, value) = be_u8(input)?;
        Ok((input, ClientCertificateType::from_u8(value)))
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAlgorithm> {
        let (input, value) = be_u8(input)?;
        Ok((input, SignatureAlgorithm::from_u8(value)))
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], HashAlgorithm> {
        let (input, value) = be_u8(input)?;
        Ok((input, HashAlgorithm::from_u8(value)))
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

    pub fn to_u8(&self) -> u8 {
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
