mod certificate;
mod client_hello;
mod error;
mod hello_verify_request;
mod id;
mod server_hello;
mod server_key_exchange;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1_0,
    V1_2,
    V1_3,
    Unknown(u16),
}

impl ProtocolVersion {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0xFEFF => ProtocolVersion::V1_0,
            0xFEFD => ProtocolVersion::V1_2,
            0xFEFC => ProtocolVersion::V1_3,
            _ => ProtocolVersion::Unknown(value),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            ProtocolVersion::V1_0 => 0xFEFF,
            ProtocolVersion::V1_2 => 0xFEFD,
            ProtocolVersion::V1_3 => 0xFEFC,
            ProtocolVersion::Unknown(value) => *value,
        }
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
            0 => MessageType::HelloRequest,
            1 => MessageType::ClientHello,
            3 => MessageType::HelloVerifyRequest,
            2 => MessageType::ServerHello,
            11 => MessageType::Certificate,
            12 => MessageType::ServerKeyExchange,
            13 => MessageType::CertificateRequest,
            14 => MessageType::ServerHelloDone,
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
pub enum ErrorKind {
    KeyExchangeAlgorithmNotEnough,
    // ...existing code...
}
