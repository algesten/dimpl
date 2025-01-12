mod certificate;
mod client_hello;
mod error;
mod hello_verify_request;
mod id;
mod server_hello;

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
