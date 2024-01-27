use crate::codec::{Checked, CheckedMut, Codec};
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    HelloVerifyRequest,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
}

impl TryFrom<u8> for HandshakeType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use HandshakeType::*;
        Ok(match value {
            0 => HelloRequest,
            1 => ClientHello,
            2 => ServerHello,
            3 => HelloVerifyRequest,
            11 => Certificate,
            12 => ServerKeyExchange,
            13 => CertificateRequest,
            14 => ServerHelloDone,
            15 => CertificateVerify,
            16 => ClientKeyExchange,
            20 => Finished,
            _ => return Err(Error::TooShort),
        })
    }
}

impl From<HandshakeType> for u8 {
    fn from(value: HandshakeType) -> Self {
        use HandshakeType::*;
        match value {
            HelloRequest => 0,
            ClientHello => 1,
            ServerHello => 2,
            HelloVerifyRequest => 3,
            Certificate => 11,
            ServerKeyExchange => 12,
            CertificateRequest => 13,
            ServerHelloDone => 14,
            CertificateVerify => 15,
            ClientKeyExchange => 16,
            Finished => 20,
        }
    }
}

impl Codec for HandshakeType {
    fn encoded_length() -> usize {
        1
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        out[0] = (*self).into();
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        Ok(bytes[0].try_into()?)
    }
}
