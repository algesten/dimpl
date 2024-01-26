use crate::codec::CodecVariable;
use crate::types::{HandshakeType, Length24};

use super::client_hello::ClientHello;
use super::fragment::DtlsFragment;

#[derive(Debug, Clone)]
pub struct Handshake {
    pub handshake_type: HandshakeType,
    pub length: Length24,
    // pub message_seq: MessageSeq,
    // pub fragment_offset: FragmentOffset,
    pub fragment_length: Length24,
    pub body: HandshakeVariant,
}

#[derive(Debug, Clone)]
pub enum HandshakeVariant {
    ClientHello(ClientHello),
}

impl CodecVariable<()> for Handshake {
    fn encoded_length(&self) -> usize {
        todo!()
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), crate::DimplError> {
        todo!()
    }

    fn decode(bytes: &[u8], _: ()) -> Result<Self, crate::DimplError> {
        todo!()
    }
}

impl From<Handshake> for DtlsFragment {
    fn from(value: Handshake) -> Self {
        DtlsFragment::Handshake(value)
    }
}
