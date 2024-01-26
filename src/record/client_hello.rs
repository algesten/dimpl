use crate::codec::CodecVariable;
use crate::types::HandshakeType;

use super::fragment::DtlsFragment;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub handshake_type: HandshakeType,
}

impl CodecVariable<()> for ClientHello {
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

impl From<ClientHello> for DtlsFragment {
    fn from(value: ClientHello) -> Self {
        todo!()
    }
}
