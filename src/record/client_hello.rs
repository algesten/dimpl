use crate::codec::CodecVariable;
use crate::types::random::Random;
use crate::types::varvec::SessionId;
use crate::types::version::ProtocolVersion;

use super::fragment::DtlsFragment;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
}

impl CodecVariable for ClientHello {
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
