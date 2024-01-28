use crate::codec::{Checked, CheckedMut, CodecVar};
use crate::types::random::Random;
use crate::types::varvec::{CipherSuites, CompressionMethods, SessionId};
use crate::types::version::ProtocolVersion;
use crate::Error;

use super::fragment::DtlsFragment;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suites: CipherSuites,
    pub compression_methods: CompressionMethods,
}

impl CodecVar for ClientHello {
    fn encoded_length(&self) -> usize {
        todo!()
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        todo!()
    }

    fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
        todo!()
    }
}

impl From<ClientHello> for DtlsFragment {
    fn from(value: ClientHello) -> Self {
        todo!()
    }
}
