use crate::codec::Codec;
use crate::DimplError;

pub enum ProtocolVersion {
    Dtls1_2,
}

impl Codec for ProtocolVersion {
    fn encode_length(&self) -> usize {
        2
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), crate::DimplError> {
        match self {
            ProtocolVersion::Dtls1_2 => {
                // DTLS version are using 1-complement.
                out[0] = !1;
                out[1] = !2;
            }
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, crate::DimplError> {
        if bytes[0] == 3 && bytes[1] == 3 {
            Ok(ProtocolVersion::Dtls1_2)
        } else {
            Err(DimplError::UnsupportedTlsVersion(bytes[0], bytes[1]))
        }
    }
}
