use core::fmt;

use crate::codec::{Checked, CheckedMut, Codec};
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    Dtls1_0,
    Dtls1_2,
}

impl Codec for ProtocolVersion {
    fn encoded_length() -> usize {
        2
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        use ProtocolVersion::*;
        // DTLS versions are using 1-complement.
        match self {
            Dtls1_0 => {
                out[0] = !1;
                out[1] = !0;
            }
            Dtls1_2 => {
                out[0] = !1;
                out[1] = !2;
            }
        }
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        use ProtocolVersion::*;
        match (bytes[0], bytes[1]) {
            (0xfe, 0xff) => Ok(Dtls1_0),
            (0xfe, 0xfd) => Ok(Dtls1_2),
            _ => Err(Error::UnsupportedTlsVersion(bytes[0], bytes[1])),
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ProtocolVersion::*;
        write!(
            f,
            "{}",
            match self {
                Dtls1_0 => "DTLS 1.0",
                Dtls1_2 => "DTLS 1.2",
            }
        )
    }
}
