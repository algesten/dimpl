//! Cipher suite definitions.

// TODO: support more. Do we avoid RSA?
// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // c02f

use crate::codec::{Checked, CheckedMut, Codec};
use crate::Error;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // c02b
    UNKNOWN,
}

impl Codec for CipherSuite {
    fn encoded_length() -> usize {
        2
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        use CipherSuite::*;
        match self {
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                out[0] = 0xc0;
                out[1] = 0x2b;
            }
            UNKNOWN => {
                unreachable!("Attempt to encode UNKNOWN cipher suite")
            }
        }
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        match (bytes[0], bytes[1]) {
            (0xc0, 0x2b) => return Ok(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            _ => {}
        }

        // We don't know this suite
        Ok(CipherSuite::UNKNOWN)
    }
}
