//! Compression method definitions (null)

use crate::codec::{Checked, CheckedMut, Codec};
use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Null,
    Unknown,
}

impl Codec for CompressionMethod {
    fn encoded_length() -> usize {
        1
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        use CompressionMethod::*;
        match self {
            Null => {
                out[0] = 0;
            }
            Unknown => {
                unreachable!("Attempt to encode Unknown compression method")
            }
        }
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        if bytes[0] == 0 {
            Ok(CompressionMethod::Null)
        } else {
            Ok(CompressionMethod::Unknown)
        }
    }
}
