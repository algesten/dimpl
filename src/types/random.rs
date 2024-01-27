use crate::codec::{Checked, SliceCheck};
use crate::codec::{CheckedMut, Codec};
use crate::Error;

use super::numerics::GmtUnixTime;

const RANDOM_BYTES: usize = 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Random {
    pub gmt_unix_time: GmtUnixTime,
    pub random_bytes: [u8; RANDOM_BYTES],
}

impl Codec for Random {
    fn encoded_length() -> usize {
        GmtUnixTime::encoded_length() + RANDOM_BYTES
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        let out = self.gmt_unix_time.encode_fixed(&mut *out)?;
        let (mut dst, _) = out.checked_split_mut(RANDOM_BYTES)?;
        dst.copy_from_slice(&self.random_bytes);
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        let (gmt_unix_time, bytes) = GmtUnixTime::decode_fixed(&*bytes)?;
        let (checked, _) = bytes.checked_split(RANDOM_BYTES)?;
        let random_bytes: [u8; RANDOM_BYTES] = (&*checked).try_into().unwrap();
        Ok(Self {
            gmt_unix_time,
            random_bytes,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Data taken from a pcap

    const TEST_DATA: &[u8] = &[
        // date
        0xf4, 0x2f, 0x67, 0xa3, // Oct 27, 2099 02:23:47.000000000 CET
        // random
        0xf6, 0xfc, 0x51, 0x50, 0x43, 0x7b, 0xd2, 0x81, 0x52, 0xd0, 0x1f, 0xd5, 0x71, 0xc7, 0x25,
        0x97, 0x3a, 0x77, 0xa1, 0x90, 0x41, 0xa0, 0x6c, 0xf0, 0x89, 0x60, 0xb3, 0x46,
    ];

    #[test]
    fn decode_random() {
        let (random, _) = Random::decode_fixed(TEST_DATA).unwrap();
        assert_eq!(
            random,
            Random {
                gmt_unix_time: 4096747427.try_into().unwrap(),
                random_bytes: [
                    0xf6, 0xfc, 0x51, 0x50, 0x43, 0x7b, 0xd2, 0x81, 0x52, 0xd0, 0x1f, 0xd5, 0x71,
                    0xc7, 0x25, 0x97, 0x3a, 0x77, 0xa1, 0x90, 0x41, 0xa0, 0x6c, 0xf0, 0x89, 0x60,
                    0xb3, 0x46
                ],
            }
        )
    }
}
