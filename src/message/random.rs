use std::array::from_fn;
use std::ops::Deref;
use std::time::Instant;

use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use nom::IResult;
use rand::Rng;

use crate::time_tricks::InstantExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Random {
    pub gmt_unix_time: u32,
    pub random_bytes: [u8; 28],
}

impl Random {
    pub fn new(now: Instant) -> Self {
        let gmt_duration = now.to_unix_duration();
        // This is valid until yaer 2106, at which point I will be beyond caring.
        let gmt_unix_time = gmt_duration.as_secs() as u32;

        let mut t = rand::thread_rng();

        Self {
            gmt_unix_time,
            random_bytes: from_fn(|_| t.gen()),
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Random> {
        let (input, gmt_unix_time) = be_u32(input)?;
        let (input, input_rand) = take(28_usize)(input)?;
        let mut random_bytes = [0u8; 28];
        random_bytes.copy_from_slice(input_rand);

        Ok((
            input,
            Random {
                gmt_unix_time,
                random_bytes,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.gmt_unix_time.to_be_bytes());
        output.extend_from_slice(&self.random_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_parse() {
        let data = [
            0x5F, 0x37, 0xA9, 0x4B, // gmt_unix_time
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E,
        ];

        let expected = Random {
            gmt_unix_time: 0x5F37A94B,
            random_bytes: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            ],
        };

        let (_, parsed) = Random::parse(&data).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn random_serialize() {
        let random = Random {
            gmt_unix_time: 0x5F37A94B,
            random_bytes: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            ],
        };

        let mut serialized = Vec::new();
        random.serialize(&mut serialized);

        let expected = [
            0x5F, 0x37, 0xA9, 0x4B, // gmt_unix_time
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        ];

        assert_eq!(serialized, expected);
    }
}
