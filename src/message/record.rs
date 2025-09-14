use core::fmt;
use std::cmp::Ordering;
use std::ops::Range;

use super::ProtocolVersion;
use crate::buffer::Buf;
use crate::util::be_u48;
use crate::Error;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::{Err, IResult};

pub struct DTLSRecordSlice<'a> {
    pub slice: &'a mut [u8],
    pub rest: &'a mut [u8],
}

impl<'a> DTLSRecordSlice<'a> {
    pub fn try_read(input: &'a mut [u8]) -> Result<Option<DTLSRecordSlice<'a>>, Error> {
        if input.is_empty() {
            return Ok(None);
        }

        if input.len() < DTLSRecord::HEADER_LEN {
            return Err(Error::ParseIncomplete);
        }

        let length_bytes = input[DTLSRecord::LENGTH_OFFSET].try_into().unwrap();
        let length = u16::from_be_bytes(length_bytes) as usize;
        let mid = DTLSRecord::HEADER_LEN + length;

        if input.len() < mid {
            return Err(Error::ParseIncomplete);
        }

        let (slice, rest) = input.split_at_mut(mid);

        Ok(Some(DTLSRecordSlice { slice, rest }))
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct DTLSRecord<'a> {
    pub content_type: ContentType,
    pub version: ProtocolVersion,
    pub sequence: Sequence,
    pub length: u16,
    pub fragment: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sequence {
    pub epoch: u16,
    pub sequence_number: u64, // technically u48
}

impl<'a> DTLSRecord<'a> {
    /// DTLS record header length: content_type(1) + version(2) + epoch(2) + seq(6) + length(2)
    pub const HEADER_LEN: usize = 13;

    /// Length of the explicit nonce prefix in AEAD ciphers (e.g., AES-GCM)
    pub const EXPLICIT_NONCE_LEN: usize = 8;

    /// Byte offset in the record header where the 2-byte length field is
    pub const LENGTH_OFFSET: Range<usize> = 11..13;

    pub fn parse(input: &'a [u8]) -> IResult<&[u8], DTLSRecord<'a>> {
        let (input, content_type) = ContentType::parse(input)?; // u8
        let (input, version) = ProtocolVersion::parse(input)?; // u16
        let (input, epoch) = be_u16(input)?; // u16
        let (input, sequence_number) = be_u48(input)?; // u48
        let (input, length) = be_u16(input)?; // u16
        let (rest, fragment) = take(length as usize)(input)?;

        let sequence = Sequence {
            epoch,
            sequence_number,
        };

        Ok((
            rest,
            DTLSRecord {
                content_type,
                version,
                sequence,
                length,
                fragment,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        output.push(self.content_type.as_u8());
        self.version.serialize(output);
        output.extend_from_slice(&self.sequence.epoch.to_be_bytes());
        output.extend_from_slice(&self.sequence.sequence_number.to_be_bytes()[2..]);
        output.extend_from_slice(&self.length.to_be_bytes());
        output.extend_from_slice(self.fragment);
    }

    pub fn nonce(&self) -> &[u8] {
        &self.fragment[..Self::EXPLICIT_NONCE_LEN]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

impl Default for ContentType {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl ContentType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Unknown(value),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert => 21,
            ContentType::Handshake => 22,
            ContentType::ApplicationData => 23,
            ContentType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ContentType> {
        let (input, byte) = be_u8(input)?;
        Ok((input, Self::from_u8(byte)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;
    use crate::message::ProtocolVersion;

    const RECORD: &[u8] = &[
        0x16, // ContentType::Handshake
        0xFE, 0xFD, // ProtocolVersion::DTLS1_2
        0x00, 0x01, // epoch
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence_number
        0x00, 0x10, // length
        // fragment
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    #[test]
    fn roundtrip() {
        let mut record: Vec<u8> = RECORD.to_vec();

        let record = DTLSRecord {
            content_type: ContentType::Handshake,
            version: ProtocolVersion::DTLS1_2,
            sequence: Sequence {
                epoch: 1,
                sequence_number: 1,
            },
            length: 16,
            fragment: &mut record[DTLSRecord::HEADER_LEN..],
        };

        // Serialize and compare to RECORD
        let mut serialized = Buf::new();
        record.serialize(&mut serialized);
        assert_eq!(&*serialized, RECORD);

        // Parse and compare with original
        let (rest, parsed) = DTLSRecord::parse(&mut serialized).unwrap();
        assert_eq!(parsed, record);

        assert!(rest.is_empty());
    }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[epoch: {}, sequence_number: {}]",
            self.epoch, self.sequence_number,
        )
    }
}

impl Ord for Sequence {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.epoch < other.epoch {
            Ordering::Less
        } else if self.epoch > other.epoch {
            Ordering::Greater
        } else {
            self.sequence_number.cmp(&other.sequence_number)
        }
    }
}

impl PartialOrd for Sequence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
