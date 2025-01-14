use super::util::be_u48;
use super::ProtocolVersion;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

#[derive(Debug, PartialEq, Eq)]
pub struct DTLSRecord<'a> {
    pub content_type: ContentType,
    pub version: ProtocolVersion,
    pub epoch: u16,
    pub sequence_number: u64,
    pub length: u16,
    pub fragment: &'a [u8],
}

impl<'a> DTLSRecord<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], DTLSRecord<'a>> {
        let (input, content_type) = ContentType::parse(input)?;
        let (input, version) = ProtocolVersion::parse(input)?;
        let (input, epoch) = be_u16(input)?;
        let (input, sequence_number) = be_u48(input)?;
        let (input, length) = be_u16(input)?;
        let (input, fragment) = take(length as usize)(input)?;

        Ok((
            input,
            DTLSRecord {
                content_type,
                version,
                epoch,
                sequence_number,
                length,
                fragment,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.push(self.content_type.as_u8());
        self.version.serialize(output);
        output.extend_from_slice(&self.epoch.to_be_bytes());
        output.extend_from_slice(&self.sequence_number.to_be_bytes()[2..]);
        output.extend_from_slice(&self.length.to_be_bytes());
        output.extend_from_slice(self.fragment);
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
        let record = DTLSRecord {
            content_type: ContentType::Handshake,
            version: ProtocolVersion::DTLS1_2,
            epoch: 1,
            sequence_number: 1,
            length: 16,
            fragment: &RECORD[13..],
        };

        // Serialize and compare to RECORD
        let mut serialized = Vec::new();
        record.serialize(&mut serialized);
        assert_eq!(serialized, RECORD);

        // Parse and compare with original
        let (rest, parsed) = DTLSRecord::parse(&serialized).unwrap();
        assert_eq!(parsed, record);

        assert!(rest.is_empty());
    }
}
