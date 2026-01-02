//! DTLS 1.3 ACK message (RFC 9147 Section 7)
//!
//! The ACK message is used to acknowledge received records, enabling
//! selective retransmission and confirming KeyUpdate transitions.
//!
//! Format:
//! ```text
//! struct {
//!     RecordNumber record_numbers<0..2^16-1>;
//! } ACK;
//!
//! struct {
//!     uint64 epoch;
//!     uint64 sequence_number;
//! } RecordNumber;
//! ```

use crate::buffer::Buf;
use nom::number::complete::{be_u16, be_u64};
use nom::IResult;

/// A record number identifying a specific DTLS record by epoch and sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordNumber {
    pub epoch: u64,
    pub sequence_number: u64,
}

impl RecordNumber {
    pub const WIRE_SIZE: usize = 16; // 8 bytes epoch + 8 bytes sequence

    pub fn new(epoch: u64, sequence_number: u64) -> Self {
        Self {
            epoch,
            sequence_number,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, epoch) = be_u64(input)?;
        let (input, sequence_number) = be_u64(input)?;
        Ok((
            input,
            Self {
                epoch,
                sequence_number,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.epoch.to_be_bytes());
        output.extend_from_slice(&self.sequence_number.to_be_bytes());
    }
}

/// DTLS 1.3 ACK message.
#[derive(Debug, Clone, Default)]
pub struct AckMessage {
    pub record_numbers: Vec<RecordNumber>,
}

impl AckMessage {
    pub fn new() -> Self {
        Self {
            record_numbers: Vec::new(),
        }
    }

    /// Create an ACK for a single record.
    #[allow(dead_code)]
    pub fn for_record(epoch: u64, sequence_number: u64) -> Self {
        Self {
            record_numbers: vec![RecordNumber::new(epoch, sequence_number)],
        }
    }

    /// Add a record number to acknowledge.
    pub fn add(&mut self, epoch: u64, sequence_number: u64) {
        self.record_numbers
            .push(RecordNumber::new(epoch, sequence_number));
    }

    /// Parse an ACK message from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        // Length prefix: 2 bytes
        let (input, len) = be_u16(input)?;
        let len = len as usize;

        // Validate length is multiple of RecordNumber size
        if len % RecordNumber::WIRE_SIZE != 0 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }

        let count = len / RecordNumber::WIRE_SIZE;
        let mut record_numbers = Vec::with_capacity(count);
        let mut remaining = input;

        for _ in 0..count {
            let (rest, rn) = RecordNumber::parse(remaining)?;
            record_numbers.push(rn);
            remaining = rest;
        }

        Ok((remaining, Self { record_numbers }))
    }

    /// Serialize the ACK message to wire format.
    pub fn serialize(&self, output: &mut Buf) {
        // Length prefix
        let len = (self.record_numbers.len() * RecordNumber::WIRE_SIZE) as u16;
        output.extend_from_slice(&len.to_be_bytes());

        // Record numbers
        for rn in &self.record_numbers {
            rn.serialize(output);
        }
    }

    /// Check if this ACK acknowledges a specific record.
    pub fn acknowledges(&self, epoch: u64, sequence_number: u64) -> bool {
        self.record_numbers
            .iter()
            .any(|rn| rn.epoch == epoch && rn.sequence_number == sequence_number)
    }

    /// Check if this ACK is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.record_numbers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_number_roundtrip() {
        let rn = RecordNumber::new(3, 42);
        let mut buf = Buf::new();
        rn.serialize(&mut buf);

        assert_eq!(buf.len(), 16);

        let (rest, parsed) = RecordNumber::parse(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, rn);
    }

    #[test]
    fn test_ack_message_roundtrip() {
        let mut ack = AckMessage::new();
        ack.add(3, 10);
        ack.add(3, 15);
        ack.add(4, 0);

        let mut buf = Buf::new();
        ack.serialize(&mut buf);

        // Length (2) + 3 * RecordNumber (16 each) = 50 bytes
        assert_eq!(buf.len(), 2 + 3 * 16);

        let (rest, parsed) = AckMessage::parse(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.record_numbers.len(), 3);
        assert!(parsed.acknowledges(3, 10));
        assert!(parsed.acknowledges(3, 15));
        assert!(parsed.acknowledges(4, 0));
        assert!(!parsed.acknowledges(3, 11));
    }

    #[test]
    fn test_ack_for_record() {
        let ack = AckMessage::for_record(3, 100);
        assert_eq!(ack.record_numbers.len(), 1);
        assert!(ack.acknowledges(3, 100));
    }
}
