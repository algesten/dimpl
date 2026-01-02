//! DTLS 1.3 Record Layer (RFC 9147)
//!
//! This module implements the DTLS 1.3 record format which differs significantly
//! from DTLS 1.2:
//!
//! - Unified header format (more compact, 1-5 byte header for encrypted records)
//! - Encrypted sequence numbers in epoch > 0
//! - Different AEAD nonce construction (XOR vs concatenation)
//! - Inner content type (encrypted with payload)
//!
//! # Record Formats
//!
//! ## Plaintext Record (epoch 0)
//! ```text
//!  struct {
//!      ContentType type;
//!      ProtocolVersion legacy_record_version = {254,253}; // DTLS 1.2
//!      uint16 epoch = 0;
//!      uint48 sequence_number;
//!      uint16 length;
//!      opaque fragment[DTLSPlaintext.length];
//!  } DTLSPlaintext;
//! ```
//!
//! ## Ciphertext Record (epoch > 0) - Unified Header
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |0|0|1|C|S|L|E E|  Fixed bits | C=CID | S=SeqNo | L=Length | E=Epoch
//! +-+-+-+-+-+-+-+-+
//! | Connection ID |  if C=1 (we don't use CID for now)
//! | (variable)    |
//! +-+-+-+-+-+-+-+-+
//! | 8 or 16 bit   |  if S=0: 8-bit seq, S=1: 16-bit seq
//! |Sequence Number|
//! +-+-+-+-+-+-+-+-+
//! | 16 bit Length |  if L=1
//! +-+-+-+-+-+-+-+-+
//! |               |
//! ~ Encrypted     ~
//! | Record        |
//! +-+-+-+-+-+-+-+-+
//! ```
//!
//! NOTE: This module is prepared for full DTLS 1.3 record layer integration.
//! Some items are currently unused but will be connected in future work.

use std::fmt;
use std::ops::Range;

use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::{Err, IResult};

#[cfg(test)]
use super::record::{ContentType, Sequence};
#[cfg(test)]
use super::ProtocolVersion;
#[cfg(test)]
use crate::buffer::Buf;

/// DTLS 1.3 unified header flags
pub mod flags {
    /// Fixed header bits (001xxxxx)
    pub const FIXED_BITS: u8 = 0b0010_0000;
    /// Mask for fixed bits
    pub const FIXED_MASK: u8 = 0b1110_0000;
    /// Connection ID present
    pub const CID_BIT: u8 = 0b0001_0000;
    /// Sequence number is 16-bit (vs 8-bit)
    pub const SEQ_16BIT: u8 = 0b0000_1000;
    /// Length field present
    pub const LENGTH_BIT: u8 = 0b0000_0100;
    /// Epoch bits mask (lower 2 bits)
    pub const EPOCH_MASK: u8 = 0b0000_0011;
}

/// DTLS 1.3 plaintext record (used during initial handshake, epoch 0)
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextRecord {
    pub content_type: ContentType,
    pub sequence: Sequence,
    pub length: u16,
    pub fragment_range: Range<usize>,
}

#[cfg(test)]
impl PlaintextRecord {
    /// Parse a DTLS 1.3 plaintext record (epoch 0).
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let original_input = input;
        let (input, content_type) = ContentType::parse(input)?;
        let (input, version) = ProtocolVersion::parse(input)?;

        // DTLS 1.3 uses legacy version 0xFEFD (DTLS 1.2) in record layer
        if version != ProtocolVersion::DTLS1_2 {
            return Err(Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }

        let (input, epoch) = be_u16(input)?;

        // Plaintext records must be epoch 0
        if epoch != 0 {
            return Err(Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }

        let (input, seq_bytes) = take(6usize)(input)?;
        let sequence_number = u64::from_be_bytes([
            0,
            0,
            seq_bytes[0],
            seq_bytes[1],
            seq_bytes[2],
            seq_bytes[3],
            seq_bytes[4],
            seq_bytes[5],
        ]);

        let (input, length) = be_u16(input)?;
        let (rest, fragment) = take(length as usize)(input)?;

        let relative_offset = fragment.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + fragment.len();

        Ok((
            rest,
            PlaintextRecord {
                content_type,
                sequence: Sequence {
                    epoch: 0,
                    sequence_number,
                },
                length,
                fragment_range: start..end,
            },
        ))
    }

    /// Serialize a plaintext record.
    pub fn serialize(&self, fragment: &[u8], output: &mut Buf) {
        output.push(self.content_type.as_u8());
        ProtocolVersion::DTLS1_2.serialize(output);
        output.extend_from_slice(&0u16.to_be_bytes()); // epoch 0
        output.extend_from_slice(&self.sequence.sequence_number.to_be_bytes()[2..]); // 48-bit seq
        output.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        output.extend_from_slice(fragment);
    }
}

/// DTLS 1.3 ciphertext record (unified header format, epoch > 0)
#[derive(Clone, PartialEq, Eq)]
pub struct CiphertextRecord {
    /// Epoch (lower 2 bits, full epoch tracked externally)
    pub epoch_bits: u8,
    /// Sequence number (8 or 16 bits, full 48-bit seq tracked externally)
    pub sequence_bits: u16,
    /// Whether 16-bit sequence was used
    pub seq_16bit: bool,
    /// Length (if present in header)
    pub length: Option<u16>,
    /// Encrypted content range in buffer
    pub encrypted_range: Range<usize>,
}

impl CiphertextRecord {
    /// Parse a DTLS 1.3 ciphertext record (unified header).
    ///
    /// The `remaining_len` is used when the length field is not present.
    pub fn parse(
        input: &[u8],
        base_offset: usize,
        remaining_len: Option<usize>,
    ) -> IResult<&[u8], Self> {
        let original_input = input;
        let (input, header_byte) = be_u8(input)?;

        // Check fixed bits (001xxxxx)
        if (header_byte & flags::FIXED_MASK) != flags::FIXED_BITS {
            return Err(Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }

        // We don't support Connection IDs
        if (header_byte & flags::CID_BIT) != 0 {
            return Err(Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }

        let seq_16bit = (header_byte & flags::SEQ_16BIT) != 0;
        let has_length = (header_byte & flags::LENGTH_BIT) != 0;
        let epoch_bits = header_byte & flags::EPOCH_MASK;

        // Parse sequence number
        let (input, sequence_bits) = if seq_16bit {
            let (i, seq) = be_u16(input)?;
            (i, seq)
        } else {
            let (i, seq) = be_u8(input)?;
            (i, seq as u16)
        };

        // Parse length if present
        let (input, length) = if has_length {
            let (i, len) = be_u16(input)?;
            (i, Some(len))
        } else {
            (input, None)
        };

        // Determine encrypted content length
        let content_len = match length {
            Some(len) => len as usize,
            None => remaining_len.ok_or_else(|| {
                Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Eof))
            })?,
        };

        let (rest, encrypted) = take(content_len)(input)?;

        let relative_offset = encrypted.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + encrypted.len();

        Ok((
            rest,
            CiphertextRecord {
                epoch_bits,
                sequence_bits,
                seq_16bit,
                length,
                encrypted_range: start..end,
            },
        ))
    }

    /// Serialize a ciphertext record with unified header.
    ///
    /// - Uses 16-bit sequence if `seq_16bit` is true
    /// - Always includes length field for simplicity
    #[cfg(test)]
    pub fn serialize(epoch_bits: u8, sequence_number: u64, encrypted: &[u8], output: &mut Buf) {
        // Determine if we need 16-bit sequence
        let seq_low = (sequence_number & 0xFFFF) as u16;
        let seq_16bit = seq_low > 255;

        let mut header = flags::FIXED_BITS;
        if seq_16bit {
            header |= flags::SEQ_16BIT;
        }
        header |= flags::LENGTH_BIT; // Always include length for simplicity
        header |= epoch_bits & flags::EPOCH_MASK;

        output.push(header);

        if seq_16bit {
            output.extend_from_slice(&seq_low.to_be_bytes());
        } else {
            output.push(seq_low as u8);
        }

        output.extend_from_slice(&(encrypted.len() as u16).to_be_bytes());
        output.extend_from_slice(encrypted);
    }

    /// Compute the header length for this record.
    pub fn header_len(&self) -> usize {
        let mut len = 1; // header byte
        len += if self.seq_16bit { 2 } else { 1 };
        if self.length.is_some() {
            len += 2;
        }
        len
    }
}

impl fmt::Debug for CiphertextRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CiphertextRecord")
            .field("epoch_bits", &self.epoch_bits)
            .field("sequence_bits", &self.sequence_bits)
            .field("seq_16bit", &self.seq_16bit)
            .field("length", &self.length)
            .field("encrypted_range", &self.encrypted_range)
            .finish()
    }
}

/// DTLS 1.3 AEAD nonce construction.
///
/// Unlike DTLS 1.2 (which concatenates fixed IV + explicit nonce),
/// DTLS 1.3 XORs the 64-bit sequence number with the 12-byte IV.
///
/// ```text
/// nonce = iv XOR (0 || sequence_number)
/// ```
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dtls13Nonce(pub [u8; 12]);

#[cfg(test)]
impl Dtls13Nonce {
    /// Create a DTLS 1.3 nonce by XORing the sequence number with the IV.
    pub fn new(iv: &[u8; 12], sequence_number: u64) -> Self {
        let mut nonce = *iv;
        // XOR the sequence number into the rightmost 8 bytes
        let seq_bytes = sequence_number.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        Dtls13Nonce(nonce)
    }
}

/// DTLS 1.3 inner plaintext structure.
///
/// The actual content type is encrypted as the last byte of the plaintext.
/// ```text
/// struct {
///     opaque content[length];
///     ContentType type;
///     uint8 zeros[padding_length];
/// } DTLSInnerPlaintext;
/// ```
#[cfg(test)]
pub struct Dtls13InnerPlaintext;

#[cfg(test)]
impl Dtls13InnerPlaintext {
    /// Add inner content type to plaintext (before encryption).
    /// Returns the plaintext with content type appended.
    pub fn encode(plaintext: &[u8], content_type: ContentType, output: &mut Buf) {
        output.extend_from_slice(plaintext);
        output.push(content_type.as_u8());
        // No padding for now (could add zeros for traffic analysis protection)
    }

    /// Decode inner plaintext (after decryption).
    /// Removes trailing zeros and extracts the content type.
    pub fn decode(inner: &[u8]) -> Option<(ContentType, &[u8])> {
        if inner.is_empty() {
            return None;
        }

        // Find the content type (last non-zero byte)
        let mut idx = inner.len() - 1;
        while idx > 0 && inner[idx] == 0 {
            idx -= 1;
        }

        let content_type = ContentType::from_u8(inner[idx]);
        let content = &inner[..idx];
        Some((content_type, content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls13_nonce() {
        let iv = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let seq = 0x0000000000000001u64;

        let nonce = Dtls13Nonce::new(&iv, seq);

        // XOR should affect only the last 8 bytes
        assert_eq!(nonce.0[0..4], iv[0..4]);
        // Last byte should be XORed with 0x01
        assert_eq!(nonce.0[11], iv[11] ^ 0x01);
    }

    #[test]
    fn test_inner_plaintext_roundtrip() {
        let content = b"Hello, DTLS 1.3!";
        let content_type = ContentType::ApplicationData;

        let mut encoded = Buf::new();
        Dtls13InnerPlaintext::encode(content, content_type, &mut encoded);

        assert_eq!(encoded.len(), content.len() + 1);
        assert_eq!(
            encoded[encoded.len() - 1],
            ContentType::ApplicationData.as_u8()
        );

        let (decoded_type, decoded_content) = Dtls13InnerPlaintext::decode(&encoded).unwrap();
        assert_eq!(decoded_type, ContentType::ApplicationData);
        assert_eq!(decoded_content, content);
    }

    #[test]
    fn test_ciphertext_header_serialize() {
        let mut output = Buf::new();
        CiphertextRecord::serialize(1, 42, &[0xde, 0xad, 0xbe, 0xef], &mut output);

        // Header: 0b00100101 = 0x25 (fixed bits | length bit | epoch 1)
        // Seq: 42 (1 byte since < 256)
        // Length: 4 (2 bytes)
        // Data: 4 bytes
        assert_eq!(output[0] & flags::FIXED_MASK, flags::FIXED_BITS);
        assert_eq!(output[0] & flags::EPOCH_MASK, 1);
        assert!((output[0] & flags::LENGTH_BIT) != 0);
        assert_eq!(output[1], 42); // sequence
        assert_eq!(&output[2..4], &[0x00, 0x04]); // length
        assert_eq!(&output[4..], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_ciphertext_header_parse() {
        // Construct: fixed bits | length | epoch 2, seq=100, len=5, data
        let data = [
            0b0010_0110, // header: fixed | length | epoch 2
            100,         // 8-bit sequence
            0x00,
            0x05, // length = 5
            0x01,
            0x02,
            0x03,
            0x04,
            0x05, // encrypted data
        ];

        let (rest, record) = CiphertextRecord::parse(&data, 0, None).unwrap();
        assert!(rest.is_empty());
        assert_eq!(record.epoch_bits, 2);
        assert_eq!(record.sequence_bits, 100);
        assert!(!record.seq_16bit);
        assert_eq!(record.length, Some(5));
        assert_eq!(record.encrypted_range, 4..9);
    }

    #[test]
    fn test_plaintext_record_roundtrip() {
        let mut output = Buf::new();
        let record = PlaintextRecord {
            content_type: ContentType::Handshake,
            sequence: Sequence {
                epoch: 0,
                sequence_number: 1,
            },
            length: 4,
            fragment_range: 0..4,
        };

        let fragment = [0x01, 0x02, 0x03, 0x04];
        record.serialize(&fragment, &mut output);

        // Parse it back
        let (rest, parsed) = PlaintextRecord::parse(&output, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.content_type, ContentType::Handshake);
        assert_eq!(parsed.sequence.epoch, 0);
        assert_eq!(parsed.sequence.sequence_number, 1);
        assert_eq!(parsed.length, 4);
    }
}
