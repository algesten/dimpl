//! KeyShare extension (RFC 8446 Section 4.2.8)
//!
//! The key_share extension contains the client's or server's DH public value
//! for key exchange. In TLS/DTLS 1.3, this replaces the ServerKeyExchange and
//! ClientKeyExchange messages from TLS 1.2.
//!
//! NOTE: This module is prepared for DTLS 1.3 but not yet fully integrated
//! into the main extension parsing paths.

use crate::message::NamedGroup;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use std::ops::Range;

/// Maximum number of key shares in a ClientHello.
const MAX_KEY_SHARES: usize = 4;

/// A single key share entry: named group + public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// The named group (e.g., X25519, secp256r1).
    pub group: NamedGroup,
    /// Range into the source buffer containing the public key bytes.
    pub key_exchange_range: Range<usize>,
}

impl KeyShareEntry {
    /// Get the key exchange bytes from a buffer.
    pub fn key_exchange<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.key_exchange_range.clone()]
    }

    /// Parse a single KeyShareEntry.
    fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let original_input = input;
        let (input, group) = NamedGroup::parse(input)?;
        let (input, key_len) = be_u16(input)?;
        let (input, _key_bytes) = take(key_len)(input)?;

        // Calculate range for key bytes
        let key_offset = base_offset + (input.as_ptr() as usize - original_input.as_ptr() as usize)
            - key_len as usize;
        let key_range = key_offset..(key_offset + key_len as usize);

        Ok((
            input,
            Self {
                group,
                key_exchange_range: key_range,
            },
        ))
    }
}

/// KeyShare extension for ClientHello.
///
/// Contains a list of key share entries, one per supported group.
/// The client typically sends one or more entries for the groups it prefers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareClientHello {
    pub entries: ArrayVec<KeyShareEntry, MAX_KEY_SHARES>,
}

impl KeyShareClientHello {
    /// Parse the extension data from a ClientHello.
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let (mut input, list_len) = be_u16(input)?;
        let mut entries = ArrayVec::new();
        let mut remaining = list_len as usize;

        // Calculate offset for entries (after the 2-byte length)
        let entries_base = base_offset + 2;
        let mut entry_offset = entries_base;

        while remaining >= 4 {
            // minimum: 2 bytes group + 2 bytes key length
            let entry_start = input;
            let (rest, entry) = KeyShareEntry::parse(input, entry_offset)?;
            let consumed = entry_start.len() - rest.len();
            entry_offset += consumed;
            remaining -= consumed;
            input = rest;

            // Only add entries for known groups
            if !matches!(entry.group, NamedGroup::Unknown(_)) {
                let _ = entries.try_push(entry);
            }
        }

        Ok((input, Self { entries }))
    }
}

/// KeyShare extension for ServerHello.
///
/// Contains a single key share entry for the group selected by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareServerHello {
    pub entry: KeyShareEntry,
}

impl KeyShareServerHello {
    /// Parse the extension data from a ServerHello.
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let (input, entry) = KeyShareEntry::parse(input, base_offset)?;
        Ok((input, Self { entry }))
    }
}

/// KeyShare extension for HelloRetryRequest.
///
/// Contains only the selected group (no key material), telling the client
/// which group to use in its retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyShareHelloRetryRequest {
    pub selected_group: NamedGroup,
}

impl KeyShareHelloRetryRequest {
    /// Parse the extension data from a HelloRetryRequest.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, selected_group) = NamedGroup::parse(input)?;
        Ok((input, Self { selected_group }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn test_key_share_hrr_roundtrip() {
        // Serialize: group as 2 bytes
        let buf: [u8; 2] = [0x00, 0x1D]; // X25519 = 0x001D

        let (rest, parsed) = KeyShareHelloRetryRequest::parse(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.selected_group, NamedGroup::X25519);
    }

    #[test]
    fn test_key_share_server_hello_roundtrip() {
        // Create a buffer with key material in wire format
        // group (2) + key_len (2) + key_bytes (8)
        let key_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut wire_buf = Buf::new();
        wire_buf.extend_from_slice(&[0x00, 0x1D]); // X25519
        wire_buf.extend_from_slice(&[0x00, 0x08]); // key length
        wire_buf.extend_from_slice(&key_bytes);

        let (rest, parsed) = KeyShareServerHello::parse(&wire_buf, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.entry.group, NamedGroup::X25519);
        assert_eq!(parsed.entry.key_exchange(&wire_buf), &key_bytes);
    }

    #[test]
    fn test_key_share_client_hello_roundtrip() {
        // Create wire format with two key shares
        let x25519_key = [0xAAu8; 32]; // X25519 public key is 32 bytes
        let p256_key = [0xBBu8; 65]; // P-256 uncompressed point is 65 bytes

        let mut wire_buf = Buf::new();
        // List length: (2+2+32) + (2+2+65) = 36 + 69 = 105
        wire_buf.extend_from_slice(&[0x00, 105]);
        // X25519 entry
        wire_buf.extend_from_slice(&[0x00, 0x1D]); // X25519
        wire_buf.extend_from_slice(&[0x00, 32]); // key length
        wire_buf.extend_from_slice(&x25519_key);
        // P-256 entry
        wire_buf.extend_from_slice(&[0x00, 0x17]); // secp256r1
        wire_buf.extend_from_slice(&[0x00, 65]); // key length
        wire_buf.extend_from_slice(&p256_key);

        // Note: base_offset must match where the extension data starts
        // The key_exchange ranges will be relative to the start of wire_buf
        let (rest, parsed) = KeyShareClientHello::parse(&wire_buf, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].group, NamedGroup::X25519);
        assert_eq!(parsed.entries[1].group, NamedGroup::Secp256r1);
        // Verify key_exchange ranges point to correct data
        // First key at offset 6 (2 list len + 2 group + 2 key len), length 32
        assert_eq!(parsed.entries[0].key_exchange(&wire_buf), &x25519_key);
        // Second key at offset 6+32+4 = 42, length 65
        assert_eq!(parsed.entries[1].key_exchange(&wire_buf), &p256_key);
    }
}
