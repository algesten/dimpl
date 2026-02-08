use crate::buffer::Buf;
use crate::types::NamedGroup;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use std::ops::Range;

/// A single KeyShareEntry (RFC 8446 Section 4.2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange_range: Range<usize>,
}

impl KeyShareEntry {
    pub fn key_exchange<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.key_exchange_range.clone()]
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], KeyShareEntry> {
        let original_input = input;
        let (input, group) = NamedGroup::parse(input)?;
        let (input, ke_len) = be_u16(input)?;
        let (input, ke_slice) = take(ke_len)(input)?;

        let relative_offset = ke_slice.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + ke_slice.len();

        Ok((
            input,
            KeyShareEntry {
                group,
                key_exchange_range: start..end,
            },
        ))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        output.extend_from_slice(&self.group.as_u16().to_be_bytes());
        let ke = self.key_exchange(buf);
        output.extend_from_slice(&(ke.len() as u16).to_be_bytes());
        output.extend_from_slice(ke);
    }
}

/// KeyShare extension in ClientHello (RFC 8446 Section 4.2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareClientHello {
    pub entries: ArrayVec<KeyShareEntry, 2>,
}

impl KeyShareClientHello {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], KeyShareClientHello> {
        let original_input = input;
        let (input, list_len) = be_u16(input)?;
        let (input, entries_data) = take(list_len)(input)?;

        let entries_base_offset =
            base_offset + (entries_data.as_ptr() as usize - original_input.as_ptr() as usize);

        let mut entries = ArrayVec::new();
        let mut rest = entries_data;
        while !rest.is_empty() {
            let entry_offset =
                entries_base_offset + (rest.as_ptr() as usize - entries_data.as_ptr() as usize);
            let (r, entry) = KeyShareEntry::parse(rest, entry_offset)?;
            if entry.group.is_supported() {
                entries.push(entry);
            }
            rest = r;
        }

        Ok((input, KeyShareClientHello { entries }))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        // Calculate total length of entries
        let total_len: usize = self
            .entries
            .iter()
            .map(|e| 2 + 2 + e.key_exchange(buf).len())
            .sum();
        output.extend_from_slice(&(total_len as u16).to_be_bytes());

        for entry in &self.entries {
            entry.serialize(buf, output);
        }
    }
}

/// KeyShare extension in ServerHello (RFC 8446 Section 4.2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareServerHello {
    pub entry: KeyShareEntry,
}

impl KeyShareServerHello {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], KeyShareServerHello> {
        let (input, entry) = KeyShareEntry::parse(input, base_offset)?;
        Ok((input, KeyShareServerHello { entry }))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        self.entry.serialize(buf, output);
    }
}

/// KeyShare extension in HelloRetryRequest (RFC 8446 Section 4.2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareHelloRetryRequest {
    pub selected_group: NamedGroup,
}

impl KeyShareHelloRetryRequest {
    pub fn parse(input: &[u8]) -> IResult<&[u8], KeyShareHelloRetryRequest> {
        let (input, selected_group) = NamedGroup::parse(input)?;
        Ok((input, KeyShareHelloRetryRequest { selected_group }))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.selected_group.as_u16().to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn key_share_client_hello_roundtrip() {
        let message: &[u8] = &[
            0x00, 0x08, // client_shares length (8)
            0x00, 0x1D, // NamedGroup::X25519
            0x00, 0x04, // key_exchange length
            0x01, 0x02, 0x03, 0x04, // key_exchange data
        ];

        let (rest, parsed) = KeyShareClientHello::parse(message, 0).unwrap();
        assert!(rest.is_empty());

        let mut serialized = Buf::new();
        parsed.serialize(message, &mut serialized);
        assert_eq!(&*serialized, message);
    }

    #[test]
    fn key_share_server_hello_roundtrip() {
        let message: &[u8] = &[
            0x00, 0x1D, // NamedGroup::X25519
            0x00, 0x04, // key_exchange length
            0x01, 0x02, 0x03, 0x04, // key_exchange data
        ];

        let (rest, parsed) = KeyShareServerHello::parse(message, 0).unwrap();
        assert!(rest.is_empty());

        let mut serialized = Buf::new();
        parsed.serialize(message, &mut serialized);
        assert_eq!(&*serialized, message);
    }

    #[test]
    fn key_share_hrr_roundtrip() {
        let message: &[u8] = &[
            0x00, 0x17, // NamedGroup::Secp256r1
        ];

        let (rest, parsed) = KeyShareHelloRetryRequest::parse(message).unwrap();
        assert!(rest.is_empty());

        let mut serialized = Buf::new();
        parsed.serialize(&mut serialized);
        assert_eq!(&*serialized, message);
    }
}
