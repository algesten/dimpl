use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::{IResult, bytes::complete::take, number::complete::be_u8};

/// Connection ID extension as defined in RFC 9146.
///
/// The CID value is what the sender wants the peer to include in
/// encrypted records sent back. An empty CID is valid — it means
/// "negotiate CID but don't include one in records sent to me."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionIdExtension {
    pub cid: ArrayVec<u8, 255>,
}

impl ConnectionIdExtension {
    pub fn new(cid: &[u8]) -> Self {
        let mut arr = ArrayVec::new();
        // unwrap: cid.len() <= 255 enforced by config validation
        arr.try_extend_from_slice(cid).unwrap();
        ConnectionIdExtension { cid: arr }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ConnectionIdExtension> {
        let (input, cid_len) = be_u8(input)?;
        let (input, cid_bytes) = take(cid_len as usize)(input)?;
        let mut cid = ArrayVec::new();
        // unwrap: cid_len <= 255, ArrayVec capacity is 255
        cid.try_extend_from_slice(cid_bytes).unwrap();
        // RFC 9146 §3 defines the extension body as exactly a `ConnectionId`
        // structure. Trailing bytes are a malformed extension — per RFC 5246
        // §7.2.2 / RFC 8446 §6 that's a decode_error. Fail strictly instead
        // of silently accepting, matching every other extension parser.
        if !input.is_empty() {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }
        Ok((input, ConnectionIdExtension { cid }))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.push(self.cid.len() as u8);
        output.extend_from_slice(&self.cid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn roundtrip() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let ext = ConnectionIdExtension::new(&cid);

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        assert_eq!(
            &*serialized,
            &[0x04, 0x01, 0x02, 0x03, 0x04] // length(1) + cid(4)
        );

        let (rest, parsed) = ConnectionIdExtension::parse(&serialized).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, ext);
    }

    #[test]
    fn empty_cid() {
        let ext = ConnectionIdExtension::new(&[]);

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        assert_eq!(&*serialized, &[0x00]); // length(1) only

        let (rest, parsed) = ConnectionIdExtension::parse(&serialized).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, ext);
    }

    /// RFC 9146 §3 defines the extension body as exactly a `ConnectionId`
    /// structure. Trailing bytes must be rejected (RFC 5246 §7.2.2 decode_error).
    #[test]
    fn rejects_trailing_bytes() {
        // length(1) + cid(2) + trailing(1)
        let malformed = [0x02, 0xAA, 0xBB, 0xCC];
        assert!(ConnectionIdExtension::parse(&malformed).is_err());

        // Also check zero-length CID with trailing bytes.
        let malformed_zero = [0x00, 0xDE];
        assert!(ConnectionIdExtension::parse(&malformed_zero).is_err());
    }
}
