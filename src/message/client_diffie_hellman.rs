// Per RFC 5246 7.4.7.1, ClientDiffieHellmanPublic carries dh_Yc as an opaque
// vector when explicit encoding is used. The implicit/explicit choice is
// only relevant for fixed_dh client certificates; for ephemeral DH (DHE), the
// client sends dh_Yc as an opaque vector without a leading encoding byte.
// We therefore do NOT encode a PublicValueEncoding field here.
use crate::buffer::Buf;
use nom::number::complete::be_u16;
use nom::{
    bytes::complete::take,
    error::{Error, ErrorKind},
    Err, IResult,
};

#[derive(Debug, PartialEq, Eq)]
pub struct ClientDiffieHellmanPublic<'a> {
    pub public_value: &'a [u8],
}

impl<'a> ClientDiffieHellmanPublic<'a> {
    pub fn new(public_value: &'a [u8]) -> Self {
        ClientDiffieHellmanPublic { public_value }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ClientDiffieHellmanPublic<'a>> {
        let (input, public_value_len) = be_u16(input)?;
        if public_value_len == 0 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, public_value) = take(public_value_len)(input)?;

        Ok((input, ClientDiffieHellmanPublic { public_value }))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&(self.public_value.len() as u16).to_be_bytes());
        output.extend_from_slice(self.public_value);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0x00, 0x04, // Public value length
        0x01, 0x02, 0x03, 0x04, // Public value data
    ];

    #[test]
    fn roundtrip() {
        let public_value = &MESSAGE[2..6];

        let client_diffie_hellman_public = ClientDiffieHellmanPublic::new(public_value);

        // Serialize and compare to MESSAGE
        let mut serialized = Buf::new();
        client_diffie_hellman_public.serialize(&mut serialized);
        assert_eq!(&*serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = ClientDiffieHellmanPublic::parse(&serialized).unwrap();
        assert_eq!(parsed, client_diffie_hellman_public);

        assert!(rest.is_empty());
    }

    #[test]
    fn zero_length_is_rejected() {
        // length=0, no value => invalid for explicit DHE (must be 1..2^16-1)
        let message: &[u8] = &[0x00, 0x00];

        let result = ClientDiffieHellmanPublic::parse(message);
        assert!(result.is_err(), "zero-length dh_Yc must be rejected");
    }

    #[test]
    fn parse_and_serialize_roundtrip() {
        // length=4, value bytes follow
        let message: &[u8] = &[0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];

        let (rest, parsed) = ClientDiffieHellmanPublic::parse(message).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.public_value, &message[2..]);

        let mut out = Buf::new();
        parsed.serialize(&mut out);
        assert_eq!(&*out, message);
    }
}
