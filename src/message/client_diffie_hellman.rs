use crate::message::PublicValueEncoding;
use nom::number::complete::{be_u16, be_u8};
use nom::{
    bytes::complete::take,
    error::{Error, ErrorKind},
    Err, IResult,
};

#[derive(Debug, PartialEq, Eq)]
pub struct ClientDiffieHellmanPublic<'a> {
    pub encoding: PublicValueEncoding,
    pub public_value: &'a [u8],
}

impl<'a> ClientDiffieHellmanPublic<'a> {
    pub fn new(encoding: PublicValueEncoding, public_value: &'a [u8]) -> Self {
        ClientDiffieHellmanPublic {
            encoding,
            public_value,
        }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ClientDiffieHellmanPublic<'a>> {
        let (input, encoding) = PublicValueEncoding::parse(input)?;
        let (input, public_value_len) = be_u16(input)?;
        let (input, public_value) = take(public_value_len)(input)?;

        let is_valid = match encoding {
            PublicValueEncoding::Implicit => public_value.is_empty(),
            PublicValueEncoding::Explicit => !public_value.is_empty(),
            PublicValueEncoding::Unknown(_) => false,
        };

        if !is_valid {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }

        Ok((
            input,
            ClientDiffieHellmanPublic {
                encoding,
                public_value,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.push(self.encoding.to_u8());
        output.extend_from_slice(&(self.public_value.len() as u16).to_be_bytes());
        output.extend_from_slice(self.public_value);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const MESSAGE: &[u8] = &[
        0x01, // PublicValueEncoding::Explicit
        0x00, 0x04, // Public value length
        0x01, 0x02, 0x03, 0x04, // Public value data
    ];

    #[test]
    fn roundtrip() {
        let encoding = PublicValueEncoding::Explicit;
        let public_value = &MESSAGE[3..7];

        let client_diffie_hellman_public = ClientDiffieHellmanPublic::new(encoding, public_value);

        // Serialize and compare to MESSAGE
        let mut serialized = Vec::new();
        client_diffie_hellman_public.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = ClientDiffieHellmanPublic::parse(&serialized).unwrap();
        assert_eq!(parsed, client_diffie_hellman_public);

        assert!(rest.is_empty());
    }

    #[test]
    fn implicit_encoding_with_empty_value() {
        let message: &[u8] = &[
            0x00, // PublicValueEncoding::Implicit
            0x00, 0x00, // Public value length
        ];

        let encoding = PublicValueEncoding::Implicit;
        let public_value = &message[3..3];

        let client_diffie_hellman_public = ClientDiffieHellmanPublic::new(encoding, public_value);

        // Serialize and compare to message
        let mut serialized = Vec::new();
        client_diffie_hellman_public.serialize(&mut serialized);
        assert_eq!(serialized, message);

        // Parse and compare with original
        let (rest, parsed) = ClientDiffieHellmanPublic::parse(&serialized).unwrap();
        assert_eq!(parsed, client_diffie_hellman_public);

        assert!(rest.is_empty());
    }

    #[test]
    fn unknown_encoding_should_error() {
        let message: &[u8] = &[
            0xFF, // PublicValueEncoding::Unknown
            0x00, 0x04, // Public value length
            0x01, 0x02, 0x03, 0x04, // Public value data
        ];

        let result = ClientDiffieHellmanPublic::parse(message);
        assert!(result.is_err());
    }
}
