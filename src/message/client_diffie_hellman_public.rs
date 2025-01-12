use super::error::ParseError;
use super::PublicValueEncoding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDiffieHellmanPublic<'a> {
    pub encoding: PublicValueEncoding,
    pub dh_public: &'a [u8],
}

impl<'a> ClientDiffieHellmanPublic<'a> {
    pub fn new(encoding: PublicValueEncoding, dh_public: &'a [u8]) -> Self {
        ClientDiffieHellmanPublic {
            encoding,
            dh_public,
        }
    }

    pub fn parse(data: &'a [u8]) -> Result<ClientDiffieHellmanPublic<'a>, ParseError<ErrorKind>> {
        if data.len() < 1 {
            return Err(ParseError::new(ErrorKind::DhPublicNotEnough, 0));
        }
        let encoding = PublicValueEncoding::from_u8(data[0]);
        let dh_public = &data[1..];
        match encoding {
            PublicValueEncoding::Explicit => {
                if dh_public.len() < 1 || dh_public.len() > 0xFFFF {
                    return Err(ParseError::new(ErrorKind::DhPublicLengthIncorrect, 1));
                }
            }
            PublicValueEncoding::Implicit => {
                if !dh_public.is_empty() {
                    return Err(ParseError::new(ErrorKind::DhPublicNotZero, 1));
                }
            }
            PublicValueEncoding::Unknown(_) => {
                return Err(ParseError::new(ErrorKind::UnknownEncoding, 0));
            }
        }
        Ok(ClientDiffieHellmanPublic {
            encoding,
            dh_public,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.push(self.encoding.to_u8());
        out.extend_from_slice(self.dh_public);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    DhPublicNotEnough,
    DhPublicLengthIncorrect,
    DhPublicNotZero,
    UnknownEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE_EXPLICIT: &[u8] = &[
        0x01, // PublicValueEncoding (Explicit)
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DH public value
    ];

    const MESSAGE_IMPLICIT: &[u8] = &[
        0x00, // PublicValueEncoding (Implicit)
    ];

    #[test]
    fn roundtrip_explicit() {
        let original =
            ClientDiffieHellmanPublic::new(PublicValueEncoding::Explicit, &MESSAGE_EXPLICIT[1..]);

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE_EXPLICIT);

        let parsed = ClientDiffieHellmanPublic::parse(&serialized).unwrap();

        assert_eq!(parsed.encoding, original.encoding);
        assert_eq!(parsed.dh_public, original.dh_public);
    }

    #[test]
    fn roundtrip_implicit() {
        let original =
            ClientDiffieHellmanPublic::new(PublicValueEncoding::Implicit, &MESSAGE_IMPLICIT[1..]);

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE_IMPLICIT);

        let parsed = ClientDiffieHellmanPublic::parse(&serialized).unwrap();

        assert_eq!(parsed.encoding, original.encoding);
        assert_eq!(parsed.dh_public, original.dh_public);
    }

    #[test]
    fn parse_dh_public_not_enough() {
        let error = ClientDiffieHellmanPublic::parse(&[]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DhPublicNotEnough);
    }

    #[test]
    fn parse_dh_public_length_incorrect() {
        let error = ClientDiffieHellmanPublic::parse(&[0x01]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DhPublicLengthIncorrect);
    }

    #[test]
    fn parse_dh_public_not_zero() {
        let error = ClientDiffieHellmanPublic::parse(&[0x00, 0x01]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DhPublicNotZero);
    }

    #[test]
    fn parse_unknown_encoding() {
        let error = ClientDiffieHellmanPublic::parse(&[0xFF]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownEncoding);
    }
}
