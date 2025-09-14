use super::{CurveType, DigitallySigned, KeyExchangeAlgorithm, NamedCurve};
use crate::buffer::Buf;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u16, be_u8};
use nom::Err;
use nom::{bytes::complete::take, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct ServerKeyExchange<'a> {
    pub params: ServerKeyExchangeParams<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerKeyExchangeParams<'a> {
    Dh(DhParams<'a>),
    Ecdh(EcdhParams<'a>),
}

impl<'a> ServerKeyExchange<'a> {
    pub fn parse(
        input: &'a [u8],
        key_exchange_algorithm: KeyExchangeAlgorithm,
    ) -> IResult<&'a [u8], ServerKeyExchange<'a>> {
        let (input, params) = match key_exchange_algorithm {
            KeyExchangeAlgorithm::EDH => {
                let (input, dh_params) = DhParams::parse(input)?;
                (input, ServerKeyExchangeParams::Dh(dh_params))
            }
            KeyExchangeAlgorithm::EECDH => {
                let (input, ecdh_params) = EcdhParams::parse(input)?;
                (input, ServerKeyExchangeParams::Ecdh(ecdh_params))
            }
            _ => return Err(Err::Failure(Error::new(input, ErrorKind::Tag))),
        };

        Ok((input, ServerKeyExchange { params }))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        match &self.params {
            ServerKeyExchangeParams::Dh(dh_params) => dh_params.serialize(output),
            ServerKeyExchangeParams::Ecdh(ecdh_params) => ecdh_params.serialize(output),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DhParams<'a> {
    pub p: &'a [u8],
    pub g: &'a [u8],
    pub ys: &'a [u8],
    pub signature: Option<DigitallySigned<'a>>,
}

impl<'a> DhParams<'a> {
    pub fn new(p: &'a [u8], g: &'a [u8], ys: &'a [u8], signature: Option<DigitallySigned<'a>>) -> Self {
        DhParams { p, g, ys, signature }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], DhParams<'a>> {
        let (input, p_len) = be_u16(input)?;
        if p_len < 1 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, p) = take(p_len)(input)?;
        let (input, g_len) = be_u16(input)?;
        if g_len < 1 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, g) = take(g_len)(input)?;
        let (input, ys_len) = be_u16(input)?;
        if ys_len < 1 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, ys) = take(ys_len)(input)?;

        // Optionally parse a trailing DigitallySigned structure
        let (input, signature) = if !input.is_empty() {
            let (input_after_sig, signed) = DigitallySigned::parse(input)?;
            (input_after_sig, Some(signed))
        } else {
            (input, None)
        };

        Ok((input, DhParams { p, g, ys, signature }))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        output.extend_from_slice(&(self.p.len() as u16).to_be_bytes());
        output.extend_from_slice(self.p);
        output.extend_from_slice(&(self.g.len() as u16).to_be_bytes());
        output.extend_from_slice(self.g);
        output.extend_from_slice(&(self.ys.len() as u16).to_be_bytes());
        output.extend_from_slice(self.ys);
        if let Some(signed) = &self.signature {
            signed.serialize(output);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EcdhParams<'a> {
    pub curve_type: CurveType,
    pub named_curve: NamedCurve,
    pub public_key: &'a [u8],
    pub signature: Option<DigitallySigned<'a>>,
}

impl<'a> EcdhParams<'a> {
    pub fn new(
        curve_type: CurveType,
        named_curve: NamedCurve,
        public_key: &'a [u8],
        signature: Option<DigitallySigned<'a>>,
    ) -> Self {
        EcdhParams {
            curve_type,
            named_curve,
            public_key,
            signature,
        }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], EcdhParams<'a>> {
        let (input, curve_type) = CurveType::parse(input)?;
        let (input, named_curve) = NamedCurve::parse(input)?;

        // First byte is the length of the public key
        let (input, public_key_len) = be_u8(input)?;
        let (input, public_key) = take(public_key_len as usize)(input)?;

        // Optionally parse a trailing DigitallySigned structure
        let (input, signature) = if !input.is_empty() {
            let (rest, signed) = DigitallySigned::parse(input)?;
            (rest, Some(signed))
        } else {
            (input, None)
        };

        Ok((
            input,
            EcdhParams {
                curve_type,
                named_curve,
                public_key,
                signature,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        output.push(self.curve_type.as_u8());
        output.extend_from_slice(&self.named_curve.as_u16().to_be_bytes());
        output.push(self.public_key.len() as u8);
        output.extend_from_slice(self.public_key);
        if let Some(signed) = &self.signature {
            signed.serialize(output);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buffer::Buf;
    use crate::message::{HashAlgorithm, SignatureAlgorithm, SignatureAndHashAlgorithm};

    const MESSAGE_DH: &[u8] = &[
        0x00, 0x04, // p length
        0x01, 0x02, 0x03, 0x04, // p
        0x00, 0x02, // g length
        0x05, 0x06, // g
        0x00, 0x02, // ys length
        0x07, 0x08, // ys
    ];

    const MESSAGE_ECDH_PUBKEY: &[u8] = &[
        0x03, // curve_type
        0x00, 0x17, // named_curve
        0x04, // public_key length
        0x01, 0x02, 0x03, 0x04, // public_key
    ];

    #[test]
    fn roundtrip_dh() {
        let mut serialized = Buf::new();

        let dh_params = DhParams::new(
            &MESSAGE_DH[2..6],
            &MESSAGE_DH[8..10],
            &MESSAGE_DH[12..14],
            None,
        );

        let server_key_exchange = ServerKeyExchange {
            params: ServerKeyExchangeParams::Dh(dh_params),
        };

        // Serialize and compare to DH_MESSAGE
        server_key_exchange.serialize(&mut serialized);
        assert_eq!(&*serialized, MESSAGE_DH);

        // Parse and compare with original
        let (rest, parsed) =
            ServerKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EDH).unwrap();
        assert_eq!(parsed, server_key_exchange);

        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_dh_with_signature() {
        // Build a message with params followed by a DigitallySigned block
        let algorithm = SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA);
        let signature_bytes: &[u8] = &[0x0A, 0x0B, 0x0C, 0x0D];

        let mut expected = Buf::new();
        // params
        expected.extend_from_slice(&[0x00, 0x04]);
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        expected.extend_from_slice(&[0x00, 0x02]);
        expected.extend_from_slice(&[0x05, 0x06]);
        expected.extend_from_slice(&[0x00, 0x02]);
        expected.extend_from_slice(&[0x07, 0x08]);
        // DigitallySigned
        expected.extend_from_slice(&algorithm.as_u16().to_be_bytes());
        expected.extend_from_slice(&(signature_bytes.len() as u16).to_be_bytes());
        expected.extend_from_slice(signature_bytes);

        let signed = DigitallySigned::new(algorithm, signature_bytes);
        let dh_params = DhParams::new(&[1, 2, 3, 4], &[5, 6], &[7, 8], Some(signed));

        // Serialize
        let mut serialized = Buf::new();
        let ske = ServerKeyExchange {
            params: ServerKeyExchangeParams::Dh(dh_params),
        };
        ske.serialize(&mut serialized);
        assert_eq!(&*serialized, &*expected);

        // Parse
        let (rest, parsed) = ServerKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EDH).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(parsed, ske);
    }

    #[test]
    fn roundtrip_ecdh() {
        let mut serialized = Buf::new();

        // Build expected message dynamically with DigitallySigned
        let algorithm = SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA);
        let signature_bytes: &[u8] = &[0x05, 0x06, 0x07, 0x08];

        let signed = DigitallySigned::new(algorithm, signature_bytes);

        let ecdh_params = EcdhParams::new(
            CurveType::NamedCurve,
            NamedCurve::Secp256r1,
            &MESSAGE_ECDH_PUBKEY[4..8],
            Some(signed),
        );

        let server_key_exchange = ServerKeyExchange {
            params: ServerKeyExchangeParams::Ecdh(ecdh_params),
        };

        // Serialize and compare to expected bytes
        server_key_exchange.serialize(&mut serialized);

        let mut expected = Buf::new();
        expected.extend_from_slice(MESSAGE_ECDH_PUBKEY);
        expected.extend_from_slice(&algorithm.as_u16().to_be_bytes());
        expected.extend_from_slice(&(signature_bytes.len() as u16).to_be_bytes());
        expected.extend_from_slice(signature_bytes);

        assert_eq!(&*serialized, &*expected);

        // Parse and compare with original
        let (rest, parsed) =
            ServerKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EECDH).unwrap();
        assert_eq!(parsed, server_key_exchange);

        assert!(rest.is_empty());
    }
}
