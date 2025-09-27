use super::{CurveType, DigitallySigned, KeyExchangeAlgorithm, NamedCurve};
use crate::buffer::Buf;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u8;
use nom::Err;
use nom::{bytes::complete::take, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct ServerKeyExchange<'a> {
    pub params: ServerKeyExchangeParams<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerKeyExchangeParams<'a> {
    Ecdh(EcdhParams<'a>),
}

impl<'a> ServerKeyExchange<'a> {
    pub fn parse(
        input: &'a [u8],
        key_exchange_algorithm: KeyExchangeAlgorithm,
    ) -> IResult<&'a [u8], ServerKeyExchange<'a>> {
        let (input, params) = match key_exchange_algorithm {
            KeyExchangeAlgorithm::EECDH => {
                let (input, ecdh_params) = EcdhParams::parse(input)?;
                (input, ServerKeyExchangeParams::Ecdh(ecdh_params))
            }
            _ => return Err(Err::Failure(Error::new(input, ErrorKind::Tag))),
        };

        Ok((input, ServerKeyExchange { params }))
    }

    pub fn serialize(&self, output: &mut Buf, with_signature: bool) {
        match &self.params {
            ServerKeyExchangeParams::Ecdh(ecdh_params) => {
                ecdh_params.serialize(output, with_signature)
            }
        }
    }

    pub fn signature(&self) -> Option<&DigitallySigned<'a>> {
        match &self.params {
            ServerKeyExchangeParams::Ecdh(ecdh_params) => ecdh_params.signature.as_ref(),
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

    pub fn serialize(&self, output: &mut Buf, with_signature: bool) {
        output.push(self.curve_type.as_u8());
        output.extend_from_slice(&self.named_curve.as_u16().to_be_bytes());
        output.push(self.public_key.len() as u8);
        output.extend_from_slice(self.public_key);

        if with_signature {
            if let Some(signed) = &self.signature {
                signed.serialize(output);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buffer::Buf;
    use crate::message::{HashAlgorithm, SignatureAlgorithm, SignatureAndHashAlgorithm};

    const MESSAGE_ECDH_PUBKEY: &[u8] = &[
        0x03, // curve_type
        0x00, 0x17, // named_curve
        0x04, // public_key length
        0x01, 0x02, 0x03, 0x04, // public_key
    ];

    #[test]
    fn roundtrip_ecdh() {
        let mut serialized = Buf::new();

        // Build expected message dynamically with DigitallySigned
        let algorithm =
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA);
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
        server_key_exchange.serialize(&mut serialized, true);

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
