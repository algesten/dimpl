use super::{CurveType, DigitallySigned, KeyExchangeAlgorithm, NamedCurve};
use crate::buffer::Buf;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u8;
use nom::Err;
use nom::{bytes::complete::take, IResult};
use std::ops::Range;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerKeyExchange {
    pub params: ServerKeyExchangeParams,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerKeyExchangeParams {
    Ecdh(EcdhParams),
}

impl ServerKeyExchange {
    pub fn parse(
        input: &[u8],
        base_offset: usize,
        key_exchange_algorithm: KeyExchangeAlgorithm,
    ) -> IResult<&[u8], ServerKeyExchange> {
        let (input, params) = match key_exchange_algorithm {
            KeyExchangeAlgorithm::EECDH => {
                let (input, ecdh_params) = EcdhParams::parse(input, base_offset)?;
                (input, ServerKeyExchangeParams::Ecdh(ecdh_params))
            }
            _ => return Err(Err::Failure(Error::new(input, ErrorKind::Tag))),
        };

        Ok((input, ServerKeyExchange { params }))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf, with_signature: bool) {
        match &self.params {
            ServerKeyExchangeParams::Ecdh(ecdh_params) => {
                ecdh_params.serialize(buf, output, with_signature)
            }
        }
    }

    pub fn signature(&self) -> Option<&DigitallySigned> {
        match &self.params {
            ServerKeyExchangeParams::Ecdh(ecdh_params) => ecdh_params.signature.as_ref(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EcdhParams {
    pub curve_type: CurveType,
    pub named_curve: NamedCurve,
    pub public_key_range: Range<usize>,
    pub signature: Option<DigitallySigned>,
}

impl EcdhParams {
    pub fn public_key<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.public_key_range.clone()]
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], EcdhParams> {
        let original_input = input;
        let (input, curve_type) = CurveType::parse(input)?;
        let (input, named_curve) = NamedCurve::parse(input)?;

        // First byte is the length of the public key
        let (input, public_key_len) = be_u8(input)?;
        let (input, public_key_slice) = take(public_key_len as usize)(input)?;

        // Calculate absolute range for public key
        let relative_offset = public_key_slice.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + public_key_slice.len();
        let public_key_range = start..end;

        // Optionally parse a trailing DigitallySigned structure
        let (input, signature) = if !input.is_empty() {
            // Calculate absolute offset for the signature part
            let sig_offset =
                base_offset + (input.as_ptr() as usize - original_input.as_ptr() as usize);
            let (rest, signed) = DigitallySigned::parse(input, sig_offset)?;
            (rest, Some(signed))
        } else {
            (input, None)
        };

        Ok((
            input,
            EcdhParams {
                curve_type,
                named_curve,
                public_key_range,
                signature,
            },
        ))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf, with_signature: bool) {
        let public_key = self.public_key(buf);
        output.push(self.curve_type.as_u8());
        output.extend_from_slice(&self.named_curve.as_u16().to_be_bytes());
        output.push(public_key.len() as u8);
        output.extend_from_slice(public_key);

        if with_signature {
            if let Some(signed) = &self.signature {
                signed.serialize(buf, output);
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
        // Build expected message
        let algorithm =
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA);
        let signature_bytes: &[u8] = &[0x05, 0x06, 0x07, 0x08];

        let mut expected = Buf::new();
        expected.extend_from_slice(MESSAGE_ECDH_PUBKEY);
        expected.extend_from_slice(&algorithm.as_u16().to_be_bytes());
        expected.extend_from_slice(&(signature_bytes.len() as u16).to_be_bytes());
        expected.extend_from_slice(signature_bytes);

        // Parse the message with base_offset 0
        let (rest, parsed) =
            ServerKeyExchange::parse(&expected, 0, KeyExchangeAlgorithm::EECDH).unwrap();
        assert!(rest.is_empty());

        // Serialize and compare to expected bytes
        let mut serialized = Buf::new();
        parsed.serialize(&expected, &mut serialized, true);
        assert_eq!(&*serialized, &*expected);
    }
}
