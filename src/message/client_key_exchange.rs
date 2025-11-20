use super::KeyExchangeAlgorithm;
use super::{CurveType, NamedCurve};
use crate::buffer::Buf;
use nom::bytes::complete::take;
use nom::error::Error;
use nom::number::complete::be_u8;
use nom::{Err, IResult};
use std::ops::Range;

#[derive(Debug, PartialEq, Eq)]
pub struct ClientKeyExchange {
    pub exchange_keys: ExchangeKeys,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExchangeKeys {
    Ecdh(ClientEcdhKeys),
}

/// ECDHE key exchange parameters
#[derive(Debug, PartialEq, Eq)]
pub struct ClientEcdhKeys {
    pub curve_type: CurveType,
    pub named_curve: NamedCurve,
    pub public_key_range: Range<usize>,
}

impl ClientEcdhKeys {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], ClientEcdhKeys> {
        let original_input = input;
        let (input, public_key_length) = be_u8(input)?;
        let (input, public_key_slice) = take(public_key_length)(input)?;

        // Calculate absolute range in root buffer
        let relative_offset = public_key_slice.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + public_key_slice.len();

        Ok((
            input,
            ClientEcdhKeys {
                // In ClientKeyExchange, we don't include curve_type and named_curve
                // since they're already established during ServerKeyExchange
                curve_type: CurveType::NamedCurve,  // Default
                named_curve: NamedCurve::Secp256r1, // Default
                public_key_range: start..end,
            },
        ))
    }

    pub fn public_key<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.public_key_range.clone()]
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        // For client key exchange, we only need to include the public key length and value
        // The curve_type and named_curve are already established during ServerKeyExchange
        let public_key = self.public_key(buf);
        output.push(public_key.len() as u8);
        output.extend_from_slice(public_key);
    }
}

impl ClientKeyExchange {
    pub fn parse(
        input: &[u8],
        base_offset: usize,
        key_exchange_algorithm: KeyExchangeAlgorithm,
    ) -> IResult<&[u8], ClientKeyExchange> {
        let (input, exchange_keys) = match key_exchange_algorithm {
            KeyExchangeAlgorithm::EECDH => {
                let (input, ecdh_keys) = ClientEcdhKeys::parse(input, base_offset)?;
                (input, ExchangeKeys::Ecdh(ecdh_keys))
            }
            _ => return Err(Err::Failure(Error::new(input, nom::error::ErrorKind::Tag))),
        };

        Ok((input, ClientKeyExchange { exchange_keys }))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        match &self.exchange_keys {
            ExchangeKeys::Ecdh(ecdh_keys) => ecdh_keys.serialize(buf, output),
        }
    }

    /// Helper to serialize directly from public key bytes (for sending)
    pub fn serialize_from_bytes(public_key: &[u8], output: &mut Buf) {
        output.push(public_key.len() as u8);
        output.extend_from_slice(public_key);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buffer::Buf;
    use crate::message::KeyExchangeAlgorithm;

    const ECDH_MESSAGE: &[u8] = &[
        0x04, // Public key length
        0x01, 0x02, 0x03, 0x04, // Public key data
    ];

    #[test]
    fn roundtrip_ecdh() {
        // Parse the message with base_offset 0
        let (rest, parsed) =
            ClientKeyExchange::parse(ECDH_MESSAGE, 0, KeyExchangeAlgorithm::EECDH).unwrap();
        assert!(rest.is_empty());

        // Serialize and compare to ECDH_MESSAGE
        let mut serialized = Buf::new();
        parsed.serialize(ECDH_MESSAGE, &mut serialized);
        assert_eq!(&*serialized, ECDH_MESSAGE);
    }
}
