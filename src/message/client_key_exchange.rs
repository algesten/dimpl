use super::KeyExchangeAlgorithm;
use super::{ClientDiffieHellmanPublic, CurveType, NamedCurve};
use crate::buffer::Buf;
use nom::bytes::complete::take;
use nom::error::Error;
use nom::number::complete::be_u8;
use nom::{Err, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct ClientKeyExchange<'a> {
    pub exchange_keys: ExchangeKeys<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExchangeKeys<'a> {
    DhAnon(ClientDiffieHellmanPublic<'a>),
    Ecdh(ClientEcdhKeys<'a>),
}

/// ECDHE key exchange parameters
#[derive(Debug, PartialEq, Eq)]
pub struct ClientEcdhKeys<'a> {
    pub curve_type: CurveType,
    pub named_curve: NamedCurve,
    pub public_key_length: u8,
    pub public_key: &'a [u8],
}

impl<'a> ClientEcdhKeys<'a> {
    pub fn new(curve_type: CurveType, named_curve: NamedCurve, public_key: &'a [u8]) -> Self {
        let public_key_length = public_key.len() as u8;
        ClientEcdhKeys {
            curve_type,
            named_curve,
            public_key_length,
            public_key,
        }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ClientEcdhKeys<'a>> {
        let (input, public_key_length) = be_u8(input)?;
        let (input, public_key) = take(public_key_length)(input)?;

        Ok((
            input,
            ClientEcdhKeys {
                // In ClientKeyExchange, we don't include curve_type and named_curve
                // since they're already established during ServerKeyExchange
                curve_type: CurveType::NamedCurve,  // Default
                named_curve: NamedCurve::Secp256r1, // Default
                public_key_length,
                public_key,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        // For client key exchange, we only need to include the public key length and value
        // The curve_type and named_curve are already established during ServerKeyExchange
        output.push(self.public_key_length);
        output.extend_from_slice(self.public_key);
    }
}

impl<'a> ClientKeyExchange<'a> {
    pub fn new(exchange_keys: ExchangeKeys<'a>) -> Self {
        ClientKeyExchange { exchange_keys }
    }

    pub fn parse(
        input: &'a [u8],
        key_exchange_algorithm: KeyExchangeAlgorithm,
    ) -> IResult<&'a [u8], ClientKeyExchange<'a>> {
        let (input, exchange_keys) = match key_exchange_algorithm {
            KeyExchangeAlgorithm::EDH => {
                let (input, dh_anon) = ClientDiffieHellmanPublic::parse(input)?;
                (input, ExchangeKeys::DhAnon(dh_anon))
            }
            KeyExchangeAlgorithm::EECDH => {
                let (input, ecdh_keys) = ClientEcdhKeys::parse(input)?;
                (input, ExchangeKeys::Ecdh(ecdh_keys))
            }
            _ => return Err(Err::Failure(Error::new(input, nom::error::ErrorKind::Tag))),
        };

        Ok((input, ClientKeyExchange { exchange_keys }))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        match &self.exchange_keys {
            ExchangeKeys::DhAnon(dh_anon) => dh_anon.serialize(output),
            ExchangeKeys::Ecdh(ecdh_keys) => ecdh_keys.serialize(output),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buffer::Buf;
    use crate::message::{KeyExchangeAlgorithm, PublicValueEncoding};

    const DH_MESSAGE: &[u8] = &[
        0x01, // PublicValueEncoding::Explicit
        0x00, 0x04, // Public value length
        0x01, 0x02, 0x03, 0x04, // Public value data
    ];

    const ECDH_MESSAGE: &[u8] = &[
        0x04, // Public key length
        0x01, 0x02, 0x03, 0x04, // Public key data
    ];

    #[test]
    fn roundtrip_dh() {
        let encoding = PublicValueEncoding::Explicit;
        let public_value = &DH_MESSAGE[3..7];

        let dh_anon = ClientDiffieHellmanPublic::new(encoding, public_value);
        let client_key_exchange = ClientKeyExchange::new(ExchangeKeys::DhAnon(dh_anon));

        // Serialize and compare to DH_MESSAGE
        let mut serialized = Buf::new();
        client_key_exchange.serialize(&mut serialized);
        assert_eq!(&*serialized, DH_MESSAGE);

        // Parse and compare with original
        let (rest, parsed) =
            ClientKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EDH).unwrap();
        assert_eq!(parsed, client_key_exchange);

        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_ecdh() {
        let public_key = &ECDH_MESSAGE[1..5];

        let ecdh_keys =
            ClientEcdhKeys::new(CurveType::NamedCurve, NamedCurve::Secp256r1, public_key);
        let client_key_exchange = ClientKeyExchange::new(ExchangeKeys::Ecdh(ecdh_keys));

        // Serialize and compare to ECDH_MESSAGE
        let mut serialized = Buf::new();
        client_key_exchange.serialize(&mut serialized);
        assert_eq!(&*serialized, ECDH_MESSAGE);

        // Parse and compare with original
        let (rest, parsed) =
            ClientKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EECDH).unwrap();

        // For parsing, we need to manually check since the curve info is defaulted
        match &parsed.exchange_keys {
            ExchangeKeys::Ecdh(keys) => {
                assert_eq!(keys.public_key_length, 4);
                assert_eq!(keys.public_key, public_key);
            }
            _ => panic!("Expected ECDH keys"),
        }

        assert!(rest.is_empty());
    }
}
