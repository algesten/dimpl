use super::ClientDiffieHellmanPublic;
use super::KeyExchangeAlgorithm;
use nom::error::Error;
use nom::{Err, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct ClientKeyExchange<'a> {
    pub exchange_keys: ExchangeKeys<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExchangeKeys<'a> {
    DhAnon(ClientDiffieHellmanPublic<'a>),
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
            KeyExchangeAlgorithm::EDH | KeyExchangeAlgorithm::EECDH => {
                let (input, dh_anon) = ClientDiffieHellmanPublic::parse(input)?;
                (input, ExchangeKeys::DhAnon(dh_anon))
            }
            _ => return Err(Err::Failure(Error::new(input, nom::error::ErrorKind::Tag))),
        };

        Ok((input, ClientKeyExchange { exchange_keys }))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        match &self.exchange_keys {
            ExchangeKeys::DhAnon(dh_anon) => dh_anon.serialize(output),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::message::{KeyExchangeAlgorithm, PublicValueEncoding};

    const MESSAGE: &[u8] = &[
        0x01, // PublicValueEncoding::Explicit
        0x00, 0x04, // Public value length
        0x01, 0x02, 0x03, 0x04, // Public value data
    ];

    #[test]
    fn roundtrip() {
        let encoding = PublicValueEncoding::Explicit;
        let public_value = &MESSAGE[3..7];

        let dh_anon = ClientDiffieHellmanPublic::new(encoding, public_value);
        let client_key_exchange = ClientKeyExchange::new(ExchangeKeys::DhAnon(dh_anon));

        // Serialize and compare to MESSAGE
        let mut serialized = Vec::new();
        client_key_exchange.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) =
            ClientKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EECDH).unwrap();
        assert_eq!(parsed, client_key_exchange);

        assert!(rest.is_empty());
    }
}
