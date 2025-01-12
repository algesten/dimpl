use super::client_diffie_hellman_public::{
    ClientDiffieHellmanPublic, ErrorKind as ClientDiffieHellmanErrorKind,
};
use super::error::ParseError;
use super::KeyExchangeAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKeyExchange<'a> {
    pub exchange_keys: ExchangeKeys<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeKeys<'a> {
    ClientDiffieHellmanPublic(ClientDiffieHellmanPublic<'a>),
}

impl<'a> ClientKeyExchange<'a> {
    pub fn parse(
        data: &'a [u8],
        key_exchange_algorithm: KeyExchangeAlgorithm,
    ) -> Result<ClientKeyExchange<'a>, ParseError<ErrorKind>> {
        let exchange_keys = match key_exchange_algorithm {
            KeyExchangeAlgorithm::EECDH | KeyExchangeAlgorithm::EDH => {
                let dh_public = ClientDiffieHellmanPublic::parse(data).map_err(|e| {
                    ParseError::new(ErrorKind::ClientDiffieHellman(e.kind()), e.position())
                })?;
                ExchangeKeys::ClientDiffieHellmanPublic(dh_public)
            }
            KeyExchangeAlgorithm::Unknown => {
                return Err(ParseError::new(ErrorKind::UnknownKeyExchangeAlgorithm, 0))
            }
        };
        Ok(ClientKeyExchange { exchange_keys })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match &self.exchange_keys {
            ExchangeKeys::ClientDiffieHellmanPublic(dh_public) => dh_public.serialize(out),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    UnknownKeyExchangeAlgorithm,
    ClientDiffieHellman(ClientDiffieHellmanErrorKind),
}

impl From<ClientDiffieHellmanErrorKind> for ErrorKind {
    fn from(error: ClientDiffieHellmanErrorKind) -> Self {
        ErrorKind::ClientDiffieHellman(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::KeyExchangeAlgorithm;
    use crate::message::PublicValueEncoding;

    const MESSAGE_DH: &[u8] = &[
        0x01, // PublicValueEncoding (Explicit)
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DH public value
    ];

    #[test]
    fn roundtrip_dh() {
        let original = ClientKeyExchange {
            exchange_keys: ExchangeKeys::ClientDiffieHellmanPublic(ClientDiffieHellmanPublic::new(
                PublicValueEncoding::Explicit,
                &MESSAGE_DH[1..],
            )),
        };

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE_DH);

        let parsed = ClientKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EECDH).unwrap();

        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_unknown_key_exchange_algorithm() {
        let error =
            ClientKeyExchange::parse(&MESSAGE_DH, KeyExchangeAlgorithm::Unknown).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownKeyExchangeAlgorithm);
    }
}
