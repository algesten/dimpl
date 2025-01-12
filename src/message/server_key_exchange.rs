use super::error::ParseError;
use super::id::Random;
use super::{CipherSuite, KeyExchangeAlgorithm, ProtocolVersion};

#[derive(Debug)]
pub struct ServerKeyExchange<'a> {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub cipher_suite: CipherSuite,
    pub key_exchange_algorithm: KeyExchangeAlgorithm,
    pub key_exchange_data: &'a [u8],
}

impl<'a> ServerKeyExchange<'a> {
    pub fn new(
        server_version: ProtocolVersion,
        random: Random,
        cipher_suite: CipherSuite,
        key_exchange_algorithm: KeyExchangeAlgorithm,
        key_exchange_data: &'a [u8],
    ) -> Self {
        ServerKeyExchange {
            server_version,
            random,
            cipher_suite,
            key_exchange_algorithm,
            key_exchange_data,
        }
    }

    pub fn parse(data: &'a [u8]) -> Result<ServerKeyExchange<'a>, ParseError<ErrorKind>> {
        let mut position = 0;

        if data.len() < 2 {
            return Err(ParseError::new(ErrorKind::ServerVersionNotEnough, position));
        }
        let server_version =
            ProtocolVersion::from_u16(u16::from_be_bytes([data[position], data[position + 1]]));
        position += 2;

        if data.len() < position + 32 {
            return Err(ParseError::new(ErrorKind::RandomNotEnough, position));
        }
        let random = Random::new(&data[position..position + 32]).unwrap();
        position += 32;

        if data.len() < position + 2 {
            return Err(ParseError::new(ErrorKind::CipherSuiteNotEnough, position));
        }
        let cipher_suite =
            CipherSuite::from_u16(u16::from_be_bytes([data[position], data[position + 1]]));
        position += 2;

        let key_exchange_algorithm = KeyExchangeAlgorithm::from_cipher_suite(cipher_suite);

        let key_exchange_data = &data[position..];

        Ok(ServerKeyExchange {
            server_version,
            random,
            cipher_suite,
            key_exchange_algorithm,
            key_exchange_data,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.server_version.to_u16().to_be_bytes());
        out.extend_from_slice(&self.random);
        out.extend_from_slice(&self.cipher_suite.to_u16().to_be_bytes());
        out.extend_from_slice(self.key_exchange_data);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    ServerVersionNotEnough,
    RandomNotEnough,
    CipherSuiteNotEnough,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = &[
        0xFE, 0xFD, // ProtocolVersion::V1_2
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, // Random
        0xC0, 0x2F, // CipherSuite::EECDH_AESGCM
        0x01, 0x02, 0x03, 0x04, // KeyExchangeData
    ];

    #[test]
    fn roundtrip() {
        let original = ServerKeyExchange::new(
            ProtocolVersion::V1_2,
            "01234567890123456789012345678901".try_into().unwrap(),
            CipherSuite::EECDH_AESGCM,
            KeyExchangeAlgorithm::EECDH,
            &[0x01, 0x02, 0x03, 0x04],
        );

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = ServerKeyExchange::parse(&serialized).unwrap();

        assert_eq!(parsed.server_version, original.server_version);
        assert_eq!(parsed.random, original.random);
        assert_eq!(parsed.cipher_suite, original.cipher_suite);
        assert_eq!(
            parsed.key_exchange_algorithm,
            original.key_exchange_algorithm
        );
        assert_eq!(parsed.key_exchange_data, original.key_exchange_data);
    }

    #[test]
    fn parse_server_version_not_enough() {
        let error = ServerKeyExchange::parse(&MESSAGE[..1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ServerVersionNotEnough);
    }

    #[test]
    fn parse_random_not_enough() {
        let error = ServerKeyExchange::parse(&MESSAGE[..2]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RandomNotEnough);
    }

    #[test]
    fn parse_cipher_suite_not_enough() {
        let error = ServerKeyExchange::parse(&MESSAGE[..34]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CipherSuiteNotEnough);
    }
}
