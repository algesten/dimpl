use super::error::ParseError;
use super::id::{Random, SessionId};
use super::{CipherSuite, CompressionMethod, ProtocolVersion};
use smallvec::SmallVec;

#[derive(Debug)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,
    pub extensions_present: bool,
}

impl ServerHello {
    pub fn new(
        server_version: ProtocolVersion,
        random: Random,
        session_id: SessionId,
        cipher_suite: CipherSuite,
        compression_method: CompressionMethod,
        extensions_present: bool,
    ) -> Self {
        ServerHello {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions_present,
        }
    }

    pub fn parse(data: &[u8]) -> Result<ServerHello, ParseError<ErrorKind>> {
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

        if data.len() < position + 1 {
            return Err(ParseError::new(ErrorKind::SessionIdLength, position));
        }
        let session_id_len = data[position] as usize;
        position += 1;

        if session_id_len > 32 {
            return Err(ParseError::new(ErrorKind::SessionIdTooLong, position));
        }

        if data.len() < position + session_id_len {
            return Err(ParseError::new(ErrorKind::SessionIdNotEnough, position));
        }
        let session_id = SessionId::try_new(&data[position..position + session_id_len])
            .map_err(|_| ParseError::new(ErrorKind::SessionIdNotEnough, position))?;
        position += session_id_len;

        if data.len() < position + 2 {
            return Err(ParseError::new(ErrorKind::CipherSuiteNotEnough, position));
        }
        let cipher_suite =
            CipherSuite::from_u16(u16::from_be_bytes([data[position], data[position + 1]]));
        position += 2;

        if data.len() < position + 1 {
            return Err(ParseError::new(
                ErrorKind::CompressionMethodNotEnough,
                position,
            ));
        }
        let compression_method = CompressionMethod::from_u8(data[position]);
        position += 1;

        let extensions_present = data.len() > position;

        Ok(ServerHello {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions_present,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.server_version.to_u16().to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.cipher_suite.to_u16().to_be_bytes());
        out.push(self.compression_method.to_u8());
        if self.extensions_present {
            // Add logic to serialize extensions if needed
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    ServerVersionNotEnough,
    RandomNotEnough,
    SessionIdLength,
    SessionIdNotEnough,
    SessionIdTooLong,
    CipherSuiteNotEnough,
    CompressionMethodNotEnough,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = &[
        0xFE, 0xFD, // ProtocolVersion::V1_2
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, // Random
        0x0A, // SessionId length
        0x73, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x31, 0x32, 0x33, // SessionId
        0xC0, 0x2F, // CipherSuite
        0x00, // CompressionMethod
    ];

    #[test]
    fn roundtrip() {
        let original = ServerHello::new(
            ProtocolVersion::V1_2,
            "01234567890123456789012345678901".try_into().unwrap(),
            "session123".try_into().unwrap(),
            CipherSuite::EECDH_AESGCM,
            CompressionMethod::Null,
            false,
        );

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = ServerHello::parse(&serialized).unwrap();

        assert_eq!(parsed.server_version, original.server_version);
        assert_eq!(parsed.random, original.random);
        assert_eq!(parsed.session_id, original.session_id);
        assert_eq!(parsed.cipher_suite, original.cipher_suite);
        assert_eq!(parsed.compression_method, original.compression_method);
        assert_eq!(parsed.extensions_present, original.extensions_present);
    }

    #[test]
    fn parse_server_version_too_short() {
        let error = ServerHello::parse(&MESSAGE[..1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ServerVersionNotEnough);
    }

    #[test]
    fn parse_random_too_short() {
        let error = ServerHello::parse(&MESSAGE[..2]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RandomNotEnough);
    }

    #[test]
    fn parse_session_id_length() {
        let error = ServerHello::parse(&MESSAGE[..34]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SessionIdLength);
    }

    #[test]
    fn parse_session_id_too_long() {
        let mut data = MESSAGE.to_vec();
        data[34] = 33; // SessionId length (33)
        let error = ServerHello::parse(&data).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SessionIdTooLong);
    }

    #[test]
    fn parse_session_id_not_enough() {
        let error = ServerHello::parse(&MESSAGE[..44]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SessionIdNotEnough);
    }

    #[test]
    fn parse_cipher_suite_not_enough() {
        let error = ServerHello::parse(&MESSAGE[..45]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CipherSuiteNotEnough);
    }

    #[test]
    fn parse_compression_method_not_enough() {
        let error = ServerHello::parse(&MESSAGE[..47]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CompressionMethodNotEnough);
    }
}
