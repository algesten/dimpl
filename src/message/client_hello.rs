use super::error::ParseError;
use super::id::{Cookie, Random, SessionId};
use super::{CipherSuite, CompressionMethod, ProtocolVersion};
use smallvec::SmallVec;

pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cookie: Cookie,
    pub cipher_suites: SmallVec<[CipherSuite; 16]>,
    pub compression_methods: SmallVec<[CompressionMethod; 16]>,
}

impl ClientHello {
    pub fn new(
        client_version: ProtocolVersion,
        random: Random,
        session_id: SessionId,
        cookie: Cookie,
        cipher_suites: impl IntoIterator<Item = CipherSuite>,
        compression_methods: impl IntoIterator<Item = CompressionMethod>,
    ) -> Self {
        ClientHello {
            client_version,
            random,
            session_id,
            cookie,
            cipher_suites: cipher_suites.into_iter().collect(),
            compression_methods: compression_methods.into_iter().collect(),
        }
    }

    pub fn parse(data: &[u8]) -> Result<ClientHello, ParseError<ErrorKind>> {
        let mut position = 0;

        if data.len() < 2 {
            return Err(ParseError::new(ErrorKind::ClientVersionNotEnough, position));
        }
        let client_version =
            ProtocolVersion::from_u16(u16::from_be_bytes([data[position], data[position + 1]]));
        position += 2;

        if data.len() < position + 32 {
            return Err(ParseError::new(ErrorKind::RandomNotEnough, position));
        }
        // unwrap is ok, because the max length of Random is 32.
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

        if data.len() < position + 1 {
            return Err(ParseError::new(ErrorKind::CookieLength, position));
        }
        let cookie_len = data[position] as usize;
        position += 1;

        if data.len() < position + cookie_len {
            return Err(ParseError::new(ErrorKind::CookieNotEnough, position));
        }
        // unwrap() is ok because the cookie length is one byte and the Cookie type holds 255.
        let cookie = Cookie::try_new(&data[position..position + cookie_len]).unwrap();
        position += cookie_len;

        if data.len() < position + 2 {
            return Err(ParseError::new(ErrorKind::CipherSuitesLength, position));
        }
        let cipher_suites_len = u16::from_be_bytes([data[position], data[position + 1]]) as usize;
        position += 2;

        if cipher_suites_len < 2 {
            return Err(ParseError::new(ErrorKind::CipherSuitesTooShort, position));
        }

        if data.len() < position + cipher_suites_len * 2 {
            return Err(ParseError::new(ErrorKind::CipherSuitesNotEnough, position));
        }
        let cipher_suites = &data[position..position + cipher_suites_len * 2];
        let cipher_suites: Result<SmallVec<[CipherSuite; 16]>, ParseError<ErrorKind>> =
            cipher_suites
                .chunks(2)
                .map(|chunk| {
                    if chunk.len() != 2 {
                        Err(ParseError::new(ErrorKind::CipherSuite, position))
                    } else {
                        Ok(CipherSuite::from_u16(u16::from_be_bytes([
                            chunk[0], chunk[1],
                        ])))
                    }
                })
                .collect();
        let cipher_suites = cipher_suites?;
        position += cipher_suites_len * 2;

        if data.len() < position + 1 {
            return Err(ParseError::new(
                ErrorKind::CompressionMethodsLength,
                position,
            ));
        }
        let compression_methods_len = data[position] as usize;
        position += 1;

        if compression_methods_len < 1 {
            return Err(ParseError::new(
                ErrorKind::CompressionMethodsTooShort,
                position,
            ));
        }

        if data.len() < position + compression_methods_len {
            return Err(ParseError::new(
                ErrorKind::CompressionMethodsNotEnough,
                position,
            ));
        }
        let compression_methods = &data[position..position + compression_methods_len];
        let compression_methods: Result<SmallVec<[CompressionMethod; 16]>, ParseError<ErrorKind>> =
            compression_methods
                .iter()
                .map(|&byte| Ok(CompressionMethod::from_u8(byte)))
                .collect();
        let compression_methods = compression_methods?;

        Ok(ClientHello {
            client_version,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.client_version.to_u16().to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.push(self.cookie.len() as u8);
        out.extend_from_slice(&self.cookie);
        out.extend_from_slice(&(self.cipher_suites.len() as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            out.extend_from_slice(&suite.to_u16().to_be_bytes());
        }
        out.push(self.compression_methods.len() as u8);
        for method in &self.compression_methods {
            out.push(method.to_u8());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    ClientVersionNotEnough,
    RandomNotEnough,
    SessionIdLength,
    SessionIdNotEnough,
    SessionIdTooLong,
    CookieLength,
    CookieNotEnough,
    CipherSuitesLength,
    CipherSuitesNotEnough,
    CipherSuitesTooShort,
    CipherSuite,
    CompressionMethodsLength,
    CompressionMethodsNotEnough,
    CompressionMethodsTooShort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        const EXPECTED_SERIALIZED: &[u8] = &[
            0xFE, 0xFD, // ProtocolVersion::V1_2
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x30, 0x31, // Random
            0x0A, // SessionId length
            0x73, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x31, 0x32, 0x33, // SessionId
            0x09, // Cookie length
            0x63, 0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x34, 0x35, 0x36, // Cookie
            0x00, 0x02, // CipherSuites length
            0xC0, 0x2F, 0xC0, 0x30, // CipherSuites
            0x02, // CompressionMethods length
            0x00, 0x01, // CompressionMethods
        ];

        let original = ClientHello::new(
            ProtocolVersion::V1_2,
            "01234567890123456789012345678901".try_into().unwrap(),
            "session123".try_into().unwrap(),
            "cookie456".try_into().unwrap(),
            [CipherSuite::EECDH_AESGCM, CipherSuite::EDH_AESGCM],
            [CompressionMethod::Null, CompressionMethod::Deflate],
        );

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, EXPECTED_SERIALIZED);

        let parsed = ClientHello::parse(&serialized).unwrap();

        assert_eq!(parsed.client_version, original.client_version);
        assert_eq!(parsed.random, original.random);
        assert_eq!(parsed.session_id, original.session_id);
        assert_eq!(parsed.cookie, original.cookie);
        assert_eq!(parsed.cipher_suites, original.cipher_suites);
        assert_eq!(parsed.compression_methods, original.compression_methods);
    }
}
