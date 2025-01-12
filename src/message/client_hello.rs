use super::id::{Cookie, Random, SessionId};
use super::{CipherSuite, CompressionMethod, ProtocolVersion};
use nom::error::{Error, ErrorKind};
use nom::Err;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use smallvec::SmallVec;

use super::util::many1;

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cookie: Cookie,
    pub cipher_suites: SmallVec<[CipherSuite; 32]>,
    pub compression_methods: SmallVec<[CompressionMethod; 4]>,
}

impl ClientHello {
    pub fn new(
        client_version: ProtocolVersion,
        random: Random,
        session_id: SessionId,
        cookie: Cookie,
        cipher_suites: SmallVec<[CipherSuite; 32]>,
        compression_methods: SmallVec<[CompressionMethod; 4]>,
    ) -> Self {
        ClientHello {
            client_version,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ClientHello> {
        let (input, client_version) = ProtocolVersion::parse(input)?;
        let (input, random) = Random::parse(input)?;
        let (input, session_id) = SessionId::parse(input)?;
        let (input, cookie) = Cookie::parse(input)?;
        let (input, cipher_suites_len) = be_u16(input)?;
        let (input, input_cipher) = take(cipher_suites_len)(input)?;
        let (rest, cipher_suites) = many1(CipherSuite::parse)(input_cipher)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }
        let (input, compression_methods_len) = be_u8(input)?;
        let (input, input_compression) = take(compression_methods_len)(input)?;
        let (rest, compression_methods) = many1(CompressionMethod::parse)(input_compression)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }

        Ok((
            input,
            ClientHello {
                client_version,
                random,
                session_id,
                cookie,
                cipher_suites,
                compression_methods,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.client_version.to_u16().to_be_bytes());
        output.extend_from_slice(&self.random);
        output.push(self.session_id.len() as u8);
        output.extend_from_slice(&self.session_id);
        output.push(self.cookie.len() as u8);
        output.extend_from_slice(&self.cookie);
        output.extend_from_slice(&(self.cipher_suites.len() as u16 * 2).to_be_bytes());
        for suite in &self.cipher_suites {
            output.extend_from_slice(&suite.to_u16().to_be_bytes());
        }
        output.push(self.compression_methods.len() as u8);
        for method in &self.compression_methods {
            output.push(method.to_u8());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    const MESSAGE: &[u8] = &[
        0xFE, 0xFD, // ProtocolVersion::DTLS1_2
        // Random
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, //
        0x01, // SessionId length
        0xAA, // SessionId
        0x01, // Cookie length
        0xBB, // Cookie
        0x00, 0x04, // CipherSuites length
        0xC0, 0x2F, // CipherSuite::EECDH_AESGCM
        0xC0, 0x30, // CipherSuite::EDH_AESGCM
        0x01, // CompressionMethods length
        0x00, // CompressionMethod::Null
    ];

    #[test]
    fn roundtrip() {
        let random = Random::new(&MESSAGE[2..34]).unwrap();
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cookie = Cookie::try_new(&[0xBB]).unwrap();
        let cipher_suites = smallvec![CipherSuite::EECDH_AESGCM, CipherSuite::EDH_AESGCM];
        let compression_methods = smallvec![CompressionMethod::Null];

        let client_hello = ClientHello::new(
            ProtocolVersion::DTLS1_2,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
        );

        // Serialize and compare to MESSAGE
        let mut serialized = Vec::new();
        client_hello.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = ClientHello::parse(&serialized).unwrap();
        assert_eq!(parsed, client_hello);

        assert!(rest.is_empty());
    }

    #[test]
    fn session_id_too_long() {
        let mut message = MESSAGE.to_vec();
        message[34] = 0x21; // SessionId length (33, which is too long)

        let result = ClientHello::parse(&message);
        assert!(result.is_err());
    }

    #[test]
    fn cookie_too_long() {
        let mut message = MESSAGE.to_vec();
        message[36] = 0xFF; // Cookie length (255, which is too long)

        let result = ClientHello::parse(&message);
        assert!(result.is_err());
    }
}
