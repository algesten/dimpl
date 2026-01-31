use super::{CompressionMethod, Dtls13CipherSuite, ProtocolVersion};
use super::{Cookie, Extension, ExtensionType, Random, SessionId};
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u16, be_u8};
use nom::{Err, IResult};

use crate::buffer::Buf;
use crate::util::many1;

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub legacy_session_id: SessionId,
    pub legacy_cookie: Cookie,
    pub cipher_suites: ArrayVec<Dtls13CipherSuite, 3>,
    pub legacy_compression_methods: ArrayVec<CompressionMethod, 2>,
    pub extensions: ArrayVec<Extension, 8>,
}

impl ClientHello {
    pub fn new(
        legacy_version: ProtocolVersion,
        random: Random,
        legacy_session_id: SessionId,
        legacy_cookie: Cookie,
        cipher_suites: ArrayVec<Dtls13CipherSuite, 3>,
        legacy_compression_methods: ArrayVec<CompressionMethod, 2>,
    ) -> Self {
        ClientHello {
            legacy_version,
            random,
            legacy_session_id,
            legacy_cookie,
            cipher_suites,
            legacy_compression_methods,
            extensions: ArrayVec::new(),
        }
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], ClientHello> {
        let original_input = input;
        let (input, legacy_version) = ProtocolVersion::parse(input)?;
        let (input, random) = Random::parse(input)?;
        let (input, legacy_session_id) = SessionId::parse(input)?;
        let (input, legacy_cookie) = Cookie::parse(input)?;
        let (input, cipher_suites_len) = be_u16(input)?;
        let (input, input_cipher) = take(cipher_suites_len)(input)?;
        let (rest, cipher_suites) =
            many1(Dtls13CipherSuite::parse, Dtls13CipherSuite::is_known)(input_cipher)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }
        let (input, compression_methods_len) = be_u8(input)?;
        let (input, input_compression) = take(compression_methods_len)(input)?;
        let (rest, legacy_compression_methods) =
            many1(CompressionMethod::parse, CompressionMethod::is_known)(input_compression)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }

        let consumed = input.as_ptr() as usize - original_input.as_ptr() as usize;
        let extensions_base_offset = base_offset + consumed;

        let (remaining_input, extensions) = Self::parse_extensions(input, extensions_base_offset)?;

        Ok((
            remaining_input,
            ClientHello {
                legacy_version,
                random,
                legacy_session_id,
                legacy_cookie,
                cipher_suites,
                legacy_compression_methods,
                extensions,
            },
        ))
    }

    fn parse_extensions(
        input: &[u8],
        base_offset: usize,
    ) -> IResult<&[u8], ArrayVec<Extension, 8>> {
        let mut extensions = ArrayVec::new();

        if input.is_empty() {
            return Ok((input, extensions));
        }

        let original_input = input;
        let (remaining, extensions_len) = be_u16(input)?;

        if extensions_len == 0 {
            return Ok((remaining, extensions));
        }

        let (remaining, extensions_data) = take(extensions_len)(remaining)?;

        let consumed = extensions_data.as_ptr() as usize - original_input.as_ptr() as usize;
        let data_base_offset = base_offset + consumed;

        let mut extensions_rest = extensions_data;
        let mut current_offset = data_base_offset;
        while !extensions_rest.is_empty() {
            let before_len = extensions_rest.len();
            let (rest, extension) = Extension::parse(extensions_rest, current_offset)?;
            let parsed_len = before_len - rest.len();
            current_offset += parsed_len;

            if extension.extension_type.is_known() {
                extensions.push(extension);
            }
            extensions_rest = rest;
        }

        Ok((remaining, extensions))
    }

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        output.extend_from_slice(&self.legacy_version.as_u16().to_be_bytes());
        self.random.serialize(output);
        output.push(self.legacy_session_id.len() as u8);
        output.extend_from_slice(&self.legacy_session_id);
        output.push(self.legacy_cookie.len() as u8);
        output.extend_from_slice(&self.legacy_cookie);
        output.extend_from_slice(&(self.cipher_suites.len() as u16 * 2).to_be_bytes());
        for suite in &self.cipher_suites {
            output.extend_from_slice(&suite.as_u16().to_be_bytes());
        }
        output.push(self.legacy_compression_methods.len() as u8);
        for method in &self.legacy_compression_methods {
            output.push(method.as_u8());
        }

        if !self.extensions.is_empty() {
            let mut extensions_len = 0;
            for ext in &self.extensions {
                let ext_data = ext.extension_data(source_buf);
                extensions_len += 4 + ext_data.len();
            }

            output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

            for ext in &self.extensions {
                ext.serialize(source_buf, output);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0xFE, 0xFD, // ProtocolVersion::DTLS1_2 (legacy)
        // Random
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, //
        0x01, // SessionId length
        0xAA, // SessionId
        0x01, // Cookie length
        0xBB, // Cookie
        0x00, 0x04, // CipherSuites length
        0x13, 0x01, // AES_128_GCM_SHA256
        0x13, 0x02, // AES_256_GCM_SHA384
        0x01, // CompressionMethods length
        0x00, // Null
    ];

    #[test]
    fn roundtrip() {
        let random = Random::parse(&MESSAGE[2..34]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cookie = Cookie::try_new(&[0xBB]).unwrap();
        let mut cipher_suites = ArrayVec::new();
        cipher_suites.push(Dtls13CipherSuite::AES_128_GCM_SHA256);
        cipher_suites.push(Dtls13CipherSuite::AES_256_GCM_SHA384);
        let mut compression_methods = ArrayVec::new();
        compression_methods.push(CompressionMethod::Null);

        let client_hello = ClientHello::new(
            ProtocolVersion::DTLS1_2,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
        );

        let mut serialized = Buf::new();
        client_hello.serialize(&[], &mut serialized);
        assert_eq!(&*serialized, MESSAGE);

        let (rest, parsed) = ClientHello::parse(&serialized, 0).unwrap();
        assert_eq!(parsed, client_hello);

        assert!(rest.is_empty());
    }

    #[test]
    fn session_id_too_long() {
        let mut message = MESSAGE.to_vec();
        message[34] = 0x21; // SessionId length (33, too long)

        let result = ClientHello::parse(&message, 0);
        assert!(result.is_err());
    }

    #[test]
    fn cookie_too_long() {
        let mut message = MESSAGE.to_vec();
        message[36] = 0xFF; // Cookie length (255, too long for available data)

        let result = ClientHello::parse(&message, 0);
        assert!(result.is_err());
    }

    #[test]
    fn cipher_suites_capacity_matches_known() {
        let client_hello = ClientHello {
            legacy_version: ProtocolVersion::DTLS1_2,
            random: Random::parse(&MESSAGE[2..34]).unwrap().1,
            legacy_session_id: SessionId::empty(),
            legacy_cookie: Cookie::empty(),
            cipher_suites: ArrayVec::new(),
            legacy_compression_methods: ArrayVec::new(),
            extensions: ArrayVec::new(),
        };

        assert_eq!(
            client_hello.cipher_suites.capacity(),
            Dtls13CipherSuite::all().len(),
            "cipher_suites ArrayVec capacity must match all known Dtls13CipherSuites"
        );
    }

    #[test]
    fn extensions_capacity_fits_known() {
        let client_hello = ClientHello {
            legacy_version: ProtocolVersion::DTLS1_2,
            random: Random::parse(&MESSAGE[2..34]).unwrap().1,
            legacy_session_id: SessionId::empty(),
            legacy_cookie: Cookie::empty(),
            cipher_suites: ArrayVec::new(),
            legacy_compression_methods: ArrayVec::new(),
            extensions: ArrayVec::new(),
        };

        assert!(
            client_hello.extensions.capacity() >= ExtensionType::all().len(),
            "extensions ArrayVec capacity must fit all known ExtensionTypes"
        );
    }
}
