use super::extensions::{
    ECPointFormatsExtension, SignatureAlgorithmsExtension, SupportedGroupsExtension,
    UseSrtpExtension,
};
use super::{CipherSuite, CompressionMethod, ProtocolVersion};
use super::{Cookie, Extension, ExtensionType, Random, SessionId};
use nom::error::{Error, ErrorKind};
use nom::Err;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use tinyvec::ArrayVec;

use crate::util::many1;

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello<'a> {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cookie: Cookie,
    pub cipher_suites: ArrayVec<[CipherSuite; 32]>,
    pub compression_methods: ArrayVec<[CompressionMethod; 4]>,
    pub extensions: ArrayVec<[Extension<'a>; 16]>,
}

impl<'a> ClientHello<'a> {
    pub fn new(
        client_version: ProtocolVersion,
        random: Random,
        session_id: SessionId,
        cookie: Cookie,
        cipher_suites: ArrayVec<[CipherSuite; 32]>,
        compression_methods: ArrayVec<[CompressionMethod; 4]>,
    ) -> Self {
        ClientHello {
            client_version,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
            extensions: ArrayVec::new(),
        }
    }

    /// Add all required extensions for DTLS handshake
    pub fn with_extensions(mut self, extension_data: &'a mut Vec<u8>) -> Self {
        // Clear the extension data buffer
        extension_data.clear();

        // First write all extension data
        let mut extension_ranges = ArrayVec::<[(ExtensionType, usize, usize); 8]>::new();

        // Add renegotiation_info extension (empty)
        let start_pos = extension_data.len();
        extension_data.extend_from_slice(&[0x00]); // Empty extension data
        extension_ranges.push((
            ExtensionType::Unknown(0xff01), // renegotiation_info
            start_pos,
            extension_data.len(),
        ));

        // Check if we have any ECC-based cipher suites
        let has_ecc = self.cipher_suites.iter().any(|suite| suite.has_ecc());

        // Add supported groups and EC point formats if using ECC
        if has_ecc {
            // Add supported groups extension
            let supported_groups = SupportedGroupsExtension::default();
            let start_pos = extension_data.len();
            supported_groups.serialize(extension_data);
            extension_ranges.push((
                ExtensionType::SupportedGroups,
                start_pos,
                extension_data.len(),
            ));

            // Add EC point formats extension
            let ec_point_formats = ECPointFormatsExtension::default();
            let start_pos = extension_data.len();
            ec_point_formats.serialize(extension_data);
            extension_ranges.push((
                ExtensionType::EcPointFormats,
                start_pos,
                extension_data.len(),
            ));
        }

        // Add signature algorithms extension (required for TLS 1.2+)
        let signature_algorithms = SignatureAlgorithmsExtension::default();
        let start_pos = extension_data.len();
        signature_algorithms.serialize(extension_data);
        extension_ranges.push((
            ExtensionType::SignatureAlgorithms,
            start_pos,
            extension_data.len(),
        ));

        // Add use_srtp extension for DTLS-SRTP support
        let use_srtp = UseSrtpExtension::default();
        let start_pos = extension_data.len();
        use_srtp.serialize(extension_data);
        extension_ranges.push((ExtensionType::UseSrtp, start_pos, extension_data.len()));

        // Add session_ticket extension (empty)
        let start_pos = extension_data.len();
        extension_data.extend_from_slice(&[0x00]); // Empty extension data
        extension_ranges.push((
            ExtensionType::SessionTicket,
            start_pos,
            extension_data.len(),
        ));

        // Add encrypt_then_mac extension (empty)
        let start_pos = extension_data.len();
        extension_data.extend_from_slice(&[0x00]); // Empty extension data
        extension_ranges.push((
            ExtensionType::EncryptThenMac,
            start_pos,
            extension_data.len(),
        ));

        // Add extended_master_secret extension (empty)
        let start_pos = extension_data.len();
        extension_ranges.push((
            ExtensionType::ExtendedMasterSecret,
            start_pos,
            start_pos, // No data at all
        ));

        // Now create all extensions using the written data
        for (extension_type, start, end) in extension_ranges {
            self.extensions
                .push(Extension::new(extension_type, &extension_data[start..end]));
        }

        self
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ClientHello<'a>> {
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

        // Parse extensions if there are any left
        let (remaining_input, extensions) = Self::parse_extensions(input)?;

        Ok((
            remaining_input,
            ClientHello {
                client_version,
                random,
                session_id,
                cookie,
                cipher_suites,
                compression_methods,
                extensions,
            },
        ))
    }

    /// Parse extensions from the input
    fn parse_extensions(input: &'a [u8]) -> IResult<&'a [u8], ArrayVec<[Extension<'a>; 16]>> {
        let mut extensions = ArrayVec::new();

        // Early return if input is empty
        if input.is_empty() {
            return Ok((input, extensions));
        }

        // Parse extensions length
        let (remaining, extensions_len) = be_u16(input)?;

        // Early return if extensions length is 0
        if extensions_len == 0 {
            return Ok((remaining, extensions));
        }

        // Take the extensions data
        let (remaining, extensions_data) = take(extensions_len)(remaining)?;

        // Parse individual extensions
        let mut extensions_rest = extensions_data;
        while !extensions_rest.is_empty() && extensions.len() < 16 {
            let (rest, extension) = Extension::parse(extensions_rest)?;

            // Add the extension directly with the proper lifetime
            extensions.push(extension);
            extensions_rest = rest;
        }

        Ok((remaining, extensions))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.client_version.as_u16().to_be_bytes());
        self.random.serialize(output);
        output.push(self.session_id.len() as u8);
        output.extend_from_slice(&self.session_id);
        output.push(self.cookie.len() as u8);
        output.extend_from_slice(&self.cookie);
        output.extend_from_slice(&(self.cipher_suites.len() as u16 * 2).to_be_bytes());
        for suite in &self.cipher_suites {
            output.extend_from_slice(&suite.as_u16().to_be_bytes());
        }
        output.push(self.compression_methods.len() as u8);
        for method in &self.compression_methods {
            output.push(method.as_u8());
        }

        // Add extensions if any
        if !self.extensions.is_empty() {
            // First calculate total extensions length
            let mut extensions_len = 0;
            for ext in &self.extensions {
                // Extension type (2) + Extension length (2) + Extension data
                extensions_len += 4 + ext.extension_data.len();
            }

            // Write extensions length
            output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

            // Write each extension
            for ext in &self.extensions {
                ext.serialize(output);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tinyvec::array_vec;

    use super::*;

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
        let random = Random::parse(&MESSAGE[2..34]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cookie = Cookie::try_new(&[0xBB]).unwrap();
        let cipher_suites = array_vec![CipherSuite::EECDH_AESGCM, CipherSuite::EDH_AESGCM];
        let compression_methods = array_vec![[CompressionMethod; 4] => CompressionMethod::Null];

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
