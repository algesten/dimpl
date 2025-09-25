use super::extensions::use_srtp::{SrtpProfileId, UseSrtpExtension};
use super::{CipherSuite, CompressionMethod, Extension, ExtensionType};
use super::{ProtocolVersion, Random, SessionId};
use crate::buffer::Buf;
use crate::util::many0;
use nom::error::{Error, ErrorKind};
use nom::Err;
use nom::{bytes::complete::take, number::complete::be_u16, IResult};
use tinyvec::ArrayVec;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello<'a> {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,
    pub extensions: Option<ArrayVec<[Extension<'a>; 32]>>,
}

impl<'a> ServerHello<'a> {
    pub fn new(
        server_version: ProtocolVersion,
        random: Random,
        session_id: SessionId,
        cipher_suite: CipherSuite,
        compression_method: CompressionMethod,
        extensions: Option<ArrayVec<[Extension<'a>; 32]>>,
    ) -> Self {
        ServerHello {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        }
    }

    /// Add extensions to ServerHello using a builder-style API, mirroring ClientHello::with_extensions
    ///
    /// - Uses the provided buffer to stage extension bytes and then stores slice references
    /// - Includes UseSRTP if a profile is provided
    /// - Includes Extended Master Secret if the flag is set
    pub fn with_extensions(
        mut self,
        buf: &'a mut Buf,
        srtp_profile: Option<SrtpProfileId>,
    ) -> Self {
        // Clear the buffer and collect extension byte ranges
        buf.clear();

        let mut ranges: ArrayVec<[(ExtensionType, usize, usize); 8]> = ArrayVec::new();

        // UseSRTP (if negotiated)
        if let Some(pid) = srtp_profile {
            let start = buf.len();
            let mut profiles = ArrayVec::new();
            profiles.push(pid);
            let ext = UseSrtpExtension::new(profiles, Vec::new());
            ext.serialize(buf);
            ranges.push((ExtensionType::UseSrtp, start, buf.len()));
        }

        // Extended Master Secret (mandatory)
        let start = buf.len();
        ranges.push((ExtensionType::ExtendedMasterSecret, start, start));

        // Renegotiation Info (RFC 5746) - empty for initial handshake
        let start = buf.len();
        buf.push(0); // renegotiated_connection length = 0
        ranges.push((ExtensionType::RenegotiationInfo, start, buf.len()));

        let mut extensions: ArrayVec<[Extension<'a>; 32]> = ArrayVec::new();
        for (t, s, e) in ranges {
            extensions.push(Extension::new(t, &buf[s..e]));
        }
        self.extensions = Some(extensions);

        self
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ServerHello<'a>> {
        let (input, server_version) = ProtocolVersion::parse(input)?;
        let (input, random) = Random::parse(input)?;
        let (input, session_id) = SessionId::parse(input)?;
        let (input, cipher_suite) = CipherSuite::parse(input)?;
        let (input, compression_method) = CompressionMethod::parse(input)?;

        // Parse extensions if there are any bytes left
        let (input, extensions) = if !input.is_empty() {
            // Check if we have enough bytes to read the extensions length (2 bytes)
            if input.len() < 2 {
                return Err(Err::Failure(Error::new(input, ErrorKind::Eof)));
            }
            let (input, extensions_len) = be_u16(input)?;

            // Check if we have enough bytes to read the extensions data
            if input.len() < extensions_len as usize {
                return Err(Err::Failure(Error::new(input, ErrorKind::Eof)));
            }

            if extensions_len > 0 {
                let (rest, input_ext) = take(extensions_len)(input)?;
                if !rest.is_empty() {
                    return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
                }
                let (_, extensions) = many0(Extension::parse)(input_ext)?;
                (rest, Some(extensions))
            } else {
                (input, None)
            }
        } else {
            (input, None)
        };

        Ok((
            input,
            ServerHello {
                server_version,
                random,
                session_id,
                cipher_suite,
                compression_method,
                extensions,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.server_version.as_u16().to_be_bytes());
        self.random.serialize(output);
        output.push(self.session_id.len() as u8);
        output.extend_from_slice(&self.session_id);
        output.extend_from_slice(&self.cipher_suite.as_u16().to_be_bytes());
        output.push(self.compression_method.as_u8());
        if let Some(extensions) = &self.extensions {
            // Calculate total extensions length according to spec:
            // For each extension: type (2) + length (2) + data
            let mut extensions_len = 0;
            for ext in extensions.iter() {
                extensions_len += 2 + 2 + ext.extension_data.len();
            }

            // Write extensions length
            output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

            // Write each extension
            for ext in extensions {
                ext.serialize(output);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use tinyvec::array_vec;

    use crate::message::ExtensionType;

    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0xFE, 0xFD, // ProtocolVersion::DTLS1_2
        // Random
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, //
        0x01, // SessionId length
        0xAA, // SessionId
        0xC0, 0x2F, // CipherSuite::EECDH_AESGCM
        0x00, // CompressionMethod::Null
        0x00, 0x0C, // Extensions length (12 bytes total: 2 type + 2 length + 8 data)
        0x00, 0x0A, // ExtensionType::SupportedGroups
        0x00, 0x08, // Extension data length (8 bytes)
        0x00, 0x06, // Extension data
        0x00, 0x17, // NamedGroup::Secp256r1
        0x00, 0x18, // NamedGroup::Secp384r1
        0x00, 0x19, // NamedGroup::Secp521r1
    ];

    #[test]
    fn roundtrip() {
        let mut serialized = Buf::new();

        let random = Random::parse(&MESSAGE[2..34]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cipher_suite = CipherSuite::ECDHE_RSA_AES128_GCM_SHA256;
        let compression_method = CompressionMethod::Null;
        let extensions = Some(array_vec!([Extension; 32] => Extension::new(
            ExtensionType::SupportedGroups,
            &MESSAGE[45..], // Only include the raw extension data (after type and length)
        )));

        let server_hello = ServerHello::new(
            ProtocolVersion::DTLS1_2,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        );

        // Serialize and compare to MESSAGE
        server_hello.serialize(&mut serialized);
        assert_eq!(&*serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = ServerHello::parse(&serialized).unwrap();
        assert_eq!(parsed, server_hello);

        assert!(rest.is_empty());
    }

    #[test]
    fn session_id_too_long() {
        let mut message = MESSAGE.to_vec();
        message[34] = 0x21; // SessionId length (33, which is too long)

        let result = ServerHello::parse(&message);
        assert!(result.is_err());
    }
}
