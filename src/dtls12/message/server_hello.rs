use super::extension::ExtensionVec;
use super::extensions::connection_id::ConnectionIdExtension;
use super::extensions::use_srtp::{SrtpProfileId, UseSrtpExtension};
use super::{CompressionMethod, Dtls12CipherSuite, Extension, ExtensionType};
use super::{ProtocolVersion, Random, SessionId};
use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::Err;
use nom::error::{Error, ErrorKind};
use nom::{IResult, bytes::complete::take, number::complete::be_u16};

#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite: Dtls12CipherSuite,
    pub compression_method: CompressionMethod,
    pub extensions: Option<ExtensionVec>,
}

impl ServerHello {
    pub fn new(
        server_version: ProtocolVersion,
        random: Random,
        session_id: SessionId,
        cipher_suite: Dtls12CipherSuite,
        compression_method: CompressionMethod,
        extensions: Option<ExtensionVec>,
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
    /// - Uses the provided buffer to stage extension bytes and then stores Range references
    /// - Includes UseSRTP if a profile is provided
    /// - Includes Extended Master Secret if the flag is set
    pub fn with_extensions(
        mut self,
        buf: &mut Buf,
        srtp_profile: Option<SrtpProfileId>,
        connection_id: Option<&[u8]>,
    ) -> Self {
        // Clear the buffer and collect extension byte ranges
        buf.clear();

        let mut ranges: ArrayVec<
            (ExtensionType, usize, usize),
            { ExtensionType::supported().len() },
        > = ArrayVec::new();

        // UseSRTP (if negotiated)
        if let Some(pid) = srtp_profile {
            let start = buf.len();
            let mut profiles = ArrayVec::new();
            profiles.push(pid);
            let ext = UseSrtpExtension::new(profiles, ArrayVec::new());
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

        // Connection ID (RFC 9146) - echo our CID if the client offered CID
        if let Some(cid) = connection_id {
            let start = buf.len();
            ConnectionIdExtension::new(cid).serialize(buf);
            ranges.push((ExtensionType::ConnectionId, start, buf.len()));
        }

        let mut extensions = ExtensionVec::new();
        for (t, s, e) in ranges {
            extensions.push(Extension {
                extension_type: t,
                extension_data_range: s..e,
            });
        }
        self.extensions = Some(extensions);

        self
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], ServerHello> {
        let original_input = input;
        let (input, server_version) = ProtocolVersion::parse(input)?;
        let (input, random) = Random::parse(input)?;
        let (input, session_id) = SessionId::parse(input)?;
        let (input, cipher_suite) = Dtls12CipherSuite::parse(input)?;
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
                let consumed_to_ext_data =
                    input_ext.as_ptr() as usize - original_input.as_ptr() as usize;
                let ext_base_offset = base_offset + consumed_to_ext_data;

                // RFC 5246 §7.4.1.4: "There MUST NOT be more than one
                // extension of the same type." The rule applies to every
                // codepoint, not just ones we support, so track all seen
                // raw u16 types before filtering.
                let mut extensions_vec = ExtensionVec::new();
                let mut current_input = input_ext;
                let mut current_offset = ext_base_offset;
                let mut seen_types: ArrayVec<u16, 64> = ArrayVec::new();
                while !current_input.is_empty() {
                    let before_len = current_input.len();
                    let (new_rest, ext) = Extension::parse(current_input, current_offset)?;
                    let parsed_len = before_len - new_rest.len();
                    current_offset += parsed_len;

                    let ty = ext.extension_type.as_u16();
                    if seen_types.contains(&ty) {
                        return Err(Err::Failure(Error::new(current_input, ErrorKind::Verify)));
                    }
                    // Fail closed on tracker overflow — matches ClientHello
                    // handling; silent drop would defeat the RFC 5246
                    // §7.4.1.4 no-duplicates guarantee.
                    seen_types.try_push(ty).map_err(|_| {
                        Err::Failure(Error::new(current_input, ErrorKind::TooLarge))
                    })?;

                    if ext.extension_type.is_supported() {
                        // Defense-in-depth duplicate gate mirroring
                        // ClientHello: reject supported duplicates at
                        // the ExtensionVec layer too, so the dedup
                        // guarantee does not rely solely on `seen_types`.
                        if extensions_vec
                            .iter()
                            .any(|e| e.extension_type == ext.extension_type)
                        {
                            return Err(Err::Failure(Error::new(current_input, ErrorKind::Verify)));
                        }
                        extensions_vec.try_push(ext).map_err(|_| {
                            Err::Failure(Error::new(current_input, ErrorKind::TooLarge))
                        })?;
                    }
                    current_input = new_rest;
                }
                (rest, Some(extensions_vec))
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

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
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
                let ext_data = ext.extension_data(source_buf);
                extensions_len += 2 + 2 + ext_data.len();
            }

            // Write extensions length
            output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

            // Write each extension
            for ext in extensions {
                ext.serialize(source_buf, output);
            }
        }
    }
}

#[cfg(test)]
mod test {
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
        0xC0, 0x2B, // Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
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
        // Parse the message first to get the Extension with proper ranges
        let (rest, parsed) = ServerHello::parse(MESSAGE, 0).unwrap();
        assert!(rest.is_empty());

        // Serialize and compare to MESSAGE
        let mut serialized = Buf::new();
        parsed.serialize(MESSAGE, &mut serialized);
        assert_eq!(&*serialized, MESSAGE);
    }

    #[test]
    fn session_id_too_long() {
        let mut message = MESSAGE.to_vec();
        message[34] = 0x21; // SessionId length (33, which is too long)

        let result = ServerHello::parse(&message, 0);
        assert!(result.is_err());
    }

    /// RFC 5246 §7.4.1.4: duplicate Hello extensions are forbidden. A
    /// ServerHello with two `connection_id` extensions must fail to
    /// parse so the second value can't overwrite the first after the
    /// client has stored `peer_cid`.
    #[test]
    fn duplicate_connection_id_extension_rejected() {
        // Build a fresh ServerHello: random + session_id + cipher_suite +
        // compression + extensions_length + two CID extensions.
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&[0xFE, 0xFD]); // DTLS 1.2
        msg.extend_from_slice(&[0u8; 32]); // Random
        msg.push(0x00); // SessionId length = 0
        msg.extend_from_slice(&[0xC0, 0x2B]); // cipher suite
        msg.push(0x00); // compression method Null
        // extensions_length: two CID extensions, each 6 bytes → 12 bytes.
        msg.extend_from_slice(&0x000Cu16.to_be_bytes());
        // CID ext 1: type=0x0036, len=2, cid_len=1, cid=[0xAA]
        msg.extend_from_slice(&[0x00, 0x36, 0x00, 0x02, 0x01, 0xAA]);
        // CID ext 2: same type, different value → duplicate.
        msg.extend_from_slice(&[0x00, 0x36, 0x00, 0x02, 0x01, 0xBB]);

        let result = ServerHello::parse(&msg, 0);
        assert!(
            result.is_err(),
            "duplicate connection_id in ServerHello must fail to parse"
        );
    }
}
