use super::{CipherSuite, CompressionMethod, Extension, ProtocolVersion, Random, SessionId};
use nom::error::{Error, ErrorKind};
use nom::Err;
use nom::{
    bytes::complete::take,
    multi::many0,
    number::complete::{be_u16, be_u8},
    IResult,
};
use smallvec::SmallVec;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello<'a> {
    pub server_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,
    pub extensions: Option<SmallVec<[Extension<'a>; 32]>>,
}

impl<'a> ServerHello<'a> {
    pub fn new(
        server_version: ProtocolVersion,
        random: Random,
        session_id: SessionId,
        cipher_suite: CipherSuite,
        compression_method: CompressionMethod,
        extensions: Option<SmallVec<[Extension<'a>; 32]>>,
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

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ServerHello<'a>> {
        let (input, server_version) = ProtocolVersion::parse(input)?;
        let (input, random) = Random::parse(input)?;
        let (input, session_id) = SessionId::parse(input)?;
        let (input, cipher_suite) = CipherSuite::parse(input)?;
        let (input, compression_method) = CompressionMethod::parse(input)?;
        let (input, extensions_present) = be_u8(input)?;
        let (input, extensions) = if extensions_present != 0 {
            let (input, extensions_len) = be_u16(input)?;
            let (rest, input_ext) = take(extensions_len)(input)?;
            if !rest.is_empty() {
                return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
            }
            let (input, extensions) = many0(Extension::parse)(input_ext)?;
            (input, Some(SmallVec::from_vec(extensions)))
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

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.server_version.as_u16().to_be_bytes());
        self.random.serialize(output);
        output.push(self.session_id.len() as u8);
        output.extend_from_slice(&self.session_id);
        output.extend_from_slice(&self.cipher_suite.as_u16().to_be_bytes());
        output.push(self.compression_method.as_u8());
        if let Some(extensions) = &self.extensions {
            output.push(1);

            // reserve space for length
            let l1 = output.len();
            output.extend_from_slice(&[0, 0]);

            for extension in extensions {
                extension.serialize(output);
            }

            let ext_len = (output.len() - l1 - 2) as u16;
            output[l1..(l1 + 2)].copy_from_slice(&ext_len.to_be_bytes());
        } else {
            output.push(0);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::message::ExtensionType;

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
        0xC0, 0x2F, // CipherSuite::EECDH_AESGCM
        0x00, // CompressionMethod::Null
        0x01, // Extensions present
        0x00, 0x0C, // Extensions length
        // Extensions
        0x00, 0x0A, // ExtensionType
        0x00, 0x08, // data length
        0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
    ];

    #[test]
    fn roundtrip() {
        let mut serialized = Vec::new();

        let random = Random::parse(&MESSAGE[2..34]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cipher_suite = CipherSuite::EECDH_AESGCM;
        let compression_method = CompressionMethod::Null;
        let extensions = Some(smallvec![Extension::new(
            ExtensionType::SupportedGroups,
            &MESSAGE[46..]
        )]);

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
        assert_eq!(serialized, MESSAGE);

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
