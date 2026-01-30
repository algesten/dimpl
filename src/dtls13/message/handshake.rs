use std::ops::Range;

use super::{
    Certificate, CertificateVerify, ClientHello, Dtls13CipherSuite, EncryptedExtensions, Finished,
    ServerHello,
};
use crate::buffer::Buf;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u8;
use nom::Err;
use nom::{number::complete::be_u24, IResult};

/// TLS 1.3 handshake header (no fragmentation fields).
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct Header {
    pub msg_type: MessageType,
    pub length: u32,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Handshake {
    pub header: Header,
    pub body: Body,
}

impl Handshake {
    #[cfg(test)]
    pub fn new(msg_type: MessageType, length: u32, body: Body) -> Self {
        Handshake {
            header: Header { msg_type, length },
            body,
        }
    }

    pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
        let (input, msg_type) = MessageType::parse(input)?;
        let (input, length) = be_u24(input)?;

        Ok((input, Header { msg_type, length }))
    }

    pub fn parse(
        input: &[u8],
        base_offset: usize,
        c: Option<Dtls13CipherSuite>,
    ) -> IResult<&[u8], Handshake> {
        let original_input = input;
        let (input, header) = Self::parse_header(input)?;

        let (input, body_bytes) = take(header.length as usize)(input)?;
        let consumed = body_bytes.as_ptr() as usize - original_input.as_ptr() as usize;
        let body_base_offset = base_offset + consumed;
        let (_, body) = Body::parse(body_bytes, body_base_offset, header.msg_type, c)?;

        Ok((input, Handshake { header, body }))
    }

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        output.push(self.header.msg_type.as_u8());
        output.extend_from_slice(&self.header.length.to_be_bytes()[1..]);
        self.body.serialize(source_buf, output);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    ClientHello,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    KeyUpdate,
    Unknown(u8),
}

impl Default for MessageType {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl MessageType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => MessageType::ClientHello,
            2 => MessageType::ServerHello,
            8 => MessageType::EncryptedExtensions,
            11 => MessageType::Certificate,
            13 => MessageType::CertificateRequest,
            15 => MessageType::CertificateVerify,
            20 => MessageType::Finished,
            24 => MessageType::KeyUpdate,
            _ => MessageType::Unknown(value),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            MessageType::ClientHello => 1,
            MessageType::ServerHello => 2,
            MessageType::EncryptedExtensions => 8,
            MessageType::Certificate => 11,
            MessageType::CertificateRequest => 13,
            MessageType::CertificateVerify => 15,
            MessageType::Finished => 20,
            MessageType::KeyUpdate => 24,
            MessageType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], MessageType> {
        let (input, byte) = be_u8(input)?;
        Ok((input, Self::from_u8(byte)))
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum Body {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EncryptedExtensions(EncryptedExtensions),
    Certificate(Certificate),
    CertificateRequest(Range<usize>),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    KeyUpdate(Range<usize>),
    Unknown(u8),
}

impl Default for Body {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl Body {
    pub fn parse(
        input: &[u8],
        base_offset: usize,
        m: MessageType,
        c: Option<Dtls13CipherSuite>,
    ) -> IResult<&[u8], Body> {
        match m {
            MessageType::ClientHello => {
                let (input, client_hello) = ClientHello::parse(input, base_offset)?;
                Ok((input, Body::ClientHello(client_hello)))
            }
            MessageType::ServerHello => {
                let (input, server_hello) = ServerHello::parse(input, base_offset)?;
                Ok((input, Body::ServerHello(server_hello)))
            }
            MessageType::EncryptedExtensions => {
                let (input, ee) = EncryptedExtensions::parse(input, base_offset)?;
                Ok((input, Body::EncryptedExtensions(ee)))
            }
            MessageType::Certificate => {
                let (input, certificate) = Certificate::parse(input, base_offset)?;
                Ok((input, Body::Certificate(certificate)))
            }
            MessageType::CertificateRequest => {
                let range = base_offset..(base_offset + input.len());
                Ok((&[], Body::CertificateRequest(range)))
            }
            MessageType::CertificateVerify => {
                let (input, cv) = CertificateVerify::parse(input, base_offset)?;
                Ok((input, Body::CertificateVerify(cv)))
            }
            MessageType::Finished => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let (input, finished) = Finished::parse(input, cipher_suite)?;
                Ok((input, Body::Finished(finished)))
            }
            MessageType::KeyUpdate => {
                let range = base_offset..(base_offset + input.len());
                Ok((&[], Body::KeyUpdate(range)))
            }
            MessageType::Unknown(value) => Ok((input, Body::Unknown(value))),
        }
    }

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        match self {
            Body::ClientHello(client_hello) => {
                client_hello.serialize(source_buf, output);
            }
            Body::ServerHello(server_hello) => {
                server_hello.serialize(source_buf, output);
            }
            Body::EncryptedExtensions(ee) => {
                ee.serialize(source_buf, output);
            }
            Body::Certificate(certificate) => {
                certificate.serialize(source_buf, output);
            }
            Body::CertificateRequest(range) => {
                output.extend_from_slice(&source_buf[range.clone()]);
            }
            Body::CertificateVerify(cv) => {
                cv.serialize(source_buf, output);
            }
            Body::Finished(finished) => {
                finished.serialize(source_buf, output);
            }
            Body::KeyUpdate(range) => {
                output.extend_from_slice(&source_buf[range.clone()]);
            }
            Body::Unknown(value) => {
                output.push(*value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use arrayvec::ArrayVec;

    use super::*;
    use crate::buffer::Buf;
    use crate::dtls13::message::{
        CompressionMethod, Cookie, Dtls13CipherSuite, ProtocolVersion, Random, SessionId,
    };

    const MESSAGE: &[u8] = &[
        0x01, // MessageType::ClientHello
        0x00, 0x00, 0x2E, // length
        // ClientHello
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
    fn handshake_size() {
        // TLS 1.3 handshake header is 4 bytes (1 type + 3 length)
        let h = Handshake::new(
            MessageType::EncryptedExtensions,
            2,
            Body::EncryptedExtensions(EncryptedExtensions {
                extensions: ArrayVec::new(),
            }),
        );

        let mut v = Buf::new();
        h.serialize(&[], &mut v);

        // 4 bytes header + 2 bytes (empty extensions length)
        assert_eq!(v.len(), 6);
    }

    #[test]
    fn roundtrip() {
        let mut serialized = Buf::new();

        let random = Random::parse(&MESSAGE[6..38]).unwrap().1;
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

        let handshake = Handshake::new(
            MessageType::ClientHello,
            0x2E,
            Body::ClientHello(client_hello),
        );

        // Serialize and compare to MESSAGE
        handshake.serialize(&[], &mut serialized);
        assert_eq!(&*serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Handshake::parse(&serialized, 0, None).unwrap();
        assert_eq!(parsed, handshake);

        assert!(rest.is_empty());
    }
}
