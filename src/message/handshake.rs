use std::cell::Cell;
use std::collections::VecDeque;
use std::hash::DefaultHasher;
use std::iter::Peekable;

use crate::incoming::Incoming;

use super::{
    Certificate, CertificateRequest, CertificateVerify, CipherSuite, ClientHello,
    ClientKeyExchange, Finished, HelloVerifyRequest, ServerHello, ServerKeyExchange,
};
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u8;
use nom::Err;
use nom::{
    number::complete::{be_u16, be_u24},
    IResult,
};
use tinyvec::ArrayVec;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct Header {
    pub msg_type: MessageType,
    pub length: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_length: u32,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct Handshake<'a> {
    pub header: Header,
    pub body: Body<'a>,
    pub handled: Cell<bool>,
}

impl<'a> Handshake<'a> {
    pub fn new(
        msg_type: MessageType,
        length: u32,
        message_seq: u16,
        fragment_offset: u32,
        fragment_length: u32,
        body: Body<'a>,
    ) -> Self {
        // The constructor must not used to create fragments.
        assert!(!body.is_fragment());

        Handshake {
            header: Header {
                msg_type,
                length,
                message_seq,
                fragment_offset,
                fragment_length,
            },
            body,
            handled: Cell::new(false),
        }
    }

    pub fn is_fragment(&self) -> bool {
        self.body.is_fragment()
    }

    pub fn parse_header(input: &'a [u8]) -> IResult<&'a [u8], Header> {
        let (input, msg_type) = MessageType::parse(input)?;
        let (input, length) = be_u24(input)?;
        let (input, message_seq) = be_u16(input)?;
        let (input, fragment_offset) = be_u24(input)?;
        let (input, fragment_length) = be_u24(input)?;

        Ok((
            input,
            Header {
                msg_type,
                length,
                message_seq,
                fragment_offset,
                fragment_length,
            },
        ))
    }

    pub fn parse(
        input: &'a [u8],
        c: Option<CipherSuite>,
        as_fragment: bool,
    ) -> IResult<&'a [u8], Handshake<'a>> {
        let (input, header) = Self::parse_header(input)?;

        let is_fragment = header.fragment_offset > 0 || header.fragment_length < header.length;

        if !as_fragment && is_fragment {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }

        let (input, body) = if as_fragment {
            let (input, fragment) = take(header.fragment_length as usize)(input)?;
            (input, Body::Fragment(fragment))
        } else {
            let (input, body_bytes) = take(header.length as usize)(input)?;
            let (_, body) = Body::parse(body_bytes, header.msg_type, c)?;
            (input, body)
        };

        Ok((
            input,
            Handshake {
                header,
                body,
                handled: Cell::new(false),
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.push(self.header.msg_type.as_u8());
        output.extend_from_slice(&self.header.length.to_be_bytes()[1..]);
        output.extend_from_slice(&self.header.message_seq.to_be_bytes());
        output.extend_from_slice(&self.header.fragment_offset.to_be_bytes()[1..]);
        output.extend_from_slice(&self.header.fragment_length.to_be_bytes()[1..]);
        self.body.serialize(output);
    }

    #[allow(private_interfaces)]
    pub fn defragment<'b, 'c: 'b>(
        mut iter: impl Iterator<Item = &'b Handshake<'c>>,
        buffer: &'a mut Vec<u8>,
        cipher_suite: Option<CipherSuite>,
    ) -> Result<(Handshake<'a>, Option<MessageType>), crate::Error> {
        buffer.clear();

        // Invariant is upheld by the caller.
        let first = iter.next().unwrap();

        let Body::Fragment(data) = first.body else {
            unreachable!("Non-Fragment body in defragment()")
        };
        buffer.extend_from_slice(data);
        first.handled.set(true);

        let mut next_type = None;

        for handshake in iter {
            if handshake.header.msg_type != first.header.msg_type {
                next_type = Some(handshake.header.msg_type);
                break;
            }

            let Body::Fragment(data) = handshake.body else {
                unreachable!("Non-Fragment body in defragment()")
            };

            handshake.handled.set(true);

            buffer.extend_from_slice(data);
        }

        if buffer.len() != first.header.length as usize {
            debug!("Defragmentation failed. Fragment length mismatch");
            return Err(crate::Error::ParseIncomplete);
        }

        let (rest, body) = Body::parse(buffer, first.header.msg_type, cipher_suite)?;

        if !rest.is_empty() && first.header.msg_type == MessageType::Finished {
            debug!("Defragmentation failed. Body::parse() did not consume the entire buffer");
            return Err(crate::Error::ParseIncomplete);
        }

        let handshake = Handshake {
            header: Header {
                msg_type: first.header.msg_type,
                length: first.header.length,
                message_seq: first.header.message_seq,
                fragment_offset: 0,
                fragment_length: first.header.length,
            },
            body,
            handled: Cell::new(false),
        };

        // Create a new Handshake with the merged body
        Ok((handshake, next_type))
    }

    fn do_clone<'b>(&self) -> Handshake<'b> {
        Handshake {
            header: Header {
                msg_type: self.header.msg_type,
                length: self.header.length,
                message_seq: self.header.message_seq,
                fragment_offset: self.header.fragment_offset,
                fragment_length: self.header.fragment_length,
            },
            body: Body::HelloRequest, // Placeholder
            handled: Cell::new(false),
        }
    }

    pub fn fragment<'b>(
        &self,
        max: usize,
        buffer: &'b mut Vec<u8>,
    ) -> impl Iterator<Item = Handshake<'b>> {
        // Must be called with an empty buffer.
        assert!(buffer.is_empty());

        self.body.serialize(buffer);

        // If this is wrong, the serialize has not produced the same output as we parsed.
        assert_eq!(buffer.len(), self.header.length as usize);

        let to_clone = self.do_clone();

        buffer.chunks(max).enumerate().map(move |(i, chunk)| {
            let fragment_length = chunk.len() as u32;
            let fragment_body = chunk;

            let mut fragment = to_clone.do_clone();
            fragment.header.fragment_offset = (i * max) as u32;
            fragment.header.fragment_length = fragment_length;
            fragment.header.message_seq = to_clone.header.message_seq + i as u16;
            fragment.body = Body::Fragment(fragment_body);

            fragment
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    HelloRequest, // empty
    ClientHello,
    HelloVerifyRequest,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone, // empty
    CertificateVerify,
    ClientKeyExchange,
    Finished,
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
            0 => MessageType::HelloRequest, // empty
            1 => MessageType::ClientHello,
            3 => MessageType::HelloVerifyRequest,
            2 => MessageType::ServerHello,
            11 => MessageType::Certificate,
            12 => MessageType::ServerKeyExchange,
            13 => MessageType::CertificateRequest,
            14 => MessageType::ServerHelloDone, // empty
            15 => MessageType::CertificateVerify,
            16 => MessageType::ClientKeyExchange,
            20 => MessageType::Finished,
            _ => MessageType::Unknown(value),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            MessageType::HelloRequest => 0,
            MessageType::ClientHello => 1,
            MessageType::HelloVerifyRequest => 3,
            MessageType::ServerHello => 2,
            MessageType::Certificate => 11,
            MessageType::ServerKeyExchange => 12,
            MessageType::CertificateRequest => 13,
            MessageType::ServerHelloDone => 14,
            MessageType::CertificateVerify => 15,
            MessageType::ClientKeyExchange => 16,
            MessageType::Finished => 20,
            MessageType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], MessageType> {
        let (input, byte) = be_u8(input)?;
        Ok((input, Self::from_u8(byte)))
    }
}

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Body<'a> {
    HelloRequest, // empty
    ClientHello(ClientHello<'a>),
    HelloVerifyRequest(HelloVerifyRequest),
    ServerHello(ServerHello<'a>),
    Certificate(Certificate<'a>),
    ServerKeyExchange(ServerKeyExchange<'a>),
    CertificateRequest(CertificateRequest<'a>),
    ServerHelloDone, // empty
    CertificateVerify(CertificateVerify<'a>),
    ClientKeyExchange(ClientKeyExchange<'a>),
    Finished(Finished<'a>),
    Unknown(u8),
    Fragment(&'a [u8]),
}

impl<'a> Default for Body<'a> {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl<'a> Body<'a> {
    pub fn is_fragment(&self) -> bool {
        matches!(self, Body::Fragment(_))
    }

    pub fn parse(
        input: &'a [u8],
        m: MessageType,
        c: Option<CipherSuite>,
    ) -> IResult<&'a [u8], Body<'a>> {
        match m {
            MessageType::HelloRequest => Ok((input, Body::HelloRequest)),
            MessageType::ClientHello => {
                let (input, client_hello) = ClientHello::parse(input)?;
                Ok((input, Body::ClientHello(client_hello)))
            }
            MessageType::HelloVerifyRequest => {
                let (input, hello_verify_request) = HelloVerifyRequest::parse(input)?;
                Ok((input, Body::HelloVerifyRequest(hello_verify_request)))
            }
            MessageType::ServerHello => {
                let (input, server_hello) = ServerHello::parse(input)?;
                Ok((input, Body::ServerHello(server_hello)))
            }
            MessageType::Certificate => {
                let (input, certificate) = Certificate::parse(input)?;
                Ok((input, Body::Certificate(certificate)))
            }
            MessageType::ServerKeyExchange => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let algo = cipher_suite.as_key_exchange_algorithm();
                let (input, server_key_exchange) = ServerKeyExchange::parse(input, algo)?;
                Ok((input, Body::ServerKeyExchange(server_key_exchange)))
            }
            MessageType::CertificateRequest => {
                let (input, certificate_request) = CertificateRequest::parse(input)?;
                Ok((input, Body::CertificateRequest(certificate_request)))
            }
            MessageType::ServerHelloDone => Ok((input, Body::ServerHelloDone)),
            MessageType::CertificateVerify => {
                let (input, certificate_verify) = CertificateVerify::parse(input)?;
                Ok((input, Body::CertificateVerify(certificate_verify)))
            }
            MessageType::ClientKeyExchange => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let algo = cipher_suite.as_key_exchange_algorithm();
                let (input, client_key_exchange) = ClientKeyExchange::parse(input, algo)?;
                Ok((input, Body::ClientKeyExchange(client_key_exchange)))
            }
            MessageType::Finished => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let (input, finished) = Finished::parse(input, cipher_suite)?;
                Ok((input, Body::Finished(finished)))
            }
            MessageType::Unknown(value) => Ok((input, Body::Unknown(value))),
        }
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        match self {
            Body::HelloRequest => {
                // Serialize HelloRequest (empty)
            }
            Body::ClientHello(client_hello) => {
                client_hello.serialize(output);
            }
            Body::HelloVerifyRequest(hello_verify_request) => {
                hello_verify_request.serialize(output);
            }
            Body::ServerHello(server_hello) => {
                server_hello.serialize(output);
            }
            Body::Certificate(certificate) => {
                certificate.serialize(output);
            }
            Body::ServerKeyExchange(server_key_exchange) => {
                server_key_exchange.serialize(output);
            }
            Body::CertificateRequest(certificate_request) => {
                certificate_request.serialize(output);
            }
            Body::ServerHelloDone => {
                // Serialize ServerHelloDone (empty)
            }
            Body::CertificateVerify(certificate_verify) => {
                certificate_verify.serialize(output);
            }
            Body::ClientKeyExchange(client_key_exchange) => {
                client_key_exchange.serialize(output);
            }
            Body::Finished(finished) => {
                finished.serialize(output);
            }
            Body::Unknown(value) => {
                output.push(*value);
            }
            Body::Fragment(value) => {
                output.extend_from_slice(value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tinyvec::array_vec;

    use super::*;
    use crate::message::{
        CipherSuite, ClientHello, CompressionMethod, Cookie, ProtocolVersion, Random, SessionId,
    };

    const MESSAGE: &[u8] = &[
        0x01, // MessageType::ClientHello
        0x00, 0x00, 0x2E, // length
        0x00, 0x00, // message_seq
        0x00, 0x00, 0x00, // fragment_offset
        0x00, 0x00, 0x2E, // fragment_length
        // ClientHello
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
    fn handshake_size() {
        let h = Handshake::new(
            // ServerHelloDone has a 0 sized body.
            MessageType::ServerHelloDone,
            0,
            0,
            0,
            0,
            Body::ServerHelloDone,
        );

        let mut v = Vec::new();
        h.serialize(&mut v);

        assert_eq!(v.len(), 12);
    }

    #[test]
    fn roundtrip() {
        let mut serialized = Vec::new();

        let random = Random::parse(&MESSAGE[14..46]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cookie = Cookie::try_new(&[0xBB]).unwrap();
        let cipher_suites = array_vec![
            CipherSuite::ECDHE_RSA_AES128_GCM_SHA256,
            CipherSuite::ECDHE_RSA_AES256_GCM_SHA384
        ];
        let compression_methods = array_vec![[CompressionMethod; 4] => CompressionMethod::Null];

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
            0,
            0,
            0x2E,
            Body::ClientHello(client_hello),
        );

        // Serialize and compare to MESSAGE
        handshake.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Handshake::parse(&serialized, None, false).unwrap();
        assert_eq!(parsed, handshake);

        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_fragment() {
        let mut serialized = Vec::new();
        let mut buffer = Vec::new();

        let random = Random::parse(&MESSAGE[14..46]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cookie = Cookie::try_new(&[0xBB]).unwrap();
        let cipher_suites = array_vec![
            CipherSuite::ECDHE_RSA_AES128_GCM_SHA256,
            CipherSuite::ECDHE_RSA_AES256_GCM_SHA384
        ];
        let compression_methods = array_vec![[CompressionMethod; 4] => CompressionMethod::Null];

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
            46,
            0,
            0,
            46,
            Body::ClientHello(client_hello),
        );

        // Fragment the handshake with size 10
        let mut fragments: VecDeque<_> = handshake.fragment(10, &mut buffer).collect();

        // Defragment the fragments
        let mut defragmented_buffer = Vec::new();
        let (defragmented_handshake, _next_type) =
            Handshake::defragment(fragments.iter(), &mut defragmented_buffer, None).unwrap();

        // Serialize and compare to MESSAGE
        defragmented_handshake.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Handshake::parse(&serialized, None, false).unwrap();
        assert_eq!(parsed, handshake);

        assert!(rest.is_empty());
    }
}
