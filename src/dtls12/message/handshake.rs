use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{
    Certificate, CertificateRequest, CertificateVerify, ClientHello, ClientKeyExchange,
    Dtls12CipherSuite, Finished, HelloVerifyRequest, ServerHello, ServerKeyExchange,
};
use crate::buffer::Buf;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u8;
use nom::Err;
use nom::{
    number::complete::{be_u16, be_u24},
    IResult,
};

#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct Header {
    pub msg_type: MessageType,
    pub length: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_length: u32,
}

#[derive(Debug, Default)]
pub struct Handshake {
    pub header: Header,
    pub body: Body,
    pub handled: AtomicBool,
}

impl PartialEq for Handshake {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.body == other.body
            && self.handled.load(Ordering::Relaxed) == other.handled.load(Ordering::Relaxed)
    }
}

impl Eq for Handshake {}

impl Handshake {
    #[cfg(test)]
    pub fn new(
        msg_type: MessageType,
        length: u32,
        message_seq: u16,
        fragment_offset: u32,
        fragment_length: u32,
        body: Body,
    ) -> Self {
        Handshake {
            header: Header {
                msg_type,
                length,
                message_seq,
                fragment_offset,
                fragment_length,
            },
            body,
            handled: AtomicBool::new(false),
        }
    }

    pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
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
        input: &[u8],
        base_offset: usize,
        c: Option<Dtls12CipherSuite>,
        as_fragment: bool,
    ) -> IResult<&[u8], Handshake> {
        let original_input = input;
        let (input, header) = Self::parse_header(input)?;

        let is_fragment = header.fragment_offset > 0 || header.fragment_length < header.length;

        if !as_fragment && is_fragment {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }

        let (input, body) = if as_fragment {
            let (input, fragment_slice) = take(header.fragment_length as usize)(input)?;
            // Calculate range relative to original input
            let relative_offset =
                fragment_slice.as_ptr() as usize - original_input.as_ptr() as usize;
            let start = base_offset + relative_offset;
            let end = start + fragment_slice.len();
            (input, Body::Fragment(start..end))
        } else {
            let (input, body_bytes) = take(header.length as usize)(input)?;
            // Calculate base_offset for body parsing
            let consumed = body_bytes.as_ptr() as usize - original_input.as_ptr() as usize;
            let body_base_offset = base_offset + consumed;
            let (_, body) = Body::parse(body_bytes, body_base_offset, header.msg_type, c)?;
            (input, body)
        };

        Ok((
            input,
            Handshake {
                header,
                body,
                handled: AtomicBool::new(false),
            },
        ))
    }

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        output.push(self.header.msg_type.as_u8());
        output.extend_from_slice(&self.header.length.to_be_bytes()[1..]);
        output.extend_from_slice(&self.header.message_seq.to_be_bytes());
        output.extend_from_slice(&self.header.fragment_offset.to_be_bytes()[1..]);
        output.extend_from_slice(&self.header.fragment_length.to_be_bytes()[1..]);
        self.body.serialize(source_buf, output);
    }

    #[allow(private_interfaces)]
    pub fn defragment<'b>(
        mut iter: impl Iterator<Item = (&'b Handshake, &'b [u8])>,
        buffer: &mut Buf,
        cipher_suite: Option<Dtls12CipherSuite>,
        transcript: Option<&mut Buf>,
    ) -> Result<Handshake, crate::Error> {
        buffer.clear();

        // Invariant is upheld by the caller.
        let (first_handshake, first_buffer) = iter.next().unwrap();

        let Body::Fragment(range) = &first_handshake.body else {
            unreachable!("Non-Fragment body in defragment()")
        };
        buffer.extend_from_slice(&first_buffer[range.clone()]);
        first_handshake.set_handled();

        for (handshake, source_buf) in iter {
            if handshake.header.msg_type != first_handshake.header.msg_type {
                break;
            }

            let Body::Fragment(range) = &handshake.body else {
                unreachable!("Non-Fragment body in defragment()")
            };

            handshake.handled.store(true, Ordering::Relaxed);

            buffer.extend_from_slice(&source_buf[range.clone()]);
        }

        if buffer.len() != first_handshake.header.length as usize {
            debug!("Defragmentation failed. Fragment length mismatch");
            return Err(crate::Error::ParseIncomplete);
        }

        // If transcript is provided, write the handshake header + body before parsing
        if let Some(transcript) = transcript {
            transcript.push(first_handshake.header.msg_type.as_u8());
            transcript.extend_from_slice(&first_handshake.header.length.to_be_bytes()[1..]);
            transcript.extend_from_slice(&first_handshake.header.message_seq.to_be_bytes());
            // Defragmented handshake has fragment_offset=0 and fragment_length=length
            transcript.extend_from_slice(&0u32.to_be_bytes()[1..]);
            transcript.extend_from_slice(&first_handshake.header.length.to_be_bytes()[1..]);
            transcript.extend_from_slice(&buffer[..first_handshake.header.length as usize]);
        }

        let (rest, body) = Body::parse(buffer, 0, first_handshake.header.msg_type, cipher_suite)?;

        if !rest.is_empty() && first_handshake.header.msg_type == MessageType::Finished {
            debug!("Defragmentation failed. Body::parse() did not consume the entire buffer");
            return Err(crate::Error::ParseIncomplete);
        }

        let handshake = Handshake {
            header: Header {
                msg_type: first_handshake.header.msg_type,
                length: first_handshake.header.length,
                message_seq: first_handshake.header.message_seq,
                fragment_offset: 0,
                fragment_length: first_handshake.header.length,
            },
            body,
            handled: AtomicBool::new(false),
        };

        // Create a new Handshake with the merged body
        Ok(handshake)
    }

    #[cfg(test)]
    fn do_clone(&self) -> Handshake {
        Handshake {
            header: Header {
                msg_type: self.header.msg_type,
                length: self.header.length,
                message_seq: self.header.message_seq,
                fragment_offset: self.header.fragment_offset,
                fragment_length: self.header.fragment_length,
            },
            body: Body::HelloRequest, // Placeholder
            handled: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub fn fragment<'b>(
        &self,
        max: usize,
        buffer: &'b mut Buf,
    ) -> impl Iterator<Item = Handshake> + 'b {
        // Must be called with an empty buffer.
        assert!(buffer.is_empty());

        // Note: For fragmentize, self is already serialized data in Body::Fragment
        // which doesn't need source_buf, so we pass an empty slice
        self.body.serialize(&[], buffer);

        // If this is wrong, the serialize has not produced the same output as we parsed.
        assert_eq!(buffer.len(), self.header.length as usize);

        let to_clone = self.do_clone();

        buffer.chunks(max).enumerate().map(move |(i, chunk)| {
            let fragment_length = chunk.len() as u32;
            let offset = i * max;
            let fragment_range = offset..(offset + chunk.len());

            let mut fragment = to_clone.do_clone();
            fragment.header.fragment_offset = offset as u32;
            fragment.header.fragment_length = fragment_length;
            fragment.header.message_seq = to_clone.header.message_seq + i as u16;
            fragment.body = Body::Fragment(fragment_range);

            fragment
        })
    }

    // These are (unencrypted) handshakes that, when detected as
    // duplicates, trigger a resend of the entire flight.
    pub fn dupe_triggers_resend(&self) -> Option<u16> {
        // Only trigger on the first fragment of a handshake message to avoid
        // multiple resends caused by fragmented duplicates of the same message.
        if self.header.fragment_offset != 0 {
            return None;
        }

        let qualifies = matches!(
            self.header.msg_type,
            MessageType::ClientHello |        // flight 1 and 3
            MessageType::HelloVerifyRequest | // flight 2
            MessageType::ServerHelloDone |    // flight 4
            MessageType::ClientKeyExchange // flight 5
        );

        qualifies.then_some(self.header.message_seq)
    }

    pub fn is_handled(&self) -> bool {
        self.handled.load(Ordering::Relaxed)
    }

    pub fn set_handled(&self) {
        self.handled.store(true, Ordering::Relaxed);
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
    NewSessionTicket,
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
            4 => MessageType::NewSessionTicket,
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
            MessageType::NewSessionTicket => 4,
            MessageType::Finished => 20,
            MessageType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], MessageType> {
        let (input, byte) = be_u8(input)?;
        Ok((input, Self::from_u8(byte)))
    }

    pub fn epoch(&self) -> u16 {
        if matches!(self, MessageType::NewSessionTicket | MessageType::Finished) {
            1
        } else {
            0
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Body {
    HelloRequest, // empty
    ClientHello(ClientHello),
    HelloVerifyRequest(HelloVerifyRequest),
    ServerHello(ServerHello),
    Certificate(Certificate),
    ServerKeyExchange(ServerKeyExchange),
    CertificateRequest(CertificateRequest),
    ServerHelloDone, // empty
    CertificateVerify(CertificateVerify),
    ClientKeyExchange(ClientKeyExchange),
    NewSessionTicket(Range<usize>),
    Finished(Finished),
    Unknown(u8),
    Fragment(Range<usize>),
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
        c: Option<Dtls12CipherSuite>,
    ) -> IResult<&[u8], Body> {
        match m {
            MessageType::HelloRequest => Ok((input, Body::HelloRequest)),
            MessageType::ClientHello => {
                let (input, client_hello) = ClientHello::parse(input, base_offset)?;
                Ok((input, Body::ClientHello(client_hello)))
            }
            MessageType::HelloVerifyRequest => {
                let (input, hello_verify_request) = HelloVerifyRequest::parse(input)?;
                Ok((input, Body::HelloVerifyRequest(hello_verify_request)))
            }
            MessageType::ServerHello => {
                let (input, server_hello) = ServerHello::parse(input, base_offset)?;
                Ok((input, Body::ServerHello(server_hello)))
            }
            MessageType::Certificate => {
                let (input, certificate) = Certificate::parse(input, base_offset)?;
                Ok((input, Body::Certificate(certificate)))
            }
            MessageType::ServerKeyExchange => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let algo = cipher_suite.as_key_exchange_algorithm();
                let (input, server_key_exchange) =
                    ServerKeyExchange::parse(input, base_offset, algo)?;
                Ok((input, Body::ServerKeyExchange(server_key_exchange)))
            }
            MessageType::CertificateRequest => {
                let (input, certificate_request) = CertificateRequest::parse(input, base_offset)?;
                Ok((input, Body::CertificateRequest(certificate_request)))
            }
            MessageType::ServerHelloDone => Ok((input, Body::ServerHelloDone)),
            MessageType::CertificateVerify => {
                let (input, certificate_verify) = CertificateVerify::parse(input, base_offset)?;
                Ok((input, Body::CertificateVerify(certificate_verify)))
            }
            MessageType::ClientKeyExchange => {
                let cipher_suite =
                    c.ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                let algo = cipher_suite.as_key_exchange_algorithm();
                let (input, client_key_exchange) =
                    ClientKeyExchange::parse(input, base_offset, algo)?;
                Ok((input, Body::ClientKeyExchange(client_key_exchange)))
            }
            MessageType::NewSessionTicket => {
                // Treat ticket as opaque per RFC 5077: lifetime_hint(4) + ticket (opaque vector)
                let range = base_offset..(base_offset + input.len());
                Ok((&[], Body::NewSessionTicket(range)))
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

    pub fn serialize(&self, source_buf: &[u8], output: &mut Buf) {
        match self {
            Body::HelloRequest => {
                // Serialize HelloRequest (empty)
            }
            Body::ClientHello(client_hello) => {
                client_hello.serialize(source_buf, output);
            }
            Body::HelloVerifyRequest(hello_verify_request) => {
                hello_verify_request.serialize(output);
            }
            Body::ServerHello(server_hello) => {
                server_hello.serialize(source_buf, output);
            }
            Body::Certificate(certificate) => {
                certificate.serialize(source_buf, output);
            }
            Body::ServerKeyExchange(server_key_exchange) => {
                server_key_exchange.serialize(source_buf, output, true);
            }
            Body::CertificateRequest(certificate_request) => {
                certificate_request.serialize(source_buf, output);
            }
            Body::ServerHelloDone => {
                // Serialize ServerHelloDone (empty)
            }
            Body::CertificateVerify(certificate_verify) => {
                certificate_verify.serialize(source_buf, output);
            }
            Body::ClientKeyExchange(client_key_exchange) => {
                client_key_exchange.serialize(source_buf, output);
            }
            Body::NewSessionTicket(range) => {
                output.extend_from_slice(&source_buf[range.clone()]);
            }
            Body::Finished(finished) => {
                finished.serialize(source_buf, output);
            }
            Body::Unknown(value) => {
                output.push(*value);
            }
            Body::Fragment(range) => {
                output.extend_from_slice(&source_buf[range.clone()]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use arrayvec::ArrayVec;
    use std::collections::VecDeque;

    use super::*;
    use crate::buffer::Buf;
    use crate::dtls12::message::{
        CompressionMethod, Cookie, Dtls12CipherSuite, ProtocolVersion, Random, SessionId,
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
        0x00, 0x04, // Dtls12CipherSuites length
        0xC0, 0x2B, // Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
        0xC0, 0x2C, // Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
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

        let mut v = Buf::new();
        h.serialize(&[], &mut v);

        assert_eq!(v.len(), 12);
    }

    #[test]
    fn roundtrip() {
        let mut serialized = Buf::new();

        let random = Random::parse(&MESSAGE[14..46]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cookie = Cookie::try_new(&[0xBB]).unwrap();
        let mut cipher_suites = ArrayVec::new();
        cipher_suites.push(Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256);
        cipher_suites.push(Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384);
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
            0,
            0,
            0x2E,
            Body::ClientHello(client_hello),
        );

        // Serialize and compare to MESSAGE
        handshake.serialize(&[], &mut serialized);
        assert_eq!(&*serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Handshake::parse(&serialized, 0, None, false).unwrap();
        assert_eq!(parsed, handshake);

        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_fragment() {
        let mut serialized = Buf::new();
        let mut buffer = Buf::new();

        let random = Random::parse(&MESSAGE[14..46]).unwrap().1;
        let session_id = SessionId::try_new(&[0xAA]).unwrap();
        let cookie = Cookie::try_new(&[0xBB]).unwrap();
        let mut cipher_suites = ArrayVec::new();
        cipher_suites.push(Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256);
        cipher_suites.push(Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384);
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
            46,
            0,
            0,
            46,
            Body::ClientHello(client_hello),
        );

        // Fragment the handshake with size 10
        let fragments: VecDeque<_> = handshake.fragment(10, &mut buffer).collect();

        // Defragment the fragments
        let mut defragmented_buffer = Buf::new();
        let defragmented_handshake = Handshake::defragment(
            fragments.iter().map(|h| (h, &buffer[..])),
            &mut defragmented_buffer,
            None,
            None,
        )
        .unwrap();

        // Serialize and compare to MESSAGE
        // Save header info and drop handshake to release buffer borrow
        let header = defragmented_handshake.header.clone();
        drop(defragmented_handshake);

        serialized.push(header.msg_type.as_u8());
        serialized.extend_from_slice(&header.length.to_be_bytes()[1..]);
        serialized.extend_from_slice(&header.message_seq.to_be_bytes());
        serialized.extend_from_slice(&header.fragment_offset.to_be_bytes()[1..]);
        serialized.extend_from_slice(&header.fragment_length.to_be_bytes()[1..]);
        serialized.extend_from_slice(&defragmented_buffer[..header.length as usize]);
        assert_eq!(&*serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Handshake::parse(&serialized, 0, None, false).unwrap();
        assert_eq!(parsed, handshake);

        assert!(rest.is_empty());
    }
}
