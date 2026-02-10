use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{Certificate, CertificateVerify, ClientHello, Dtls13CipherSuite};
use super::{EncryptedExtensions, Finished, ServerHello};
use crate::buffer::Buf;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::be_u8;
use nom::number::complete::{be_u16, be_u24};
use nom::Err;
use nom::IResult;

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
        c: Option<Dtls13CipherSuite>,
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
        cipher_suite: Option<Dtls13CipherSuite>,
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

        let mut assembled_end =
            first_handshake.header.fragment_offset + first_handshake.header.fragment_length;

        for (handshake, source_buf) in iter {
            if handshake.header.msg_type != first_handshake.header.msg_type {
                break;
            }

            let Body::Fragment(range) = &handshake.body else {
                unreachable!("Non-Fragment body in defragment()")
            };

            handshake.handled.store(true, Ordering::Relaxed);

            // Handle overlapping fragment data: skip bytes already assembled
            let frag_start = handshake.header.fragment_offset as usize;
            let frag_len = handshake.header.fragment_length as usize;
            let skip = (assembled_end as usize).saturating_sub(frag_start);
            if skip < frag_len {
                buffer.extend_from_slice(&source_buf[range.start + skip..range.end]);
            }
            let end = handshake.header.fragment_offset + handshake.header.fragment_length;
            if end > assembled_end {
                assembled_end = end;
            }
        }

        if buffer.len() != first_handshake.header.length as usize {
            debug!("Defragmentation failed. Fragment length mismatch");
            return Err(crate::Error::ParseIncomplete);
        }

        // If transcript is provided, write the TLS 1.3-style header + body.
        // Per RFC 9147 Section 5.2, the transcript uses msg_type(1) + length(3)
        // WITHOUT the DTLS-specific message_seq, fragment_offset, fragment_length.
        if let Some(transcript) = transcript {
            transcript.push(first_handshake.header.msg_type.as_u8());
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
            MessageType::ClientHello // flight 1
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
    KeyUpdate(KeyUpdateRequest),
    Unknown(u8),
    Fragment(Range<usize>),
}

/// RFC 8446 Section 4.6.3 KeyUpdate request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateRequest {
    /// Peer does not need to respond with its own KeyUpdate.
    UpdateNotRequested = 0,
    /// Peer MUST respond with its own KeyUpdate (update_not_requested).
    UpdateRequested = 1,
}

impl KeyUpdateRequest {
    /// Parse from a single byte.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(KeyUpdateRequest::UpdateNotRequested),
            1 => Some(KeyUpdateRequest::UpdateRequested),
            _ => None,
        }
    }

    /// Serialize to a single byte.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
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
                let (input, byte) = be_u8(input)?;
                let request = KeyUpdateRequest::from_u8(byte)
                    .ok_or_else(|| Err::Failure(Error::new(input, ErrorKind::Fail)))?;
                Ok((input, Body::KeyUpdate(request)))
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
            Body::KeyUpdate(request) => {
                output.push(request.as_u8());
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

    use super::*;
    use crate::buffer::Buf;
    use crate::dtls13::message::{CompressionMethod, Cookie, Dtls13CipherSuite};
    use crate::dtls13::message::{ProtocolVersion, Random, SessionId};

    const MESSAGE: &[u8] = &[
        0x01, // MessageType::ClientHello
        0x00, 0x00, 0x2E, // length
        0x00, 0x00, // message_seq
        0x00, 0x00, 0x00, // fragment_offset
        0x00, 0x00, 0x2E, // fragment_length
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
        let h = Handshake::new(
            MessageType::EncryptedExtensions,
            2,
            0,
            0,
            2,
            Body::EncryptedExtensions(EncryptedExtensions {
                extensions: ArrayVec::new(),
            }),
        );

        let mut v = Buf::new();
        h.serialize(&[], &mut v);

        // 12 bytes header + 2 bytes (empty extensions length)
        assert_eq!(v.len(), 14);
    }

    #[test]
    fn roundtrip() {
        let mut serialized = Buf::new();

        let random = Random::parse(&MESSAGE[14..46]).unwrap().1;
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
}
