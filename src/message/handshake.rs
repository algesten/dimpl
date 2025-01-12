use super::{CipherSuite, Message, MessageType};
use nom::bytes::complete::take;
use nom::{
    number::complete::{be_u16, be_u24},
    IResult,
};

#[derive(Debug, PartialEq, Eq)]
pub struct Handshake<'a> {
    pub msg_type: MessageType,
    pub length: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_length: u32,
    pub body: Message<'a>,
}

impl<'a> Handshake<'a> {
    pub fn new(
        msg_type: MessageType,
        length: u32,
        message_seq: u16,
        fragment_offset: u32,
        fragment_length: u32,
        body: Message<'a>,
    ) -> Self {
        Handshake {
            msg_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
            body,
        }
    }

    pub fn is_fragment(&self) -> bool {
        matches!(self.body, Message::Fragment(_))
    }

    pub fn parse(input: &'a [u8], c: Option<CipherSuite>) -> IResult<&[u8], Handshake<'a>> {
        let (input, msg_type) = MessageType::parse(input)?;
        let (input, length) = be_u24(input)?;
        let (input, message_seq) = be_u16(input)?;
        let (input, fragment_offset) = be_u24(input)?;
        let (input, fragment_length) = be_u24(input)?;

        let is_fragment = fragment_offset > 0 || fragment_length < length;

        let (input, body) = if is_fragment {
            let (input, fragment) = take(fragment_length as usize)(input)?;
            (input, Message::Fragment(fragment))
        } else {
            Message::parse(input, msg_type, c)?
        };

        Ok((
            input,
            Handshake {
                msg_type,
                length,
                message_seq,
                fragment_offset,
                fragment_length,
                body,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.push(self.msg_type.to_u8());
        output.extend_from_slice(&(self.length as u32).to_be_bytes()[1..]);
        output.extend_from_slice(&self.message_seq.to_be_bytes());
        output.extend_from_slice(&(self.fragment_offset as u32).to_be_bytes()[1..]);
        output.extend_from_slice(&(self.fragment_length as u32).to_be_bytes()[1..]);
        self.body.serialize(output);
    }

    pub fn defragment(fragments: &[&Handshake], buffer: &'a mut Vec<u8>) -> Option<Handshake<'a>> {
        if fragments.is_empty() {
            return None;
        }

        let first = fragments[0];

        let mut expected_offset = 0;
        let mut i = 0;

        while i < fragments.len() {
            let f = fragments[i];
            if f.fragment_offset == expected_offset {
                buffer.extend_from_slice(match &f.body {
                    Message::Fragment(data) => data,
                    _ => return None,
                });
                expected_offset += f.fragment_length;
                i += 1;
            } else {
                // Start over if fragments are not in order
                i = 0;
            }
        }

        if expected_offset != first.length {
            // We do not have the entire message.
            return None;
        }

        // Create a new Handshake with the merged body
        Some(Handshake {
            msg_type: first.msg_type,
            length: first.length,
            message_seq: first.message_seq,
            fragment_offset: 0,
            fragment_length: first.length,
            body: Message::Fragment(buffer),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{
        CipherSuite, ClientHello, CompressionMethod, Cookie, ProtocolVersion, Random, SessionId,
    };
    use smallvec::smallvec;

    const MESSAGE: &[u8] = &[
        0x01, // MessageType::ClientHello
        0x00, 0x00, 0x3A, // length
        0x00, 0x00, // message_seq
        0x00, 0x00, 0x00, // fragment_offset
        0x00, 0x00, 0x3A, // fragment_length
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
    fn roundtrip() {
        let mut serialized = Vec::new();

        let random = Random::new(&MESSAGE[14..46]).unwrap();
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

        let handshake = Handshake::new(
            MessageType::ClientHello,
            0x3A,
            0,
            0,
            0x3A,
            Message::ClientHello(client_hello),
        );

        // Serialize and compare to MESSAGE
        handshake.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Handshake::parse(&serialized, None).unwrap();
        assert_eq!(parsed, handshake);

        assert!(rest.is_empty());
    }
}
