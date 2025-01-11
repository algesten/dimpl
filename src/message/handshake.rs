use super::Message;
use super::{Certificate, CertificateVerify, ChangeCipherSpec, ClientHello};
use super::{ClientKeyExchange, Finished, ServerHello, ServerKeyExchange};

#[derive(Debug)]
pub struct Handshake {
    pub message_type: u8,
    pub length: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_length: u32,
    pub message: Message,
}

impl Handshake {
    pub fn parse(data: &[u8]) -> Option<(usize, Handshake)> {
        if data.len() < 12 {
            return None;
        }

        let message_type = data[0];
        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let message_seq = u16::from_be_bytes([data[4], data[5]]);
        let fragment_offset = u32::from_be_bytes([0, data[6], data[7], data[8]]);
        let fragment_length = u32::from_be_bytes([0, data[9], data[10], data[11]]);
        let data = &data[12..];

        if fragment_offset > 0 || (fragment_offset == 0 && fragment_length < length) {
            return Some((
                12 + data.len(),
                Handshake {
                    message_type,
                    length,
                    message_seq,
                    fragment_offset,
                    fragment_length,
                    message: Message::Fragment(data.to_vec()),
                },
            ));
        }

        if data.len() < fragment_length as usize {
            return None;
        }

        let (consumed, message) = match message_type {
            0x01 => {
                let (consumed, msg) = ClientHello::parse(data)?;
                (consumed, Message::ClientHello(msg))
            }
            0x02 => {
                let (consumed, msg) = ServerHello::parse(data)?;
                (consumed, Message::ServerHello(msg))
            }
            0x0B => {
                let (consumed, msg) = Certificate::parse(data)?;
                (consumed, Message::Certificate(msg))
            }
            0x0C => {
                let (consumed, msg) = ServerKeyExchange::parse(data)?;
                (consumed, Message::ServerKeyExchange(msg))
            }
            0x0F => {
                let (consumed, msg) = CertificateVerify::parse(data)?;
                (consumed, Message::CertificateVerify(msg))
            }
            0x10 => {
                let (consumed, msg) = ClientKeyExchange::parse(data)?;
                (consumed, Message::ClientKeyExchange(msg))
            }
            0x14 => {
                let (consumed, msg) = Finished::parse(data)?;
                (consumed, Message::Finished(msg))
            }
            0x15 => {
                let (consumed, msg) = ChangeCipherSpec::parse(data)?;
                (consumed, Message::ChangeCipherSpec(msg))
            }
            _ => return None,
        };

        Some((
            12 + consumed,
            Handshake {
                message_type,
                message,
                length,
                message_seq,
                fragment_offset,
                fragment_length,
            },
        ))
    }

    pub fn is_fragment(&self) -> bool {
        matches!(self.message, Message::Fragment(_))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.push(self.message_type);

        data.extend_from_slice(&self.length.to_be_bytes()[1..]);
        data.extend_from_slice(&self.message_seq.to_be_bytes());
        data.extend_from_slice(&self.fragment_offset.to_be_bytes()[1..]);
        data.extend_from_slice(&self.fragment_length.to_be_bytes()[1..]);

        self.message.serialize(data);
    }

    pub fn defragment(fragments: &[Handshake]) -> Option<Handshake> {
        if fragments.is_empty() {
            return None;
        }

        let message_seq = fragments[0].message_seq;
        let length = fragments[0].length;
        let message_type = fragments[0].message_type;

        // Verify that all fragments have the same message_seq, length, and message_type
        for fragment in fragments {
            if fragment.message_seq != message_seq
                || fragment.length != length
                || fragment.message_type != message_type
            {
                return None;
            }
        }

        // Combine data
        let mut merged = vec![0; 12 + length as usize];
        merged[0] = message_type;
        merged[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
        merged[4..6].copy_from_slice(&message_seq.to_be_bytes());
        merged[6..9].copy_from_slice(&fragments[0].fragment_offset.to_be_bytes()[1..]);
        merged[9..12].copy_from_slice(&fragments[0].fragment_length.to_be_bytes()[1..]);

        for fragment in fragments {
            let start = 12 + fragment.fragment_offset as usize;
            let end = start + fragment.fragment_length as usize;
            if let Message::Fragment(ref data) = fragment.message {
                merged[start..end].copy_from_slice(data);
            } else {
                return None;
            }
        }

        // Parse combined data
        Handshake::parse(&merged).map(|(_, handshake)| handshake)
    }

    pub fn fragment(&self, max: usize) -> Vec<Handshake> {
        if let Message::Fragment(_) = self.message {
            panic!("Cannot fragment a Fragment message");
        }

        let mut fragments = Vec::new();
        let mut offset = 0;
        let mut serialized = vec![];
        self.serialize(&mut serialized);
        let data = &serialized[12..];

        while offset < data.len() {
            let fragment_length = max.min(data.len() - offset);
            let fragment_data = data[offset..offset + fragment_length].to_vec();

            fragments.push(Handshake {
                message_type: self.message_type,
                length: self.length,
                message_seq: self.message_seq,
                fragment_offset: offset as u32,
                fragment_length: fragment_length as u32,
                message: Message::Fragment(fragment_data),
            });

            offset += fragment_length;
        }

        fragments
    }
}
