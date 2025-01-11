use super::Message;
use super::{Certificate, CertificateVerify, ChangeCipherSpec, ClientHello};
use super::{ClientKeyExchange, Finished, NewSessionTicket, ServerHello, ServerKeyExchange};

#[derive(Debug)]
pub struct Handshake {
    pub message: Message,
    pub length: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_length: u32,
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
            0x16 => {
                let (consumed, msg) = NewSessionTicket::parse(data)?;
                (consumed, Message::NewSessionTicket(msg))
            }
            _ => return None,
        };

        Some((
            12 + consumed,
            Handshake {
                message,
                length,
                message_seq,
                fragment_offset,
                fragment_length,
            },
        ))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.push(match &self.message {
            Message::ClientHello(_) => 0x01,
            Message::ServerHello(_) => 0x02,
            Message::Certificate(_) => 0x0B,
            Message::ServerKeyExchange(_) => 0x0C,
            Message::CertificateVerify(_) => 0x0F,
            Message::ClientKeyExchange(_) => 0x10,
            Message::Finished(_) => 0x14,
            Message::ChangeCipherSpec(_) => 0x15,
            Message::NewSessionTicket(_) => 0x16,
        });

        data.extend_from_slice(&self.length.to_be_bytes()[1..]);
        data.extend_from_slice(&self.message_seq.to_be_bytes());
        data.extend_from_slice(&self.fragment_offset.to_be_bytes()[1..]);
        data.extend_from_slice(&self.fragment_length.to_be_bytes()[1..]);

        match &self.message {
            Message::ClientHello(msg) => msg.serialize(data),
            Message::ServerHello(msg) => msg.serialize(data),
            Message::Certificate(msg) => msg.serialize(data),
            Message::ServerKeyExchange(msg) => msg.serialize(data),
            Message::CertificateVerify(msg) => msg.serialize(data),
            Message::ClientKeyExchange(msg) => msg.serialize(data),
            Message::Finished(msg) => msg.serialize(data),
            Message::ChangeCipherSpec(msg) => msg.serialize(data),
            Message::NewSessionTicket(msg) => msg.serialize(data),
        }
    }
}
