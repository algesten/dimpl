use smallvec::SmallVec;

#[derive(Debug)]
pub struct NewSessionTicket {
    pub ticket: SmallVec<[u8; 256]>,
}

impl NewSessionTicket {
    pub fn parse(data: &[u8]) -> Option<(usize, NewSessionTicket)> {
        if data.len() < 2 {
            return None;
        }

        let ticket_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = &data[2..];

        if data.len() < ticket_len {
            return None;
        }

        let ticket = SmallVec::from_slice(&data[..ticket_len]);

        Some((2 + ticket_len, NewSessionTicket { ticket }))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&(self.ticket.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.ticket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_new_session_ticket() {
        let data = [
            0x00, 0x04, // ticket_len
            0x01, 0x02, 0x03, 0x04, // ticket
        ];

        let new_session_ticket = NewSessionTicket::parse(&data).unwrap();
        assert_eq!(
            new_session_ticket.1.ticket.as_ref(),
            &[0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn parse_invalid_new_session_ticket() {
        let data = [
            0x00, 0x04, // ticket_len
            0x01, 0x02, 0x03, // incomplete ticket
        ];

        let new_session_ticket = NewSessionTicket::parse(&data);
        assert!(new_session_ticket.is_none());
    }
}
