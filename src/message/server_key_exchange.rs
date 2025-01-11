use smallvec::SmallVec;

#[derive(Debug)]
pub struct ServerKeyExchange {
    pub exchange_keys: SmallVec<[u8; 256]>,
}

impl ServerKeyExchange {
    pub fn parse(data: &[u8]) -> Option<(usize, ServerKeyExchange)> {
        if data.len() < 2 {
            return None;
        }

        let key_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = &data[2..];

        if data.len() < key_len {
            return None;
        }

        let exchange_keys = SmallVec::from_slice(&data[..key_len]);

        Some((2 + key_len, ServerKeyExchange { exchange_keys }))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&(self.exchange_keys.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.exchange_keys);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_server_key_exchange() {
        let data = [
            0x00, 0x04, // key_len
            0x01, 0x02, 0x03, 0x04, // exchange_keys
        ];

        let server_key_exchange = ServerKeyExchange::parse(&data).unwrap();
        assert_eq!(
            server_key_exchange.1.exchange_keys.as_ref(),
            &[0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn parse_invalid_server_key_exchange() {
        let data = [
            0x00, 0x04, // key_len
            0x01, 0x02, 0x03, // incomplete exchange_keys
        ];

        let server_key_exchange = ServerKeyExchange::parse(&data);
        assert!(server_key_exchange.is_none());
    }
}
