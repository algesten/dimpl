use smallvec::SmallVec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    Rsa,
    Dhe,
    Ecdhe,
    // Add other algorithms as needed
}

#[derive(Debug)]
pub struct ServerKeyExchange {
    pub algorithm: KeyExchangeAlgorithm,
    pub exchange_keys: SmallVec<[u8; 256]>,
}

impl ServerKeyExchange {
    pub fn parse(data: &[u8]) -> Option<(usize, ServerKeyExchange)> {
        if data.len() < 3 {
            return None;
        }

        let algorithm = match data[0] {
            0x00 => KeyExchangeAlgorithm::Rsa,
            0x01 => KeyExchangeAlgorithm::Dhe,
            0x02 => KeyExchangeAlgorithm::Ecdhe,
            // Add other algorithms as needed
            _ => return None,
        };

        let key_len = u16::from_be_bytes([data[1], data[2]]) as usize;
        let data = &data[3..];

        if data.len() < key_len {
            return None;
        }

        let exchange_keys = SmallVec::from_slice(&data[..key_len]);

        Some((
            3 + key_len,
            ServerKeyExchange {
                algorithm,
                exchange_keys,
            },
        ))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        let algorithm_byte = match self.algorithm {
            KeyExchangeAlgorithm::Rsa => 0x00,
            KeyExchangeAlgorithm::Dhe => 0x01,
            KeyExchangeAlgorithm::Ecdhe => 0x02,
            // Add other algorithms as needed
        };

        data.push(algorithm_byte);
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
            0x00, // algorithm (Rsa)
            0x00, 0x04, // key_len
            0x01, 0x02, 0x03, 0x04, // exchange_keys
        ];

        let server_key_exchange = ServerKeyExchange::parse(&data).unwrap();
        assert_eq!(server_key_exchange.1.algorithm, KeyExchangeAlgorithm::Rsa);
        assert_eq!(
            server_key_exchange.1.exchange_keys.as_ref(),
            &[0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn parse_invalid_server_key_exchange() {
        let data = [
            0x00, // algorithm (Rsa)
            0x00, 0x04, // key_len
            0x01, 0x02, 0x03, // incomplete exchange_keys
        ];

        let server_key_exchange = ServerKeyExchange::parse(&data);
        assert!(server_key_exchange.is_none());
    }
}
