use super::CipherSuite;
use smallvec::SmallVec;

#[derive(Debug)]
pub struct ServerHello {
    pub server_version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: SmallVec<[u8; 32]>,
    pub cipher_suite: CipherSuite,
    pub compression_method: u8,
}

impl ServerHello {
    pub fn parse(data: &[u8]) -> Option<(usize, ServerHello)> {
        if data.len() < 38 {
            return None;
        }

        let server_version = [data[0], data[1]];
        let data = &data[2..];

        let random: [u8; 32] = data[..32].try_into().unwrap();
        let data = &data[32..];

        let session_id_len = data[0] as usize;
        let data = &data[1..];
        if data.len() < session_id_len + 3 {
            return None;
        }
        let session_id = SmallVec::from_slice(&data[..session_id_len]);
        let data = &data[session_id_len..];

        let cipher_suite = CipherSuite::from_u16(u16::from_be_bytes([data[0], data[1]]));
        let data = &data[2..];

        let compression_method = data[0];

        Some((
            38 + session_id_len,
            ServerHello {
                server_version,
                random,
                session_id,
                cipher_suite,
                compression_method,
            },
        ))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&self.server_version);
        data.extend_from_slice(&self.random);
        data.push(self.session_id.len() as u8);
        data.extend_from_slice(&self.session_id);
        data.extend_from_slice(&self.cipher_suite.to_u16().to_be_bytes());
        data.push(self.compression_method);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_server_hello() {
        let data = [
            0x03, 0x03, // server_version
            // random
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x00, // session_id_len
            0xC0, 0x2F, // cipher_suite
            0x00, // compression_method
        ];

        let server_hello = ServerHello::parse(&data).unwrap();
        assert_eq!(server_hello.1.server_version, [0x03, 0x03]);
        assert_eq!(
            server_hello.1.random,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F,
            ]
        );
        assert_eq!(server_hello.1.session_id.as_ref(), &[]);
        assert_eq!(server_hello.1.cipher_suite, CipherSuite::EECDH_AESGCM);
        assert_eq!(server_hello.1.compression_method, 0x00);
    }

    #[test]
    fn parse_invalid_server_hello() {
        let data = [
            0x03, 0x03, // server_version
            // random (incomplete)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E,
        ];

        let server_hello = ServerHello::parse(&data);
        assert!(server_hello.is_none());
    }
}
