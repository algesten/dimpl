use super::CipherSuite;
use smallvec::SmallVec;

#[derive(Debug)]
pub struct ClientHello {
    pub client_version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: SmallVec<[u8; 32]>,
    pub cookie: SmallVec<[u8; 32]>,
    pub cipher_suites: SmallVec<[CipherSuite; 16]>,
    pub compression_methods: SmallVec<[u8; 8]>,
}

impl ClientHello {
    pub fn parse(data: &[u8]) -> Option<(usize, ClientHello)> {
        if data.len() < 34 {
            return None;
        }

        let client_version = [data[0], data[1]];
        let data = &data[2..];

        let random: [u8; 32] = data[..32].try_into().unwrap();
        let data = &data[32..];

        let session_id_len = data[0] as usize;
        let data = &data[1..];
        if data.len() < session_id_len {
            return None;
        }
        let session_id = SmallVec::from_slice(&data[..session_id_len]);
        let data = &data[session_id_len..];

        let cookie_len = data[0] as usize;
        let data = &data[1..];
        if data.len() < cookie_len {
            return None;
        }
        let cookie = SmallVec::from_slice(&data[..cookie_len]);
        let data = &data[cookie_len..];

        let cipher_suites_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = &data[2..];
        if data.len() < cipher_suites_len {
            return None;
        }
        let cipher_suites = (0..cipher_suites_len / 2)
            .map(|i| CipherSuite::from_u16(u16::from_be_bytes([data[2 * i], data[2 * i + 1]])))
            .collect();
        let data = &data[cipher_suites_len..];

        let compression_methods_len = data[0] as usize;
        let data = &data[1..];
        if data.len() < compression_methods_len {
            return None;
        }
        let compression_methods = SmallVec::from_slice(&data[..compression_methods_len]);

        Some((
            39 + session_id_len + cookie_len + cipher_suites_len + compression_methods_len,
            ClientHello {
                client_version,
                random,
                session_id,
                cookie,
                cipher_suites,
                compression_methods,
            },
        ))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&self.client_version);
        data.extend_from_slice(&self.random);
        data.push(self.session_id.len() as u8);
        data.extend_from_slice(&self.session_id);
        data.push(self.cookie.len() as u8);
        data.extend_from_slice(&self.cookie);
        data.extend_from_slice(&(self.cipher_suites.len() as u16 * 2).to_be_bytes());
        for suite in &self.cipher_suites {
            data.extend_from_slice(&suite.to_u16().to_be_bytes());
        }
        data.push(self.compression_methods.len() as u8);
        data.extend_from_slice(&self.compression_methods);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_client_hello() {
        let data = [
            0x03, 0x03, // client_version
            // random
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x00, // session_id_len
            0x00, // cookie_len
            0x00, 0x04, // cipher_suites_len
            0xC0, 0x2F, 0xC0, 0x30, // cipher_suites
            0x01, // compression_methods_len
            0x00, // compression_methods
        ];

        let client_hello = ClientHello::parse(&data).unwrap();
        assert_eq!(client_hello.1.client_version, [0x03, 0x03]);
        assert_eq!(
            client_hello.1.random,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
                0x1C, 0x1D, 0x1E, 0x1F,
            ]
        );
        assert_eq!(client_hello.1.session_id.as_ref(), &[]);
        assert_eq!(client_hello.1.cookie.as_ref(), &[]);
        assert_eq!(
            client_hello.1.cipher_suites.as_ref(),
            &[CipherSuite::EECDH_AESGCM, CipherSuite::EDH_AESGCM,]
        );
        assert_eq!(client_hello.1.compression_methods.as_ref(), &[0x00]);
    }

    #[test]
    fn parse_invalid_client_hello() {
        let data = [
            0x03, 0x03, // client_version
            // random (incomplete)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E,
        ];

        let client_hello = ClientHello::parse(&data);
        assert!(client_hello.is_none());
    }
}
