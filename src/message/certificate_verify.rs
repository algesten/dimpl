use smallvec::SmallVec;

#[derive(Debug)]
pub struct CertificateVerify {
    pub signature: SmallVec<[u8; 256]>,
}

impl CertificateVerify {
    pub fn parse(data: &[u8]) -> Option<(usize, CertificateVerify)> {
        if data.len() < 2 {
            return None;
        }

        let sig_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = &data[2..];

        if data.len() < sig_len {
            return None;
        }

        let signature = SmallVec::from_slice(&data[..sig_len]);

        Some((2 + sig_len, CertificateVerify { signature }))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_certificate_verify() {
        let data = [
            0x00, 0x04, // sig_len
            0x01, 0x02, 0x03, 0x04, // signature
        ];

        let certificate_verify = CertificateVerify::parse(&data).unwrap();
        assert_eq!(certificate_verify.1.signature.as_ref(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn parse_invalid_certificate_verify() {
        let data = [
            0x00, 0x04, // sig_len
            0x01, 0x02, 0x03, // incomplete signature
        ];

        let certificate_verify = CertificateVerify::parse(&data);
        assert!(certificate_verify.is_none());
    }
}
