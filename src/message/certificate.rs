use smallvec::SmallVec;

#[derive(Debug)]
pub struct Certificate {
    pub certificates: SmallVec<[Vec<u8>; 10]>,
}

impl Certificate {
    pub fn parse(data: &[u8]) -> Option<(usize, Certificate)> {
        if data.len() < 3 {
            return None;
        }

        let total_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
        let data = &data[3..];

        if data.len() < total_len {
            return None;
        }

        let mut certificates = SmallVec::new();
        let mut offset = 0;

        while offset < total_len {
            let cert_len =
                u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
            offset += 3;

            if offset + cert_len > total_len {
                return None;
            }

            certificates.push(data[offset..offset + cert_len].to_vec());
            offset += cert_len;
        }

        Some((3 + total_len, Certificate { certificates }))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        let total_len: usize = self.certificates.iter().map(|cert| cert.len() + 3).sum();
        data.extend_from_slice(&(total_len as u32).to_be_bytes()[1..]);

        for cert in &self.certificates {
            data.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            data.extend_from_slice(cert);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_certificate() {
        let data = [
            0x00, 0x00, 0x07, // total_len
            0x00, 0x00, 0x04, // cert_len
            0x01, 0x02, 0x03, 0x04, // certificate
        ];

        let certificate = Certificate::parse(&data).unwrap();
        assert_eq!(certificate.1.certificates.len(), 1);
        assert_eq!(certificate.1.certificates[0], vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn parse_invalid_certificate() {
        let data = [
            0x00, 0x00, 0x07, // total_len
            0x00, 0x00, 0x04, // cert_len
            0x01, 0x02, 0x03, // incomplete certificate
        ];

        let certificate = Certificate::parse(&data);
        assert!(certificate.is_none());
    }
}
