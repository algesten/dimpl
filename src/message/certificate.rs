use super::error::ParseError;
use smallvec::SmallVec;

#[derive(Debug)]
pub struct Certificate<'a> {
    pub certificates: SmallVec<[&'a [u8]; 16]>,
}

impl<'a> Certificate<'a> {
    pub fn new(certificates: impl IntoIterator<Item = &'a [u8]>) -> Self {
        Certificate {
            certificates: certificates.into_iter().collect(),
        }
    }

    pub fn parse(data: &'a [u8]) -> Result<Certificate<'a>, ParseError<ErrorKind>> {
        let mut position = 0;

        if data.len() < 3 {
            return Err(ParseError::new(ErrorKind::CertificatesLength, position));
        }
        let certificates_len =
            u32::from_be_bytes([0, data[position], data[position + 1], data[position + 2]])
                as usize;
        position += 3;

        println!("{} {}", data.len(), position + certificates_len);

        if data.len() < position + certificates_len {
            return Err(ParseError::new(
                ErrorKind::CertificatesLengthNotEnough,
                position,
            ));
        }

        let mut certificates = SmallVec::new();
        while position < data.len() {
            if data.len() < position + 3 {
                return Err(ParseError::new(ErrorKind::CertificateLength, position));
            }
            let cert_len =
                u32::from_be_bytes([0, data[position], data[position + 1], data[position + 2]])
                    as usize;
            position += 3;

            if cert_len < 1 {
                return Err(ParseError::new(ErrorKind::CertificateTooShort, position));
            }

            if data.len() < position + cert_len {
                return Err(ParseError::new(ErrorKind::CertificateNotEnough, position));
            }
            certificates.push(&data[position..position + cert_len]);
            position += cert_len;
        }

        Ok(Certificate { certificates })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        let total_len: usize = self.certificates.iter().map(|cert| cert.len() + 3).sum();
        out.extend_from_slice(&(total_len as u32).to_be_bytes()[1..]);

        for cert in &self.certificates {
            out.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            out.extend_from_slice(cert);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    CertificatesLength,
    CertificatesLengthNotEnough,
    CertificateLength,
    CertificateTooShort,
    CertificateNotEnough,
}

#[cfg(test)]
mod test {
    use super::*;

    const MESSAGE: &[u8] = &[
        0x00, 0x00, 0x11, // Certificates length
        0x00, 0x00, 0x03, // Certificate 1 length
        0x01, 0x02, 0x03, // Certificate 1
        0x00, 0x00, 0x03, // Certificate 2 length
        0x04, 0x05, 0x06, // Certificate 2
        0x00, 0x00, 0x02, // Certificate 3 length
        0x07, 0x08, // Certificate 3
    ];

    #[test]
    fn roundtrip() {
        let original = Certificate::new(vec![&MESSAGE[6..9], &MESSAGE[12..15], &MESSAGE[18..20]]);

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = Certificate::parse(&serialized).unwrap();

        assert_eq!(parsed.certificates, original.certificates);
    }

    #[test]
    fn parse_certificates_length() {
        let error = Certificate::parse(&MESSAGE[..2]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificatesLength);
    }

    #[test]
    fn parse_certificates_length_not_enough() {
        let error = Certificate::parse(&MESSAGE[..4]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificatesLengthNotEnough);
    }

    #[test]
    fn parse_certificate_length() {
        let mut data = MESSAGE.to_vec();
        data[5] = 12; // Makes the position offset wrong for reading the next length
        let error = Certificate::parse(&data).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificateLength);
    }

    #[test]
    fn parse_certificate_too_short() {
        let mut data = MESSAGE.to_vec();
        data[5] = 0x00; // Certificate 1 length (0)
        let error = Certificate::parse(&data).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificateTooShort);
    }

    #[test]
    fn parse_certificate_not_enough() {
        let mut data = MESSAGE.to_vec();
        data[5] = 0xff; // Certificate 1 length (255)
        let error = Certificate::parse(&data).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificateNotEnough);
    }
}
