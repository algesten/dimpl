use super::error::ParseError;
use super::{ClientCertificateType, DistinguishedName, SignatureAndHashAlgorithm};
use smallvec::SmallVec;

#[derive(Debug)]
pub struct CertificateRequest<'a> {
    pub certificate_types: SmallVec<[ClientCertificateType; 16]>,
    pub supported_signature_algorithms: SmallVec<[SignatureAndHashAlgorithm; 16]>,
    pub certificate_authorities: SmallVec<[DistinguishedName<'a>; 16]>,
}

impl<'a> CertificateRequest<'a> {
    pub fn new(
        certificate_types: impl IntoIterator<Item = ClientCertificateType>,
        supported_signature_algorithms: impl IntoIterator<Item = SignatureAndHashAlgorithm>,
        certificate_authorities: impl IntoIterator<Item = DistinguishedName<'a>>,
    ) -> Self {
        CertificateRequest {
            certificate_types: certificate_types.into_iter().collect(),
            supported_signature_algorithms: supported_signature_algorithms.into_iter().collect(),
            certificate_authorities: certificate_authorities.into_iter().collect(),
        }
    }

    pub fn parse(data: &'a [u8]) -> Result<CertificateRequest<'a>, ParseError<ErrorKind>> {
        let mut position = 0;

        if data.len() < 1 {
            return Err(ParseError::new(ErrorKind::CertificateTypesLength, position));
        }
        let certificate_types_len = data[position] as usize;
        position += 1;

        if data.len() < position + certificate_types_len {
            return Err(ParseError::new(
                ErrorKind::CertificateTypesNotEnough,
                position,
            ));
        }
        let certificate_types = &data[position..position + certificate_types_len];
        let certificate_types: SmallVec<[ClientCertificateType; 16]> = certificate_types
            .iter()
            .map(|&ct| ClientCertificateType::from_u8(ct))
            .collect();
        position += certificate_types_len;

        if data.len() < position + 2 {
            return Err(ParseError::new(
                ErrorKind::SignatureAlgorithmsLength,
                position,
            ));
        }
        let signature_algorithms_len =
            u16::from_be_bytes([data[position], data[position + 1]]) as usize;
        position += 2;

        if data.len() < position + signature_algorithms_len {
            return Err(ParseError::new(
                ErrorKind::SignatureAlgorithmsNotEnough,
                position,
            ));
        }
        let supported_signature_algorithms = &data[position..position + signature_algorithms_len];
        let supported_signature_algorithms: SmallVec<[SignatureAndHashAlgorithm; 16]> =
            supported_signature_algorithms
                .chunks(2)
                .map(|chunk| {
                    SignatureAndHashAlgorithm::from_u16(u16::from_be_bytes([chunk[0], chunk[1]]))
                })
                .collect();
        position += signature_algorithms_len;

        let mut certificate_authorities = SmallVec::new();
        while position < data.len() {
            if data.len() < position + 2 {
                return Err(ParseError::new(
                    ErrorKind::CertificateAuthoritiesLength,
                    position,
                ));
            }
            let ca_len = u16::from_be_bytes([data[position], data[position + 1]]) as usize;
            position += 2;

            if data.len() < position + ca_len {
                return Err(ParseError::new(
                    ErrorKind::CertificateAuthoritiesNotEnough,
                    position,
                ));
            }
            certificate_authorities.push(DistinguishedName(&data[position..position + ca_len]));
            position += ca_len;
        }

        Ok(CertificateRequest {
            certificate_types,
            supported_signature_algorithms,
            certificate_authorities,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.push(self.certificate_types.len() as u8);
        for &ct in &self.certificate_types {
            out.push(ct.to_u8());
        }

        let sig_alg_len = self.supported_signature_algorithms.len() * 2;
        out.extend_from_slice(&(sig_alg_len as u16).to_be_bytes());
        for &alg in &self.supported_signature_algorithms {
            out.extend_from_slice(&alg.to_u16().to_be_bytes());
        }

        for &DistinguishedName(ca) in &self.certificate_authorities {
            out.extend_from_slice(&(ca.len() as u16).to_be_bytes());
            out.extend_from_slice(ca);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    CertificateTypesLength,
    CertificateTypesNotEnough,
    SignatureAlgorithmsLength,
    SignatureAlgorithmsNotEnough,
    CertificateAuthoritiesLength,
    CertificateAuthoritiesNotEnough,
}

#[cfg(test)]
mod test {
    use crate::message::{HashAlgorithm, SignatureAlgorithm};

    use super::*;

    const MESSAGE: &[u8] = &[
        0x02, // CertificateTypes length
        0x01, 0x02, // CertificateTypes
        0x00, 0x04, // SignatureAlgorithms length
        0x04, 0x01, 0x05, 0x02, // SignatureAlgorithms
        0x00, 0x03, // CertificateAuthority 1 length
        0x01, 0x02, 0x03, // CertificateAuthority 1
        0x00, 0x03, // CertificateAuthority 2 length
        0x04, 0x05, 0x06, // CertificateAuthority 2
    ];

    #[test]
    fn roundtrip() {
        let mut serialized = Vec::new();

        let original = CertificateRequest::new(
            vec![
                ClientCertificateType::RSA_SIGN,
                ClientCertificateType::DSS_SIGN,
            ],
            vec![
                SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
                SignatureAndHashAlgorithm::new(HashAlgorithm::SHA384, SignatureAlgorithm::DSA),
            ],
            vec![
                DistinguishedName(&[0x01, 0x02, 0x03]),
                DistinguishedName(&[0x04, 0x05, 0x06]),
            ],
        );

        original.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        let parsed = CertificateRequest::parse(&serialized).unwrap();

        assert_eq!(parsed.certificate_types, original.certificate_types);
        assert_eq!(
            parsed.supported_signature_algorithms,
            original.supported_signature_algorithms
        );
        assert_eq!(
            parsed.certificate_authorities,
            original.certificate_authorities
        );
    }

    #[test]
    fn parse_certificate_types_length() {
        let error = CertificateRequest::parse(&MESSAGE[..0]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificateTypesLength);
    }

    #[test]
    fn parse_certificate_types_not_enough() {
        let error = CertificateRequest::parse(&MESSAGE[..1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificateTypesNotEnough);
    }

    #[test]
    fn parse_signature_algorithms_length() {
        let error = CertificateRequest::parse(&MESSAGE[..3]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignatureAlgorithmsLength);
    }

    #[test]
    fn parse_signature_algorithms_not_enough() {
        let error = CertificateRequest::parse(&MESSAGE[..5]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignatureAlgorithmsNotEnough);
    }

    #[test]
    fn parse_certificate_authorities_length() {
        let mut data = MESSAGE.to_vec();
        data[10] = 7; // Set so first cert "consumes" the wrong amount triggering the error
        let error = CertificateRequest::parse(&data).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificateAuthoritiesLength);
    }

    #[test]
    fn parse_certificate_authorities_not_enough() {
        let error = CertificateRequest::parse(&MESSAGE[..12]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CertificateAuthoritiesNotEnough);
    }
}
