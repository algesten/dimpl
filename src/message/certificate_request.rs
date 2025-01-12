use super::{ClientCertificateType, DistinguishedName, SignatureAndHashAlgorithm};
use nom::number::complete::{be_u16, be_u8};
use nom::{bytes::complete::take, IResult};
use smallvec::SmallVec;

#[derive(Debug, PartialEq, Eq)]
pub struct CertificateRequest<'a> {
    pub certificate_types: SmallVec<[ClientCertificateType; 8]>,
    pub supported_signature_algorithms: SmallVec<[SignatureAndHashAlgorithm; 16]>,
    pub certificate_authorities: SmallVec<[DistinguishedName<'a>; 16]>,
}

impl<'a> CertificateRequest<'a> {
    pub fn new(
        certificate_types: SmallVec<[ClientCertificateType; 8]>,
        supported_signature_algorithms: SmallVec<[SignatureAndHashAlgorithm; 16]>,
        certificate_authorities: SmallVec<[DistinguishedName<'a>; 16]>,
    ) -> Self {
        CertificateRequest {
            certificate_types,
            supported_signature_algorithms,
            certificate_authorities,
        }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], CertificateRequest<'a>> {
        let (input, cert_types_len) = be_u8(input)?;
        let (input, cert_types_data) = take(cert_types_len)(input)?;
        let certificate_types = cert_types_data
            .iter()
            .map(|&b| ClientCertificateType::from_u8(b))
            .collect();

        let (input, sig_algs_len) = be_u16(input)?;
        let (input, sig_algs_data) = take(sig_algs_len)(input)?;
        let supported_signature_algorithms = sig_algs_data
            .chunks(2)
            .map(|chunk| {
                SignatureAndHashAlgorithm::from_u16(u16::from_be_bytes([chunk[0], chunk[1]]))
            })
            .collect();

        let (input, cert_auths_len) = be_u16(input)?;
        let (mut input, mut remaining_len) = (input, cert_auths_len as usize);
        let mut certificate_authorities = SmallVec::new();

        while remaining_len > 0 {
            let (rest, name_len) = be_u16(input)?;
            let (rest, name_data) = take(name_len as usize)(rest)?;
            certificate_authorities.push(DistinguishedName(name_data));
            input = rest;
            remaining_len -= 2 + name_len as usize;
        }

        Ok((
            input,
            CertificateRequest {
                certificate_types,
                supported_signature_algorithms,
                certificate_authorities,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.push(self.certificate_types.len() as u8);
        for cert_type in &self.certificate_types {
            output.push(cert_type.to_u8());
        }

        let sig_algs_len = (self.supported_signature_algorithms.len() * 2) as u16;
        output.extend_from_slice(&sig_algs_len.to_be_bytes());
        for sig_alg in &self.supported_signature_algorithms {
            output.extend_from_slice(&sig_alg.to_u16().to_be_bytes());
        }

        let cert_auths_len: usize = self
            .certificate_authorities
            .iter()
            .map(|name| 2 + name.len())
            .sum();
        output.extend_from_slice(&(cert_auths_len as u16).to_be_bytes());
        for name in &self.certificate_authorities {
            output.extend_from_slice(&(name.len() as u16).to_be_bytes());
            output.extend_from_slice(name);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::message::{HashAlgorithm, SignatureAlgorithm};

    use super::*;
    use smallvec::smallvec;

    const MESSAGE: &[u8] = &[
        0x02, // Certificate types length
        0x01, 0x02, // Certificate types
        0x00, 0x04, // Signature algorithms length
        0x04, 0x01, 0x05, 0x02, // Signature algorithms
        0x00, 0x0C, // Certificate authorities length
        0x00, 0x04, // Distinguished name 1 length
        0x01, 0x02, 0x03, 0x04, // Distinguished name 1 data
        0x00, 0x04, // Distinguished name 2 length
        0x05, 0x06, 0x07, 0x08, // Distinguished name 2 data
    ];

    #[test]
    fn roundtrip() {
        let mut serialized = Vec::new();

        let certificate_types = smallvec![
            ClientCertificateType::RSA_SIGN,
            ClientCertificateType::DSS_SIGN
        ];
        let supported_signature_algorithms = smallvec![
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA384, SignatureAlgorithm::DSA)
        ];
        let certificate_authorities = smallvec![
            DistinguishedName(&MESSAGE[13..17]),
            DistinguishedName(&MESSAGE[19..23])
        ];

        let certificate_request = CertificateRequest::new(
            certificate_types,
            supported_signature_algorithms,
            certificate_authorities,
        );

        // Serialize and compare to MESSAGE
        certificate_request.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = CertificateRequest::parse(&serialized).unwrap();
        assert_eq!(parsed, certificate_request);

        assert!(rest.is_empty());
    }
}
