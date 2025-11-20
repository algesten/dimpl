use super::{ClientCertificateType, DistinguishedName, SignatureAndHashAlgorithm};
use crate::buffer::Buf;
use crate::util::{many0, many1};
use arrayvec::ArrayVec;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u16, be_u8};
use nom::Err;
use nom::{bytes::complete::take, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct CertificateRequest<'a> {
    pub certificate_types: ArrayVec<ClientCertificateType, 8>,
    pub supported_signature_algorithms: ArrayVec<SignatureAndHashAlgorithm, 32>,
    pub certificate_authorities: ArrayVec<DistinguishedName<'a>, 32>,
}

impl<'a> CertificateRequest<'a> {
    pub fn new(
        certificate_types: ArrayVec<ClientCertificateType, 8>,
        supported_signature_algorithms: ArrayVec<SignatureAndHashAlgorithm, 32>,
        certificate_authorities: ArrayVec<DistinguishedName<'a>, 32>,
    ) -> Self {
        CertificateRequest {
            certificate_types,
            supported_signature_algorithms,
            certificate_authorities,
        }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], CertificateRequest<'a>> {
        let (input, cert_types_len) = be_u8(input)?;
        let (input, input_type) = take(cert_types_len)(input)?;
        let (rest, certificate_types) = many1(ClientCertificateType::parse)(input_type)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }

        let (input, sig_algs_len) = be_u16(input)?;
        let (input, input_sigs) = take(sig_algs_len)(input)?;
        let (rest, supported_signature_algorithms) =
            many0(SignatureAndHashAlgorithm::parse)(input_sigs)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
        }

        let (input, cert_auths_len) = be_u16(input)?;
        let (input, input_auths) = take(cert_auths_len)(input)?;
        let (rest, certificate_authorities) = many0(DistinguishedName::parse)(input_auths)?;
        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
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

    pub fn serialize(&self, output: &mut Buf) {
        output.push(self.certificate_types.len() as u8);
        for cert_type in &self.certificate_types {
            output.push(cert_type.as_u8());
        }

        let sig_algs_len = (self.supported_signature_algorithms.len() * 2) as u16;
        output.extend_from_slice(&sig_algs_len.to_be_bytes());
        for sig_alg in &self.supported_signature_algorithms {
            output.extend_from_slice(&sig_alg.as_u16().to_be_bytes());
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

    /// Checks if the CertificateRequest supports a specific hash algorithm
    pub fn supports_hash_algorithm(&self, hash_algorithm: super::HashAlgorithm) -> bool {
        self.supported_signature_algorithms
            .iter()
            .any(|algo| algo.hash == hash_algorithm)
    }
}

#[cfg(test)]
mod test {
    use crate::message::{HashAlgorithm, SignatureAlgorithm};

    use super::*;
    use crate::buffer::Buf;

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
        let mut serialized = Buf::new();

        let mut certificate_types = ArrayVec::new();
        certificate_types.push(ClientCertificateType::RSA_SIGN);
        certificate_types.push(ClientCertificateType::DSS_SIGN);
        let mut supported_signature_algorithms = ArrayVec::new();
        supported_signature_algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA256,
            SignatureAlgorithm::RSA,
        ));
        supported_signature_algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA384,
            SignatureAlgorithm::DSA,
        ));
        let d1 = &MESSAGE[13..17];
        let d2 = &MESSAGE[19..23];
        let mut certificate_authorities = ArrayVec::new();
        certificate_authorities.push(DistinguishedName(d1));
        certificate_authorities.push(DistinguishedName(d2));

        let certificate_request = CertificateRequest::new(
            certificate_types,
            supported_signature_algorithms,
            certificate_authorities,
        );

        // Serialize and compare to MESSAGE
        certificate_request.serialize(&mut serialized);
        assert_eq!(&*serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = CertificateRequest::parse(&serialized).unwrap();
        assert_eq!(parsed, certificate_request);

        assert!(rest.is_empty());
    }
}
