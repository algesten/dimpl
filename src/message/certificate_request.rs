use super::{ClientCertificateType, DistinguishedName, SignatureAndHashAlgorithm};
use crate::buffer::Buf;
use crate::util::{many0, many1};
use arrayvec::ArrayVec;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u16, be_u8};
use nom::Err;
use nom::{bytes::complete::take, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct CertificateRequest {
    pub certificate_types: ArrayVec<ClientCertificateType, 8>,
    pub supported_signature_algorithms: ArrayVec<SignatureAndHashAlgorithm, 32>,
    pub certificate_authorities: ArrayVec<DistinguishedName, 32>,
}

impl CertificateRequest {
    pub fn new(
        certificate_types: ArrayVec<ClientCertificateType, 8>,
        supported_signature_algorithms: ArrayVec<SignatureAndHashAlgorithm, 32>,
        certificate_authorities: ArrayVec<DistinguishedName, 32>,
    ) -> Self {
        CertificateRequest {
            certificate_types,
            supported_signature_algorithms,
            certificate_authorities,
        }
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], CertificateRequest> {
        let original_input = input;
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

        // Calculate base offset for input_auths within the root buffer
        let auths_base_offset =
            base_offset + (input_auths.as_ptr() as usize - original_input.as_ptr() as usize);

        // Parse certificate authorities manually with dynamic base_offset
        let mut certificate_authorities = ArrayVec::new();
        let mut rest = input_auths;
        while !rest.is_empty() {
            let offset =
                auths_base_offset + (rest.as_ptr() as usize - input_auths.as_ptr() as usize);
            let (new_rest, auth) = DistinguishedName::parse(rest, offset)?;
            certificate_authorities.push(auth);
            rest = new_rest;
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

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
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
            .map(|name| 2 + name.as_slice(buf).len())
            .sum();
        output.extend_from_slice(&(cert_auths_len as u16).to_be_bytes());
        for name in &self.certificate_authorities {
            let name_data = name.as_slice(buf);
            output.extend_from_slice(&(name_data.len() as u16).to_be_bytes());
            output.extend_from_slice(name_data);
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
        // Parse the message with base_offset 0
        let (rest, parsed) = CertificateRequest::parse(MESSAGE, 0).unwrap();
        assert!(rest.is_empty());

        // Serialize and compare to MESSAGE
        let mut serialized = Buf::new();
        parsed.serialize(MESSAGE, &mut serialized);
        assert_eq!(&*serialized, MESSAGE);
    }
}
