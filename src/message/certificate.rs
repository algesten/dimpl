use crate::message::Asn1Cert;
use nom::{bytes::complete::take, number::complete::be_u24, IResult};
use smallvec::SmallVec;

#[derive(Debug, PartialEq, Eq)]
pub struct Certificate<'a> {
    pub certificate_list: SmallVec<[Asn1Cert<'a>; 32]>,
}

impl<'a> Certificate<'a> {
    pub fn new(certificate_list: SmallVec<[Asn1Cert<'a>; 32]>) -> Self {
        Certificate { certificate_list }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], Certificate<'a>> {
        let (input, total_len) = be_u24(input)?;
        let (mut input, mut remaining_len) = (input, total_len as usize);
        let mut certificate_list = SmallVec::new();

        while remaining_len > 0 {
            let (rest, cert_len) = be_u24(input)?;
            let (rest, cert_data) = take(cert_len as usize)(rest)?;
            certificate_list.push(Asn1Cert(cert_data));
            input = rest;
            remaining_len -= 3 + cert_len as usize;
        }

        Ok((input, Certificate { certificate_list }))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        let total_len: usize = self
            .certificate_list
            .iter()
            .map(|cert| 3 + cert.len())
            .sum();
        output.extend_from_slice(&(total_len as u32).to_be_bytes()[1..]);

        for cert in &self.certificate_list {
            output.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            output.extend_from_slice(cert);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    const MESSAGE: &[u8] = &[
        0x00, 0x00, 0x0C, // Total length
        0x00, 0x00, 0x04, // Certificate 1 length
        0x01, 0x02, 0x03, 0x04, // Certificate 1 data
        0x00, 0x00, 0x02, // Certificate 2 length
        0x05, 0x06, // Certificate 2 data
    ];

    #[test]
    fn roundtrip() {
        let mut serialized = Vec::new();

        let certificate_list = smallvec![Asn1Cert(&MESSAGE[6..10]), Asn1Cert(&MESSAGE[13..15])];

        let certificate = Certificate::new(certificate_list);

        // Serialize and compare to MESSAGE
        certificate.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Certificate::parse(&serialized).unwrap();
        assert_eq!(parsed, certificate);

        assert!(rest.is_empty());
    }
}
