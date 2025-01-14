use crate::util::many0;
use super::Asn1Cert;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::Err;
use nom::{number::complete::be_u24, IResult};
use tinyvec::ArrayVec;

#[derive(Debug, PartialEq, Eq)]
pub struct Certificate<'a> {
    pub certificate_list: ArrayVec<[Asn1Cert<'a>; 32]>,
}

impl<'a> Certificate<'a> {
    pub fn new(certificate_list: ArrayVec<[Asn1Cert<'a>; 32]>) -> Self {
        Certificate { certificate_list }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], Certificate<'a>> {
        let (input, total_len) = be_u24(input)?;
        let (input, certs_data) = take(total_len)(input)?;
        let (rest, certificate_list) = many0(Asn1Cert::parse)(certs_data)?;

        if !rest.is_empty() {
            return Err(Err::Failure(Error::new(rest, ErrorKind::LengthValue)));
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
    use tinyvec::array_vec;

    use super::*;

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

        let c1 = &MESSAGE[6..10];
        let c2 = &MESSAGE[13..15];
        let certificate_list = array_vec![Asn1Cert(c1), Asn1Cert(c2)];

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
