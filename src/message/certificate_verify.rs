use super::DigitallySigned;
use crate::buffer::Buf;
use nom::IResult;

#[derive(Debug, PartialEq, Eq)]
pub struct CertificateVerify<'a> {
    pub signed: DigitallySigned<'a>,
}

impl<'a> CertificateVerify<'a> {
    pub fn new(signed: DigitallySigned<'a>) -> Self {
        CertificateVerify { signed }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], CertificateVerify<'a>> {
        let (input, signed) = DigitallySigned::parse(input)?;
        Ok((input, CertificateVerify { signed }))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        self.signed.serialize(output);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buffer::Buf;
    use crate::message::{HashAlgorithm, SignatureAlgorithm, SignatureAndHashAlgorithm};

    const MESSAGE: &[u8] = &[
        0x04, 0x01, // SignatureAndHashAlgorithm (SHA256 + RSA)
        0x00, 0x04, // Signature length
        0x01, 0x02, 0x03, 0x04, // Signature data
    ];

    #[test]
    fn roundtrip() {
        let algorithm =
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA);
        let signature = &MESSAGE[4..8];

        let digitally_signed = DigitallySigned::new(algorithm, signature);
        let certificate_verify = CertificateVerify::new(digitally_signed);

        // Serialize and compare to MESSAGE
        let mut serialized = Buf::new();
        certificate_verify.serialize(&mut serialized);
        assert_eq!(&*serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = CertificateVerify::parse(&serialized).unwrap();
        assert_eq!(parsed, certificate_verify);

        assert!(rest.is_empty());
    }
}
