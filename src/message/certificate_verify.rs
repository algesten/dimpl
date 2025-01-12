use super::digitally_signed::{self, DigitallySigned};
use super::error::ParseError;

#[derive(Debug)]
pub struct CertificateVerify<'a> {
    pub digitally_signed: DigitallySigned<'a>,
}

impl<'a> CertificateVerify<'a> {
    pub fn new(digitally_signed: DigitallySigned<'a>) -> Self {
        CertificateVerify { digitally_signed }
    }

    pub fn parse(data: &'a [u8]) -> Result<CertificateVerify<'a>, ParseError<ErrorKind>> {
        let digitally_signed = DigitallySigned::parse(data)?;
        Ok(CertificateVerify { digitally_signed })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        self.digitally_signed.serialize(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    SignatureNotEnough,
}

impl From<digitally_signed::ErrorKind> for ErrorKind {
    fn from(value: digitally_signed::ErrorKind) -> Self {
        match value {
            digitally_signed::ErrorKind::SignatureNotEnough => Self::SignatureNotEnough,
        }
    }
}

impl From<ParseError<digitally_signed::ErrorKind>> for ParseError<ErrorKind> {
    fn from(value: ParseError<digitally_signed::ErrorKind>) -> Self {
        match value.kind() {
            digitally_signed::ErrorKind::SignatureNotEnough => {
                ParseError::new(ErrorKind::SignatureNotEnough, value.position())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{HashAlgorithm, SignatureAlgorithm, SignatureAndHashAlgorithm};

    const MESSAGE: &[u8] = &[
        0x04, 0x01, // SignatureAndHashAlgorithm (SHA256, RSA)
        0x00, 0x04, // Signature length
        0x01, 0x02, 0x03, 0x04, // Signature
    ];

    #[test]
    fn roundtrip() {
        let digitally_signed = DigitallySigned::new(
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
            &[0x01, 0x02, 0x03, 0x04],
        );
        let original = CertificateVerify::new(digitally_signed);

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = CertificateVerify::parse(&serialized).unwrap();

        assert_eq!(parsed.digitally_signed, original.digitally_signed);
    }

    #[test]
    fn parse_signature_not_enough() {
        let error = CertificateVerify::parse(&MESSAGE[..3]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignatureNotEnough);
    }

    #[test]
    fn parse_signature_length_not_enough() {
        let error = CertificateVerify::parse(&MESSAGE[..4]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignatureNotEnough);
    }
}
