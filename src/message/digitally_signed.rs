use super::error::ParseError;
use super::SignatureAndHashAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigitallySigned<'a> {
    pub algorithm: SignatureAndHashAlgorithm,
    pub signature: &'a [u8],
}

impl<'a> DigitallySigned<'a> {
    pub fn new(algorithm: SignatureAndHashAlgorithm, signature: &'a [u8]) -> Self {
        DigitallySigned {
            algorithm,
            signature,
        }
    }

    pub fn parse(data: &'a [u8]) -> Result<DigitallySigned<'a>, ParseError<ErrorKind>> {
        if data.len() < 4 {
            return Err(ParseError::new(ErrorKind::SignatureNotEnough, 0));
        }
        let algorithm = SignatureAndHashAlgorithm::from_u16(u16::from_be_bytes([data[0], data[1]]));
        let signature_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + signature_len {
            return Err(ParseError::new(ErrorKind::SignatureNotEnough, 4));
        }
        let signature = &data[4..4 + signature_len];
        Ok(DigitallySigned {
            algorithm,
            signature,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.algorithm.to_u16().to_be_bytes());
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(self.signature);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    SignatureNotEnough,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{HashAlgorithm, SignatureAlgorithm};

    const MESSAGE: &[u8] = &[
        0x04, 0x01, // SignatureAndHashAlgorithm (SHA256, RSA)
        0x00, 0x04, // Signature length
        0x01, 0x02, 0x03, 0x04, // Signature
    ];

    #[test]
    fn roundtrip() {
        let original = DigitallySigned::new(
            SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
            &[0x01, 0x02, 0x03, 0x04],
        );

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = DigitallySigned::parse(&serialized).unwrap();

        assert_eq!(parsed.algorithm, original.algorithm);
        assert_eq!(parsed.signature, original.signature);
    }

    #[test]
    fn parse_signature_not_enough() {
        let error = DigitallySigned::parse(&MESSAGE[..3]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignatureNotEnough);
    }

    #[test]
    fn parse_signature_length_not_enough() {
        let error = DigitallySigned::parse(&MESSAGE[..4]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SignatureNotEnough);
    }
}
