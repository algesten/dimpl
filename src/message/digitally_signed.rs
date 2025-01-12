use crate::message::SignatureAndHashAlgorithm;
use nom::number::complete::be_u16;
use nom::{bytes::complete::take, IResult};

#[derive(Debug, PartialEq, Eq)]
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

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], DigitallySigned<'a>> {
        let (input, algorithm) = SignatureAndHashAlgorithm::parse(input)?;
        let (input, signature_len) = be_u16(input)?;
        let (input, signature) = take(signature_len)(input)?;
        Ok((
            input,
            DigitallySigned {
                algorithm,
                signature,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.algorithm.to_u16().to_be_bytes());
        output.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        output.extend_from_slice(self.signature);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::message::{HashAlgorithm, SignatureAlgorithm};

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

        // Serialize and compare to MESSAGE
        let mut serialized = Vec::new();
        digitally_signed.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = DigitallySigned::parse(&serialized).unwrap();
        assert_eq!(parsed, digitally_signed);

        assert!(rest.is_empty());
    }
}
