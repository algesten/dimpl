use crate::buffer::Buf;
use crate::message::{SignatureAndHashAlgorithm, SignatureAndHashAlgorithmVec};
use nom::IResult;

/// SignatureAlgorithms extension as defined in RFC 5246
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAlgorithmsExtension {
    pub supported_signature_algorithms: SignatureAndHashAlgorithmVec,
}

impl SignatureAlgorithmsExtension {
    /// Create a default SignatureAlgorithmsExtension with standard algorithms
    pub fn default() -> Self {
        SignatureAlgorithmsExtension {
            supported_signature_algorithms: SignatureAndHashAlgorithmVec::from(
                *SignatureAndHashAlgorithm::supported(),
            ),
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAlgorithmsExtension> {
        let (input, list_len) = nom::number::complete::be_u16(input)?;
        let mut algorithms = SignatureAndHashAlgorithmVec::new();
        let mut remaining = list_len as usize;
        let mut current_input = input;

        // Parse algorithms, filtering to only keep supported ones
        while remaining > 0 {
            let (rest, alg) = SignatureAndHashAlgorithm::parse(current_input)?;
            // Only keep supported signature+hash combinations
            if alg.is_supported() {
                algorithms.push(alg);
            }
            current_input = rest;
            remaining -= 2; // Each algorithm pair is 2 bytes
        }

        Ok((
            current_input,
            SignatureAlgorithmsExtension {
                supported_signature_algorithms: algorithms,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf) {
        // Write the total length of all algorithms (2 bytes per algorithm)
        output.extend_from_slice(
            &((self.supported_signature_algorithms.len() * 2) as u16).to_be_bytes(),
        );

        // Write each algorithm
        for alg in &self.supported_signature_algorithms {
            output.extend_from_slice(&alg.as_u16().to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::SignatureAlgorithm;
    use crate::message::HashAlgorithm;

    use super::*;

    #[test]
    fn test_signature_algorithms_extension() {
        let mut algorithms = SignatureAndHashAlgorithmVec::new();
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA256,
            SignatureAlgorithm::ECDSA,
        ));
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA256,
            SignatureAlgorithm::RSA,
        ));

        let ext = SignatureAlgorithmsExtension {
            supported_signature_algorithms: algorithms.clone(),
        };

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        let expected = [
            0x00, 0x04, // Length (4 bytes)
            0x04, 0x03, // SHA256/ECDSA
            0x04, 0x01, // SHA256/RSA
        ];

        assert_eq!(&*serialized, expected);

        let (_, parsed) = SignatureAlgorithmsExtension::parse(&serialized).unwrap();

        assert_eq!(parsed.supported_signature_algorithms, algorithms);
    }
}
