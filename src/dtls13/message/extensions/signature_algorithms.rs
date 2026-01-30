use crate::buffer::Buf;
use crate::types::SignatureScheme;
use arrayvec::ArrayVec;
use nom::IResult;

/// SignatureAlgorithms extension for TLS 1.3 (RFC 8446 Section 4.2.3).
///
/// Uses `SignatureScheme` (u16) instead of the TLS 1.2 `SignatureAndHashAlgorithm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAlgorithmsExtension {
    pub supported_signature_algorithms: ArrayVec<SignatureScheme, 4>,
}

impl SignatureAlgorithmsExtension {
    /// Create a default SignatureAlgorithmsExtension with supported schemes.
    pub fn default() -> Self {
        SignatureAlgorithmsExtension {
            supported_signature_algorithms: SignatureScheme::supported(),
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAlgorithmsExtension> {
        let (input, list_len) = nom::number::complete::be_u16(input)?;
        let mut algorithms: ArrayVec<SignatureScheme, 4> = ArrayVec::new();
        let mut remaining = list_len as usize;
        let mut current_input = input;

        while remaining > 0 {
            let (rest, scheme) = SignatureScheme::parse(current_input)?;
            if scheme.is_supported() {
                algorithms.push(scheme);
            }
            current_input = rest;
            remaining -= 2;
        }

        Ok((
            current_input,
            SignatureAlgorithmsExtension {
                supported_signature_algorithms: algorithms,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(
            &((self.supported_signature_algorithms.len() * 2) as u16).to_be_bytes(),
        );

        for scheme in &self.supported_signature_algorithms {
            output.extend_from_slice(&scheme.as_u16().to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithms_extension() {
        let mut algorithms: ArrayVec<SignatureScheme, 4> = ArrayVec::new();
        algorithms.push(SignatureScheme::ECDSA_SECP256R1_SHA256);
        algorithms.push(SignatureScheme::RSA_PSS_RSAE_SHA256);

        let ext = SignatureAlgorithmsExtension {
            supported_signature_algorithms: algorithms.clone(),
        };

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        let expected = [
            0x00, 0x04, // Length (4 bytes)
            0x04, 0x03, // ECDSA_SECP256R1_SHA256
            0x08, 0x04, // RSA_PSS_RSAE_SHA256
        ];

        assert_eq!(&*serialized, expected);

        let (_, parsed) = SignatureAlgorithmsExtension::parse(&serialized).unwrap();

        assert_eq!(parsed.supported_signature_algorithms, algorithms);
    }

    #[test]
    fn capacity_matches_supported() {
        let ext = SignatureAlgorithmsExtension::default();
        assert_eq!(
            ext.supported_signature_algorithms.capacity(),
            SignatureScheme::supported().len(),
            "SignatureAlgorithmsExtension capacity must match supported schemes count"
        );
    }
}
