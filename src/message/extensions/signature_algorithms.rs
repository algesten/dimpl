use crate::buffer::Buf;
use nom::{number::complete::be_u8, IResult};
use tinyvec::ArrayVec;

/// Hash algorithms for signatures as defined in RFC 5246 Section 7.4.1.4.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    #[default]
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
}

impl HashAlgorithm {
    pub fn parse(input: &[u8]) -> IResult<&[u8], HashAlgorithm> {
        let (input, value) = be_u8(input)?;
        let hash = match value {
            0 => HashAlgorithm::None,
            1 => HashAlgorithm::MD5,
            2 => HashAlgorithm::SHA1,
            3 => HashAlgorithm::SHA224,
            4 => HashAlgorithm::SHA256,
            5 => HashAlgorithm::SHA384,
            6 => HashAlgorithm::SHA512,
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Switch,
                )))
            }
        };
        Ok((input, hash))
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Signature algorithms as defined in RFC 5246 Section 7.4.1.4.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgorithm {
    #[default]
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
}

impl SignatureAlgorithm {
    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAlgorithm> {
        let (input, value) = be_u8(input)?;
        let sig = match value {
            0 => SignatureAlgorithm::Anonymous,
            1 => SignatureAlgorithm::RSA,
            2 => SignatureAlgorithm::DSA,
            3 => SignatureAlgorithm::ECDSA,
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Switch,
                )))
            }
        };
        Ok((input, sig))
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// SignatureAndHashAlgorithm as defined in RFC 5246
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}

impl SignatureAndHashAlgorithm {
    pub fn new(hash: HashAlgorithm, signature: SignatureAlgorithm) -> Self {
        SignatureAndHashAlgorithm { hash, signature }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAndHashAlgorithm> {
        let (input, hash) = HashAlgorithm::parse(input)?;
        let (input, signature) = SignatureAlgorithm::parse(input)?;
        Ok((input, SignatureAndHashAlgorithm { hash, signature }))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        output.push(self.hash.as_u8());
        output.push(self.signature.as_u8());
    }
}

/// SignatureAlgorithms extension as defined in RFC 5246
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAlgorithmsExtension {
    pub supported_signature_algorithms: ArrayVec<[SignatureAndHashAlgorithm; 8]>,
}

impl SignatureAlgorithmsExtension {
    pub fn new(supported_signature_algorithms: ArrayVec<[SignatureAndHashAlgorithm; 8]>) -> Self {
        SignatureAlgorithmsExtension {
            supported_signature_algorithms,
        }
    }

    /// Create a default SignatureAlgorithmsExtension with standard algorithms
    pub fn default() -> Self {
        let mut algorithms = ArrayVec::new();
        // Add algorithms in order of preference (most secure first)
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA256,
            SignatureAlgorithm::ECDSA,
        ));
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA384,
            SignatureAlgorithm::ECDSA,
        ));
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA256,
            SignatureAlgorithm::RSA,
        ));
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA384,
            SignatureAlgorithm::RSA,
        ));

        SignatureAlgorithmsExtension {
            supported_signature_algorithms: algorithms,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SignatureAlgorithmsExtension> {
        let (input, list_len) = nom::number::complete::be_u16(input)?;
        let mut algorithms = ArrayVec::new();
        let mut remaining = list_len as usize;
        let mut current_input = input;

        while remaining > 0 {
            let (rest, alg) = SignatureAndHashAlgorithm::parse(current_input)?;
            algorithms.push(alg);
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

    pub fn serialize(&self, output: &mut Buf<'static>) {
        // Write the total length of all algorithms (2 bytes per algorithm)
        output.extend_from_slice(
            &((self.supported_signature_algorithms.len() * 2) as u16).to_be_bytes(),
        );

        // Write each algorithm
        for alg in &self.supported_signature_algorithms {
            alg.serialize(output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithms_extension() {
        let mut algorithms = ArrayVec::new();
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA256,
            SignatureAlgorithm::ECDSA,
        ));
        algorithms.push(SignatureAndHashAlgorithm::new(
            HashAlgorithm::SHA256,
            SignatureAlgorithm::RSA,
        ));

        let ext = SignatureAlgorithmsExtension::new(algorithms.clone());

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
