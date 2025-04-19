use sha2::{Digest, Sha256, Sha384};

use crate::message::HashAlgorithm;

/// A hash context that supports SHA256 and SHA384 algorithms
pub enum Hash {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Hash {
    /// Create a new hash context with the specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::SHA256 => Hash::Sha256(Sha256::new()),
            HashAlgorithm::SHA384 => Hash::Sha384(Sha384::new()),
            _ => panic!("Unsupported hash algorithm for handshake: {:?}", algorithm),
        }
    }

    /// Update the hash with new data
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hash::Sha256(hasher) => hasher.update(data),
            Hash::Sha384(hasher) => hasher.update(data),
        }
    }

    /// Finalize the hash and return the result. This clones the state, so
    /// it is possible to continue the hashing.
    pub fn clone_and_finalize(&self) -> Vec<u8> {
        match self {
            Hash::Sha256(hasher) => hasher.clone().finalize().to_vec(),
            Hash::Sha384(hasher) => hasher.clone().finalize().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let mut hash = Hash::new(HashAlgorithm::SHA256);
        hash.update(b"hello");
        hash.update(b" ");
        hash.update(b"world");
        let result = hash.clone_and_finalize();

        // Expected SHA256 hash of "hello world"
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha384() {
        let mut hash = Hash::new(HashAlgorithm::SHA384);
        hash.update(b"hello");
        hash.update(b" ");
        hash.update(b"world");
        let result = hash.clone_and_finalize();

        // Expected SHA384 hash of "hello world"
        let expected = [
            0xfd, 0xbd, 0x8e, 0x75, 0xa6, 0x7f, 0x29, 0xf7, 0x01, 0xa4, 0xe0, 0x40, 0x38, 0x5e,
            0x2e, 0x23, 0x98, 0x63, 0x03, 0xea, 0x10, 0x23, 0x92, 0x11, 0xaf, 0x90, 0x7f, 0xcb,
            0xb8, 0x35, 0x78, 0xb3, 0xe4, 0x17, 0xcb, 0x71, 0xce, 0x64, 0x6e, 0xfd, 0x08, 0x19,
            0xdd, 0x8c, 0x08, 0x8d, 0xe1, 0xbd,
        ];

        assert_eq!(result, expected);
    }
}
