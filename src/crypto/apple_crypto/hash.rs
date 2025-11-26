//! Hash implementations for Apple platforms.

use sha2::{Digest, Sha256, Sha384};

use crate::buffer::Buf;
use crate::crypto::provider::{HashContext, HashProvider};
use crate::message::HashAlgorithm;

/// Hash context implementation.
enum AppleCryptoHashContext {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl HashContext for AppleCryptoHashContext {
    fn update(&mut self, data: &[u8]) {
        match self {
            AppleCryptoHashContext::Sha256(ctx) => ctx.update(data),
            AppleCryptoHashContext::Sha384(ctx) => ctx.update(data),
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        match self {
            AppleCryptoHashContext::Sha256(ctx) => {
                let cloned = ctx.clone();
                let digest = cloned.finalize();
                out.clear();
                out.extend_from_slice(&digest);
            }
            AppleCryptoHashContext::Sha384(ctx) => {
                let cloned = ctx.clone();
                let digest = cloned.finalize();
                out.clear();
                out.extend_from_slice(&digest);
            }
        }
    }
}

/// Hash provider implementation.
#[derive(Debug)]
pub(super) struct AppleCryptoHashProvider;

impl HashProvider for AppleCryptoHashProvider {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(AppleCryptoHashContext::Sha256(Sha256::new())),
            HashAlgorithm::SHA384 => Box::new(AppleCryptoHashContext::Sha384(Sha384::new())),
            _ => panic!("Unsupported hash algorithm: {:?}", algorithm),
        }
    }
}

/// Static instance of the hash provider.
pub(super) static HASH_PROVIDER: AppleCryptoHashProvider = AppleCryptoHashProvider;
