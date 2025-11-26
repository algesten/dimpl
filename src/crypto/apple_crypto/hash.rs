//! Hash implementations using Apple CommonCrypto.

use std::ffi::c_void;

use crate::buffer::Buf;
use crate::crypto::provider::{HashContext, HashProvider};
use crate::message::HashAlgorithm;

use super::common_crypto::*;

/// Hash context implementation using CommonCrypto.
/// We accumulate data and compute hash on finalization since CommonCrypto
/// doesn't expose streaming hash context for the functions we use.
enum AppleCryptoHashContext {
    Sha256(Vec<u8>),
    Sha384(Vec<u8>),
}

impl HashContext for AppleCryptoHashContext {
    fn update(&mut self, data: &[u8]) {
        match self {
            AppleCryptoHashContext::Sha256(buf) => buf.extend_from_slice(data),
            AppleCryptoHashContext::Sha384(buf) => buf.extend_from_slice(data),
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        match self {
            AppleCryptoHashContext::Sha256(buf) => {
                let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
                unsafe {
                    CC_SHA256(
                        buf.as_ptr() as *const c_void,
                        buf.len() as u32,
                        hash.as_mut_ptr(),
                    );
                }
                out.clear();
                out.extend_from_slice(&hash);
            }
            AppleCryptoHashContext::Sha384(buf) => {
                let mut hash = [0u8; CC_SHA384_DIGEST_LENGTH];
                unsafe {
                    CC_SHA384(
                        buf.as_ptr() as *const c_void,
                        buf.len() as u32,
                        hash.as_mut_ptr(),
                    );
                }
                out.clear();
                out.extend_from_slice(&hash);
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
            HashAlgorithm::SHA256 => Box::new(AppleCryptoHashContext::Sha256(Vec::new())),
            HashAlgorithm::SHA384 => Box::new(AppleCryptoHashContext::Sha384(Vec::new())),
            _ => panic!("Unsupported hash algorithm: {:?}", algorithm),
        }
    }
}

/// Static instance of the hash provider.
pub(super) static HASH_PROVIDER: AppleCryptoHashProvider = AppleCryptoHashProvider;
