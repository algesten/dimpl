//! Hash implementations using Apple CommonCrypto streaming API.

use std::ffi::c_void;

use crate::buffer::Buf;
use crate::crypto::provider::{HashContext, HashProvider};
use crate::message::HashAlgorithm;

use super::common_crypto::*;

/// Hash context implementation using CommonCrypto streaming API.
enum AppleCryptoHashContext {
    Sha256(CcSha256Ctx),
    Sha384(CcSha512Ctx),
}

impl AppleCryptoHashContext {
    fn new_sha256() -> Self {
        let mut ctx = CcSha256Ctx {
            data: [0u8; CC_SHA256_CTX_SIZE],
        };
        unsafe {
            CC_SHA256_Init(&mut ctx);
        }
        AppleCryptoHashContext::Sha256(ctx)
    }

    fn new_sha384() -> Self {
        let mut ctx = CcSha512Ctx {
            data: [0u8; CC_SHA512_CTX_SIZE],
        };
        unsafe {
            CC_SHA384_Init(&mut ctx);
        }
        AppleCryptoHashContext::Sha384(ctx)
    }
}

impl HashContext for AppleCryptoHashContext {
    fn update(&mut self, data: &[u8]) {
        match self {
            AppleCryptoHashContext::Sha256(ctx) => unsafe {
                CC_SHA256_Update(ctx, data.as_ptr() as *const c_void, data.len() as u32);
            },
            AppleCryptoHashContext::Sha384(ctx) => unsafe {
                CC_SHA384_Update(ctx, data.as_ptr() as *const c_void, data.len() as u32);
            },
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        match self {
            AppleCryptoHashContext::Sha256(ctx) => {
                // Clone the context by copying the internal state
                let mut cloned = *ctx;
                let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
                unsafe {
                    CC_SHA256_Final(hash.as_mut_ptr(), &mut cloned);
                }
                out.clear();
                out.extend_from_slice(&hash);
            }
            AppleCryptoHashContext::Sha384(ctx) => {
                // Clone the context by copying the internal state
                let mut cloned = *ctx;
                let mut hash = [0u8; CC_SHA384_DIGEST_LENGTH];
                unsafe {
                    CC_SHA384_Final(hash.as_mut_ptr(), &mut cloned);
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
            HashAlgorithm::SHA256 => Box::new(AppleCryptoHashContext::new_sha256()),
            HashAlgorithm::SHA384 => Box::new(AppleCryptoHashContext::new_sha384()),
            _ => panic!("Unsupported hash algorithm: {:?}", algorithm),
        }
    }
}

/// Static instance of the hash provider.
pub(super) static HASH_PROVIDER: AppleCryptoHashProvider = AppleCryptoHashProvider;
