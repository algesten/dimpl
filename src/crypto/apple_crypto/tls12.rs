//! TLS 1.2 PRF, random number generation, and HMAC using Apple CommonCrypto.

use std::ffi::c_void;

use crate::buffer::Buf;
use crate::crypto::provider::{HmacProvider, PrfProvider, SecureRandom};
use crate::message::HashAlgorithm;

use super::common_crypto::*;
use super::hmac;

// SecRandomCopyBytes from Security framework
#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecRandomCopyBytes(
        rnd: *const c_void,
        count: usize,
        bytes: *mut u8,
    ) -> i32;
}

// kSecRandomDefault is NULL
const K_SEC_RANDOM_DEFAULT: *const c_void = std::ptr::null();

/// PRF provider implementation for TLS 1.2.
#[derive(Debug)]
pub(super) struct AppleCryptoPrfProvider;

impl PrfProvider for AppleCryptoPrfProvider {
    fn prf_tls12(
        &self,
        secret: &[u8],
        label: &str,
        seed: &[u8],
        out: &mut Buf,
        output_len: usize,
        scratch: &mut Buf,
        hash: HashAlgorithm,
    ) -> Result<(), String> {
        assert!(label.is_ascii(), "Label must be ASCII");

        // Compute full_seed = label + seed using scratch buffer
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);

        hmac::p_hash(hash, secret, scratch, out, output_len)
    }
}

/// Secure random number generator implementation using Apple's Security framework.
#[derive(Debug)]
pub(super) struct AppleCryptoSecureRandom;

impl SecureRandom for AppleCryptoSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), String> {
        let result = unsafe {
            SecRandomCopyBytes(K_SEC_RANDOM_DEFAULT, buf.len(), buf.as_mut_ptr())
        };

        if result == 0 {
            Ok(())
        } else {
            Err(format!("SecRandomCopyBytes failed with error: {}", result))
        }
    }
}

/// HMAC provider implementation.
#[derive(Debug)]
pub(super) struct AppleCryptoHmacProvider;

impl HmacProvider for AppleCryptoHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        let mut output = [0u8; CC_SHA256_DIGEST_LENGTH];
        unsafe {
            CCHmac(
                K_CC_HMAC_ALG_SHA256,
                key.as_ptr() as *const c_void,
                key.len(),
                data.as_ptr() as *const c_void,
                data.len(),
                output.as_mut_ptr() as *mut c_void,
            );
        }
        Ok(output)
    }
}

/// Static instance of the PRF provider.
pub(super) static PRF_PROVIDER: AppleCryptoPrfProvider = AppleCryptoPrfProvider;

/// Static instance of the secure random generator.
pub(super) static SECURE_RANDOM: AppleCryptoSecureRandom = AppleCryptoSecureRandom;

/// Static instance of the HMAC provider.
pub(super) static HMAC_PROVIDER: AppleCryptoHmacProvider = AppleCryptoHmacProvider;
