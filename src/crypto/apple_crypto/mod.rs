//! Apple Security Framework cryptographic provider implementation for dimpl.
//!
//! This module provides a cryptographic backend for dimpl using Apple's
//! Security Framework and CommonCrypto.

#![allow(unsafe_code)]

mod cipher_suite;
mod hash;
mod hmac;
mod kx_group;
mod sign;
mod tls12;

use crate::crypto::provider::CryptoProvider;
use crate::crypto::SecureRandom;

/// Get the default Apple Security Framework based crypto provider.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: cipher_suite::ALL_CIPHER_SUITES,
        kx_groups: kx_group::ALL_KX_GROUPS,
        signature_verification: &sign::SIGNATURE_VERIFIER,
        key_provider: &sign::KEY_PROVIDER,
        secure_random: &SECURE_RANDOM,
        hash_provider: &hash::HASH_PROVIDER,
        prf_provider: &tls12::PRF_PROVIDER,
        hmac_provider: &hmac::HMAC_PROVIDER,
    }
}

#[derive(Debug)]
struct AppleSecureRandom;

impl SecureRandom for AppleSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), String> {
        use security_framework::random::SecRandom;
        let rng = SecRandom::default();
        rng.copy_bytes(buf)
            .map_err(|_| "Failed to generate random bytes".to_string())
    }
}

static SECURE_RANDOM: AppleSecureRandom = AppleSecureRandom;
