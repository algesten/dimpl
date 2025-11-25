//! TLS 1.2 PRF, random number generation, and HMAC using aws-lc-rs.

use crate::crypto::provider::{HmacProvider, PrfProvider, SecureRandom};
use crate::message::HashAlgorithm;

use super::hmac;

/// PRF provider implementation for TLS 1.2.
#[derive(Debug)]
pub(super) struct AwsLcPrfProvider;

impl PrfProvider for AwsLcPrfProvider {
    fn prf_tls12(
        &self,
        secret: &[u8],
        label: &str,
        seed: &[u8],
        output_len: usize,
        hash: HashAlgorithm,
    ) -> Result<Vec<u8>, String> {
        assert!(label.is_ascii(), "Label must be ASCII");

        // Compute full_seed = label + seed
        let mut full_seed = Vec::with_capacity(label.len() + seed.len());
        full_seed.extend_from_slice(label.as_bytes());
        full_seed.extend_from_slice(seed);

        let algorithm = hmac::hmac_algorithm(hash)?;
        hmac::p_hash(algorithm, secret, &full_seed, output_len)
    }
}

/// Secure random number generator implementation.
#[derive(Debug)]
pub(super) struct AwsLcSecureRandom;

impl SecureRandom for AwsLcSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), String> {
        use aws_lc_rs::rand::SecureRandom as _;
        let rng = aws_lc_rs::rand::SystemRandom::new();
        rng.fill(buf)
            .map_err(|_| "Failed to generate random bytes".to_string())
    }
}

/// HMAC provider implementation.
#[derive(Debug)]
pub(super) struct AwsLcHmacProvider;

impl HmacProvider for AwsLcHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        use aws_lc_rs::hmac;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&hmac_key, data);
        Ok(tag.as_ref().to_vec())
    }
}

/// Static instance of the PRF provider.
pub(super) static PRF_PROVIDER: AwsLcPrfProvider = AwsLcPrfProvider;

/// Static instance of the secure random generator.
pub(super) static SECURE_RANDOM: AwsLcSecureRandom = AwsLcSecureRandom;

/// Static instance of the HMAC provider.
pub(super) static HMAC_PROVIDER: AwsLcHmacProvider = AwsLcHmacProvider;
