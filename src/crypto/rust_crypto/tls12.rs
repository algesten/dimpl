//! TLS 1.2 PRF, random number generation, and HMAC using RustCrypto.

use ::hmac::{Hmac, Mac};
use ::sha2::Sha256;

use crate::buffer::Buf;
use crate::crypto::provider::{HmacProvider, PrfProvider, SecureRandom};
use crate::message::HashAlgorithm;

use super::hmac;

/// PRF provider implementation for TLS 1.2.
#[derive(Debug)]
pub(super) struct RustCryptoPrfProvider;

impl PrfProvider for RustCryptoPrfProvider {
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

/// Secure random number generator implementation.
#[derive(Debug)]
pub(super) struct RustCryptoSecureRandom;

impl SecureRandom for RustCryptoSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), String> {
        use rand_core::OsRng;
        use rand_core::RngCore;
        OsRng.fill_bytes(buf);
        Ok(())
    }
}

/// HMAC provider implementation.
#[derive(Debug)]
pub(super) struct RustCryptoHmacProvider;

impl HmacProvider for RustCryptoHmacProvider {
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).map_err(|_| "Invalid HMAC key".to_string())?;
        mac.update(data);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut output = [0u8; 32];
        output.copy_from_slice(&bytes);
        Ok(output)
    }
}

/// Static instance of the PRF provider.
pub(super) static PRF_PROVIDER: RustCryptoPrfProvider = RustCryptoPrfProvider;

/// Static instance of the secure random generator.
pub(super) static SECURE_RANDOM: RustCryptoSecureRandom = RustCryptoSecureRandom;

/// Static instance of the HMAC provider.
pub(super) static HMAC_PROVIDER: RustCryptoHmacProvider = RustCryptoHmacProvider;
