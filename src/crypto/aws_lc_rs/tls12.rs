//! TLS 1.2 PRF, random number generation, HMAC, and SN cipher using aws-lc-rs.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use crate::buffer::Buf;
use crate::crypto::provider::{HmacProvider, PrfProvider, SecureRandom};
use crate::crypto::provider::{SnCipher, SnCipherProvider};
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
        out: &mut Buf,
        output_len: usize,
        scratch: &mut Buf,
        hash: HashAlgorithm,
    ) -> Result<(), String> {
        assert!(label.is_ascii(), "Label must be ASCII");

        // Use scratch buffer for full_seed concatenation
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);

        let algorithm = hmac::hmac_algorithm(hash)?;
        hmac::p_hash(algorithm, secret, scratch, out, output_len)
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
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        use aws_lc_rs::hmac;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&hmac_key, data);
        let mut result = [0u8; 32];
        result.copy_from_slice(tag.as_ref());
        Ok(result)
    }

    fn hmac_sha384(&self, key: &[u8], data: &[u8]) -> Result<[u8; 48], String> {
        use aws_lc_rs::hmac;
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA384, key);
        let tag = hmac::sign(&hmac_key, data);
        let mut result = [0u8; 48];
        result.copy_from_slice(tag.as_ref());
        Ok(result)
    }
}

/// Static instance of the PRF provider.
pub(super) static PRF_PROVIDER: AwsLcPrfProvider = AwsLcPrfProvider;

/// Static instance of the secure random generator.
pub(super) static SECURE_RANDOM: AwsLcSecureRandom = AwsLcSecureRandom;

/// Static instance of the HMAC provider.
pub(super) static HMAC_PROVIDER: AwsLcHmacProvider = AwsLcHmacProvider;

/// AES-128 sequence number cipher for DTLS 1.3 header protection.
#[derive(Debug)]
struct Aes128SnCipher(Aes128);

impl SnCipher for Aes128SnCipher {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let block_ref = aes::Block::from_mut_slice(block);
        self.0.encrypt_block(block_ref);
    }
}

/// AES-256 sequence number cipher for DTLS 1.3 header protection.
#[derive(Debug)]
struct Aes256SnCipher(Aes256);

impl SnCipher for Aes256SnCipher {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let block_ref = aes::Block::from_mut_slice(block);
        self.0.encrypt_block(block_ref);
    }
}

/// Sequence number cipher provider implementation.
#[derive(Debug)]
pub(super) struct AwsLcSnCipherProvider;

impl SnCipherProvider for AwsLcSnCipherProvider {
    fn create_sn_cipher(&self, key: &[u8]) -> Option<Box<dyn SnCipher>> {
        match key.len() {
            16 => Some(Box::new(Aes128SnCipher(Aes128::new_from_slice(key).ok()?))),
            32 => Some(Box::new(Aes256SnCipher(Aes256::new_from_slice(key).ok()?))),
            _ => None,
        }
    }
}

/// Static instance of the SN cipher provider.
pub(super) static SN_CIPHER_PROVIDER: AwsLcSnCipherProvider = AwsLcSnCipherProvider;
