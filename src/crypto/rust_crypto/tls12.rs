//! TLS 1.2 PRF, random number generation, HMAC, and SN cipher using RustCrypto.

use ::hmac::{Hmac, Mac};
use ::sha2::{Sha256, Sha384};
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::{Aes128, Aes256};

use crate::buffer::Buf;
use crate::crypto::provider::{HmacProvider, PrfProvider, SecureRandom};
use crate::crypto::provider::{SnCipher, SnCipherProvider};
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
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| "Invalid HMAC key".to_string())?;
        mac.update(data);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut output = [0u8; 32];
        output.copy_from_slice(&bytes);
        Ok(output)
    }

    fn hmac_sha384(&self, key: &[u8], data: &[u8]) -> Result<[u8; 48], String> {
        let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key)
            .map_err(|_| "Invalid HMAC key".to_string())?;
        mac.update(data);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut output = [0u8; 48];
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
pub(super) struct RustCryptoSnCipherProvider;

impl SnCipherProvider for RustCryptoSnCipherProvider {
    fn create_sn_cipher(&self, key: &[u8]) -> Option<Box<dyn SnCipher>> {
        match key.len() {
            16 => Some(Box::new(Aes128SnCipher(
                AesKeyInit::new_from_slice(key).ok()?,
            ))),
            32 => Some(Box::new(Aes256SnCipher(
                AesKeyInit::new_from_slice(key).ok()?,
            ))),
            _ => None,
        }
    }
}

/// Static instance of the SN cipher provider.
pub(super) static SN_CIPHER_PROVIDER: RustCryptoSnCipherProvider = RustCryptoSnCipherProvider;
