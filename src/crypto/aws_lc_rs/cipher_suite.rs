//! Cipher suite implementations using aws-lc-rs.

use aws_lc_rs::aead::{Aad as AwsAad, LessSafeKey, Nonce as AwsNonce};
use aws_lc_rs::aead::{UnboundKey, AES_128_GCM, AES_256_GCM};

use super::super::{Cipher, SupportedDtls12CipherSuite, SupportedDtls13CipherSuite};
use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};
use crate::dtls12::message::Dtls12CipherSuite;
use crate::types::{Dtls13CipherSuite, HashAlgorithm};

/// AES-GCM cipher implementation using aws-lc-rs.
struct AesGcm {
    key: LessSafeKey,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, String> {
        let algorithm = match key.len() {
            16 => &AES_128_GCM,
            32 => &AES_256_GCM,
            _ => return Err(format!("Invalid key size for AES-GCM: {}", key.len())),
        };

        let unbound_key = UnboundKey::new(algorithm, key)
            .map_err(|_| "Failed to create AES-GCM cipher".to_string())?;

        Ok(AesGcm {
            key: LessSafeKey::new(unbound_key),
        })
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        let aws_nonce =
            AwsNonce::try_assume_unique_for_key(&nonce).map_err(|_| "Invalid nonce".to_string())?;

        let aws_aad = AwsAad::from(&aad[..]);

        self.key
            .seal_in_place_append_tag(aws_nonce, aws_aad, plaintext)
            .map_err(|_| "AES-GCM encryption failed".to_string())?;

        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < 16 {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        let aws_nonce =
            AwsNonce::try_assume_unique_for_key(&nonce).map_err(|_| "Invalid nonce".to_string())?;

        let aws_aad = AwsAad::from(&aad[..]);

        let plaintext = self
            .key
            .open_in_place(aws_nonce, aws_aad, ciphertext.as_mut())
            .map_err(|_| "AES-GCM decryption failed".to_string())?;

        let plaintext_len = plaintext.len();
        ciphertext.truncate(plaintext_len);

        Ok(())
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.
#[derive(Debug)]
struct Aes128GcmSha256;

impl SupportedDtls12CipherSuite for Aes128GcmSha256 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 16, 4) // (mac_key_len, enc_key_len, fixed_iv_len)
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite.
#[derive(Debug)]
struct Aes256GcmSha384;

impl SupportedDtls12CipherSuite for Aes256GcmSha384 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 32, 4) // (mac_key_len, enc_key_len, fixed_iv_len)
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// Static instances of supported DTLS 1.2 cipher suites.
static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;

/// All supported DTLS 1.2 cipher suites.
pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedDtls12CipherSuite] =
    &[&AES_128_GCM_SHA256, &AES_256_GCM_SHA384];

// ============================================================================
// DTLS 1.3 Cipher Suites
// ============================================================================

/// TLS_AES_128_GCM_SHA256 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13Aes128GcmSha256;

impl SupportedDtls13CipherSuite for Tls13Aes128GcmSha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_128_GCM_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_len(&self) -> usize {
        16 // AES-128
    }

    fn iv_len(&self) -> usize {
        12 // GCM IV
    }

    fn tag_len(&self) -> usize {
        16 // GCM tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// TLS_AES_256_GCM_SHA384 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13Aes256GcmSha384;

impl SupportedDtls13CipherSuite for Tls13Aes256GcmSha384 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::AES_256_GCM_SHA384
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn key_len(&self) -> usize {
        32 // AES-256
    }

    fn iv_len(&self) -> usize {
        12 // GCM IV
    }

    fn tag_len(&self) -> usize {
        16 // GCM tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// Static instances of supported DTLS 1.3 cipher suites.
static TLS13_AES_128_GCM_SHA256: Tls13Aes128GcmSha256 = Tls13Aes128GcmSha256;
static TLS13_AES_256_GCM_SHA384: Tls13Aes256GcmSha384 = Tls13Aes256GcmSha384;

/// All supported DTLS 1.3 cipher suites.
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] =
    &[&TLS13_AES_128_GCM_SHA256, &TLS13_AES_256_GCM_SHA384];
