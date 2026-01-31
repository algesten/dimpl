//! Cipher suite implementations using RustCrypto.
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aes::{Aes128, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key};

use super::super::{Cipher, SupportedDtls12CipherSuite, SupportedDtls13CipherSuite};
use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};
use crate::dtls12::message::Dtls12CipherSuite;
use crate::types::{Dtls13CipherSuite, HashAlgorithm};

/// AES-GCM cipher implementation using RustCrypto.
enum AesGcm {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AesGcm::Aes128(_) => f.debug_tuple("AesGcm::Aes128").finish(),
            AesGcm::Aes256(_) => f.debug_tuple("AesGcm::Aes256").finish(),
        }
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, String> {
        match key.len() {
            16 => {
                let key = Key::<Aes128Gcm>::from_slice(key);
                Ok(AesGcm::Aes128(Box::new(Aes128Gcm::new(key))))
            }
            32 => {
                let key = Key::<Aes256Gcm>::from_slice(key);
                Ok(AesGcm::Aes256(Box::new(Aes256Gcm::new(key))))
            }
            _ => Err(format!("Invalid key size for AES-GCM: {}", key.len())),
        }
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, data: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        // AES-GCM nonce is 12 bytes
        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12, got {}",
                nonce.len()
            ));
        }

        // Create nonce from the provided nonce bytes
        let nonce_array: [u8; 12] = nonce[..12].try_into().map_err(|_| "Invalid nonce")?;

        match self {
            AesGcm::Aes128(cipher) => {
                // Create nonce from fixed-size array - AesNonce is GenericArray<u8, U12>
                use generic_array::{typenum::U12, GenericArray};
                let aes_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
                cipher
                    .encrypt_in_place(&aes_nonce, &aad, data)
                    .map_err(|_| "AES-GCM encryption failed".to_string())?;
            }
            AesGcm::Aes256(cipher) => {
                // Create nonce from fixed-size array - AesNonce is GenericArray<u8, U12>
                use generic_array::{typenum::U12, GenericArray};
                let aes_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
                cipher
                    .encrypt_in_place(&aes_nonce, &aad, data)
                    .map_err(|_| "AES-GCM encryption failed".to_string())?;
            }
        }

        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < 16 {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        // AES-GCM nonce is 12 bytes
        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12, got {}",
                nonce.len()
            ));
        }

        // Create nonce from the provided nonce bytes
        let nonce_array: [u8; 12] = nonce[..12].try_into().map_err(|_| "Invalid nonce")?;

        match self {
            AesGcm::Aes128(cipher) => {
                // Create nonce from fixed-size array - AesNonce is GenericArray<u8, U12>
                use generic_array::{typenum::U12, GenericArray};
                let aes_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
                cipher
                    .decrypt_in_place(&aes_nonce, &aad, ciphertext)
                    .map_err(|_| "AES-GCM decryption failed".to_string())?;
            }
            AesGcm::Aes256(cipher) => {
                // Create nonce from fixed-size array - AesNonce is GenericArray<u8, U12>
                use generic_array::{typenum::U12, GenericArray};
                let aes_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
                cipher
                    .decrypt_in_place(&aes_nonce, &aad, ciphertext)
                    .map_err(|_| "AES-GCM decryption failed".to_string())?;
            }
        }

        // decrypt_in_place already removes the tag and shortens the buffer
        // No need to truncate further

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

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        // unwrap: sn_key length matches AES-128 key size
        let cipher = Aes128::new_from_slice(sn_key).unwrap();
        let mut block = aes_gcm::aes::Block::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);
        block.into()
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

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        // unwrap: sn_key length matches AES-256 key size
        let cipher = Aes256::new_from_slice(sn_key).unwrap();
        let mut block = aes_gcm::aes::Block::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);
        block.into()
    }
}

/// Static instances of supported DTLS 1.3 cipher suites.
static TLS13_AES_128_GCM_SHA256: Tls13Aes128GcmSha256 = Tls13Aes128GcmSha256;
static TLS13_AES_256_GCM_SHA384: Tls13Aes256GcmSha384 = Tls13Aes256GcmSha384;

/// All supported DTLS 1.3 cipher suites.
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] =
    &[&TLS13_AES_128_GCM_SHA256, &TLS13_AES_256_GCM_SHA384];
