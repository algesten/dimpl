//! Cipher suite implementations using Apple CommonCrypto.

use std::ffi::c_void;
use std::ptr;

use crate::buffer::{Buf, TmpBuf};
use crate::crypto::provider::{Cipher, SupportedCipherSuite};
use crate::crypto::{Aad, Nonce};
use crate::message::{CipherSuite, HashAlgorithm};

use super::common_crypto::*;

const AEAD_AES_GCM_TAG_LEN: usize = 16;

/// AES-GCM cipher implementation using CommonCrypto.
struct AesGcm {
    key_data: Vec<u8>,
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.key_data.len() {
            16 => f.debug_tuple("AesGcm::Aes128").finish(),
            32 => f.debug_tuple("AesGcm::Aes256").finish(),
            _ => f.debug_tuple("AesGcm::Unknown").finish(),
        }
    }
}

impl AesGcm {
    fn new(key: &[u8]) -> Result<Self, String> {
        match key.len() {
            K_CC_AES_KEY_SIZE_128 | K_CC_AES_KEY_SIZE_256 => Ok(AesGcm {
                key_data: key.to_vec(),
            }),
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

        let mut cryptor: *mut c_void = ptr::null_mut();

        // Create GCM mode cryptor
        let status = unsafe {
            CCCryptorCreateWithMode(
                K_CC_ENCRYPT,
                K_CC_MODE_GCM,
                K_CC_ALGORITHM_AES,
                0,           // No padding for GCM
                ptr::null(), // IV will be added separately
                self.key_data.as_ptr(),
                self.key_data.len(),
                ptr::null(), // No tweak
                0,           // No tweak length
                0,           // Default rounds
                0,           // No mode options
                &mut cryptor,
            )
        };

        if status != 0 {
            return Err(format!("Failed to create AES GCM cryptor: {}", status));
        }

        // Add IV/nonce
        let status = unsafe { CCCryptorGCMAddIV(cryptor, nonce.as_ptr(), nonce.len()) };
        if status != 0 {
            unsafe { CCCryptorRelease(cryptor) };
            return Err(format!("Failed to add IV: {}", status));
        }

        // Add additional authenticated data
        let status = unsafe { CCCryptorGCMAddAAD(cryptor, aad.as_ptr(), aad.len()) };
        if status != 0 {
            unsafe { CCCryptorRelease(cryptor) };
            return Err(format!("Failed to add AAD: {}", status));
        }

        // Encrypt the plaintext
        let plain_len = data.len();
        let mut cipher_text = vec![0u8; plain_len + AEAD_AES_GCM_TAG_LEN];

        let status = unsafe {
            CCCryptorGCMEncrypt(cryptor, data.as_ptr(), plain_len, cipher_text.as_mut_ptr())
        };
        if status != 0 {
            unsafe { CCCryptorRelease(cryptor) };
            return Err(format!("Failed to encrypt: {}", status));
        }

        // Get the authentication tag
        let mut tag_len = AEAD_AES_GCM_TAG_LEN;
        let tag_ptr = unsafe { cipher_text.as_mut_ptr().add(plain_len) };
        let status = unsafe { CCCryptorGCMFinal(cryptor, tag_ptr, &mut tag_len) };

        unsafe { CCCryptorRelease(cryptor) };

        if status != 0 {
            return Err(format!("Failed to get authentication tag: {}", status));
        }

        // Replace data with ciphertext + tag
        data.clear();
        data.extend_from_slice(&cipher_text[..plain_len + tag_len]);

        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < AEAD_AES_GCM_TAG_LEN {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        // AES-GCM nonce is 12 bytes
        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12, got {}",
                nonce.len()
            ));
        }

        let ciphertext_len = ciphertext.len();
        let cipher_data_len = ciphertext_len - AEAD_AES_GCM_TAG_LEN;

        // Get access to the underlying data for decryption in-place
        let data = ciphertext.as_mut();

        let mut cryptor: *mut c_void = ptr::null_mut();

        // Create GCM mode cryptor for decryption
        let status = unsafe {
            CCCryptorCreateWithMode(
                K_CC_DECRYPT,
                K_CC_MODE_GCM,
                K_CC_ALGORITHM_AES,
                0,           // No padding for GCM
                ptr::null(), // IV will be added separately
                self.key_data.as_ptr(),
                self.key_data.len(),
                ptr::null(), // No tweak
                0,           // No tweak length
                0,           // Default rounds
                0,           // No mode options
                &mut cryptor,
            )
        };

        if status != 0 {
            return Err(format!("Failed to create AES GCM cryptor: {}", status));
        }

        // Add IV
        let status = unsafe { CCCryptorGCMAddIV(cryptor, nonce.as_ptr(), nonce.len()) };
        if status != 0 {
            unsafe { CCCryptorRelease(cryptor) };
            return Err(format!("Failed to add IV: {}", status));
        }

        // Add additional authenticated data
        let status = unsafe { CCCryptorGCMAddAAD(cryptor, aad.as_ptr(), aad.len()) };
        if status != 0 {
            unsafe { CCCryptorRelease(cryptor) };
            return Err(format!("Failed to add AAD: {}", status));
        }

        // Copy the tag before we overwrite the buffer
        let mut expected_tag = [0u8; AEAD_AES_GCM_TAG_LEN];
        expected_tag.copy_from_slice(&data[cipher_data_len..]);

        // Decrypt the ciphertext to a temporary buffer
        // (CommonCrypto does not guarantee in-place decryption safety)
        let mut plain_text = vec![0u8; cipher_data_len];

        let status = unsafe {
            CCCryptorGCMDecrypt(
                cryptor,
                data.as_ptr(),
                cipher_data_len,
                plain_text.as_mut_ptr(),
            )
        };
        if status != 0 {
            unsafe { CCCryptorRelease(cryptor) };
            return Err(format!("Failed to decrypt: {}", status));
        }

        // Verify the authentication tag
        let mut computed_tag = [0u8; AEAD_AES_GCM_TAG_LEN];
        let mut tag_len = AEAD_AES_GCM_TAG_LEN;
        let status = unsafe { CCCryptorGCMFinal(cryptor, computed_tag.as_mut_ptr(), &mut tag_len) };

        unsafe { CCCryptorRelease(cryptor) };

        if status != 0 {
            return Err(format!("Failed to get authentication tag: {}", status));
        }

        // Constant-time comparison of tags to prevent timing attacks
        let mut diff = 0u8;
        for (a, b) in expected_tag.iter().zip(computed_tag[..tag_len].iter()) {
            diff |= a ^ b;
        }
        // Also check length mismatch
        diff |= (expected_tag.len() != tag_len) as u8;

        if diff != 0 {
            return Err("Authentication tag verification failed".to_string());
        }

        // Copy plaintext back to the buffer and truncate
        data[..cipher_data_len].copy_from_slice(&plain_text);
        ciphertext.truncate(cipher_data_len);

        Ok(())
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        // Zero out the key data for security
        self.key_data.fill(0);
    }
}

/// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.
#[derive(Debug)]
struct Aes128GcmSha256;

impl SupportedCipherSuite for Aes128GcmSha256 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
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

impl SupportedCipherSuite for Aes256GcmSha384 {
    fn suite(&self) -> CipherSuite {
        CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
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

/// Static instances of supported cipher suites.
static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;

/// All supported cipher suites.
pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedCipherSuite] =
    &[&AES_128_GCM_SHA256, &AES_256_GCM_SHA384];
