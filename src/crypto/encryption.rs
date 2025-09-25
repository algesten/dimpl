use std::panic::UnwindSafe;

use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::{aead::KeyInit, Aes128Gcm, Aes256Gcm};

use crate::buffer::Buf;
use crate::crypto::{Aad, Nonce};

/// Cipher trait for DTLS encryption and decryption
pub trait Cipher: Send + Sync + UnwindSafe {
    /// Encrypt plaintext in-place
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String>;

    /// Decrypt ciphertext in-place
    fn decrypt(&mut self, ciphertext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String>;
}

/// AES-GCM implementation with different key sizes
pub enum AesGcm {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl AesGcm {
    /// Create a new AES-GCM cipher with the specified key size
    pub fn new(key: &[u8]) -> Result<Self, String> {
        match key.len() {
            16 => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| "Failed to create AES-128-GCM cipher".to_string())?;
                Ok(AesGcm::Aes128(Box::new(cipher)))
            }
            32 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| "Failed to create AES-256-GCM cipher".to_string())?;
                Ok(AesGcm::Aes256(Box::new(cipher)))
            }
            _ => Err(format!("Invalid key size for AES-GCM: {}", key.len())),
        }
    }
}

impl Cipher for AesGcm {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        let nonce = aes_gcm::Nonce::from_slice(&nonce);

        // Perform encryption based on the cipher variant
        let result = match self {
            AesGcm::Aes128(cipher) => {
                cipher
                    .encrypt_in_place(nonce, &aad, plaintext)
                    .map_err(|e| format!("AES-GCM encryption failed: {:?}", e))?;
                Ok(())
            }
            AesGcm::Aes256(cipher) => {
                cipher
                    .encrypt_in_place(nonce, &aad, plaintext)
                    .map_err(|e| format!("AES-GCM encryption failed: {:?}", e))?;
                Ok(())
            }
        };

        result
    }

    fn decrypt(&mut self, ciphertext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        // Make sure we have enough data for the tag (16 bytes)
        if ciphertext.len() < 16 {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        let nonce = aes_gcm::Nonce::from_slice(&nonce);

        // Perform decryption based on the cipher variant
        let result = match self {
            AesGcm::Aes128(cipher) => {
                cipher
                    .decrypt_in_place(nonce, &aad, ciphertext)
                    .map_err(|e| format!("AES-GCM decryption failed: {:?}", e))?;
                Ok(())
            }
            AesGcm::Aes256(cipher) => {
                cipher
                    .decrypt_in_place(nonce, &aad, ciphertext)
                    .map_err(|e| format!("AES-GCM decryption failed: {:?}", e))?;
                Ok(())
            }
        };

        result
    }
}
