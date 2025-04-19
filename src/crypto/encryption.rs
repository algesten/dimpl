use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::buffer::Buffer;

/// Cipher trait for DTLS encryption and decryption
pub trait Cipher {
    /// Encrypt plaintext in-place
    fn encrypt(&self, plaintext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), String>;

    /// Decrypt ciphertext in-place
    fn decrypt(&self, ciphertext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), String>;

    /// Generate a random nonce suitable for this cipher
    fn generate_nonce(&self) -> Vec<u8>;
}

/// AES-GCM implementation with different key sizes
pub enum AesGcm {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl AesGcm {
    /// Create a new AES-GCM cipher with the specified key size
    pub fn new(key: &[u8]) -> Result<Self, String> {
        match key.len() {
            16 => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| "Failed to create AES-128-GCM cipher".to_string())?;
                Ok(AesGcm::Aes128(cipher))
            }
            32 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| "Failed to create AES-256-GCM cipher".to_string())?;
                Ok(AesGcm::Aes256(cipher))
            }
            _ => Err(format!("Invalid key size for AES-GCM: {}", key.len())),
        }
    }
}

impl Cipher for AesGcm {
    fn encrypt(&self, plaintext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), String> {
        if nonce.len() != 12 {
            return Err("AES-GCM nonce must be 12 bytes".to_string());
        }

        let nonce = Nonce::from_slice(nonce);

        match self {
            AesGcm::Aes128(cipher) => cipher
                .encrypt_in_place(nonce, aad, plaintext)
                .map_err(|_| "Encryption failed".to_string()),
            AesGcm::Aes256(cipher) => cipher
                .encrypt_in_place(nonce, aad, plaintext)
                .map_err(|_| "Encryption failed".to_string()),
        }?;

        Ok(())
    }

    fn decrypt(&self, ciphertext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), String> {
        if nonce.len() != 12 {
            return Err("AES-GCM nonce must be 12 bytes".to_string());
        }

        let nonce = Nonce::from_slice(nonce);

        match self {
            AesGcm::Aes128(cipher) => cipher
                .decrypt_in_place(nonce, aad, ciphertext)
                .map_err(|_| "Decryption failed".to_string()),
            AesGcm::Aes256(cipher) => cipher
                .decrypt_in_place(nonce, aad, ciphertext)
                .map_err(|_| "Decryption failed".to_string()),
        }?;

        Ok(())
    }

    fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 12]; // AES-GCM requires a 12-byte nonce
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }
}
