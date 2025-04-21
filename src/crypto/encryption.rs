use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};

use crate::buffer::Buffer;

/// Cipher trait for DTLS encryption and decryption
pub trait Cipher: Send + Sync {
    /// Encrypt plaintext in-place
    fn encrypt(&self, plaintext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), String>;

    /// Decrypt ciphertext in-place
    fn decrypt(&self, ciphertext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), String>;
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
            return Err(format!("Invalid nonce length: {}", nonce.len()));
        }

        let nonce = Nonce::from_slice(nonce);
        let plaintext_data = plaintext.as_slice();

        // Perform encryption based on the cipher variant
        let result = match self {
            AesGcm::Aes128(cipher) => {
                let ciphertext = cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: plaintext_data,
                            aad,
                        },
                    )
                    .map_err(|e| format!("AES-GCM encryption failed: {:?}", e))?;

                // Replace plaintext with ciphertext
                plaintext.clear();
                plaintext.extend_from_slice(&ciphertext);
                Ok(())
            }
            AesGcm::Aes256(cipher) => {
                let ciphertext = cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: plaintext_data,
                            aad,
                        },
                    )
                    .map_err(|e| format!("AES-GCM encryption failed: {:?}", e))?;

                // Replace plaintext with ciphertext
                plaintext.clear();
                plaintext.extend_from_slice(&ciphertext);
                Ok(())
            }
        };

        result
    }

    fn decrypt(&self, ciphertext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), String> {
        if nonce.len() != 12 {
            return Err(format!("Invalid nonce length: {}", nonce.len()));
        }

        // Make sure we have enough data for the tag (16 bytes)
        if ciphertext.len() < 16 {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        let nonce = Nonce::from_slice(nonce);
        let ciphertext_data = ciphertext.as_slice();

        // Perform decryption based on the cipher variant
        let result = match self {
            AesGcm::Aes128(cipher) => {
                let plaintext = cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: ciphertext_data,
                            aad,
                        },
                    )
                    .map_err(|e| format!("AES-GCM decryption failed: {:?}", e))?;

                // Replace ciphertext with plaintext
                ciphertext.clear();
                ciphertext.extend_from_slice(&plaintext);
                Ok(())
            }
            AesGcm::Aes256(cipher) => {
                let plaintext = cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: ciphertext_data,
                            aad,
                        },
                    )
                    .map_err(|e| format!("AES-GCM decryption failed: {:?}", e))?;

                // Replace ciphertext with plaintext
                ciphertext.clear();
                ciphertext.extend_from_slice(&plaintext);
                Ok(())
            }
        };

        result
    }
}
