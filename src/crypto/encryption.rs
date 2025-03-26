use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce, Tag,
};
use rand::{rngs::OsRng, Rng, RngCore};

/// Trait for encryption/decryption operations
pub trait Cipher {
    /// Encrypt data with additional authenticated data (AAD)
    fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String>;

    /// Decrypt data with additional authenticated data (AAD)
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String>;

    /// Generate a random nonce
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
    fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err("AES-GCM nonce must be 12 bytes".to_string());
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        match self {
            AesGcm::Aes128(cipher) => cipher
                .encrypt(nonce, payload)
                .map_err(|_| "Encryption failed".to_string()),
            AesGcm::Aes256(cipher) => cipher
                .encrypt(nonce, payload)
                .map_err(|_| "Encryption failed".to_string()),
        }
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        if nonce.len() != 12 {
            return Err("AES-GCM nonce must be 12 bytes".to_string());
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        match self {
            AesGcm::Aes128(cipher) => cipher
                .decrypt(nonce, payload)
                .map_err(|_| "Decryption failed".to_string()),
            AesGcm::Aes256(cipher) => cipher
                .decrypt(nonce, payload)
                .map_err(|_| "Decryption failed".to_string()),
        }
    }

    fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}
