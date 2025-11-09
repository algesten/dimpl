use std::panic::UnwindSafe;

use aws_lc_rs::aead::{Aad as AwsAad, LessSafeKey, Nonce as AwsNonce};
use aws_lc_rs::aead::{UnboundKey, AES_128_GCM, AES_256_GCM};

use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};

/// Cipher trait for DTLS encryption and decryption
pub trait Cipher: Send + Sync + UnwindSafe {
    /// Encrypt plaintext in-place
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String>;

    /// Decrypt ciphertext in-place
    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String>;
}

/// AES-GCM implementation using aws-lc-rs
pub struct AesGcm {
    key: LessSafeKey,
}

impl AesGcm {
    /// Create a new AES-GCM cipher with the specified key size
    pub fn new(key: &[u8]) -> Result<Self, String> {
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
        // Make sure we have enough data for the tag (16 bytes)
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

        // Truncate buffer to plaintext length (removes the tag)
        let plaintext_len = plaintext.len();
        ciphertext.truncate(plaintext_len);

        Ok(())
    }
}
