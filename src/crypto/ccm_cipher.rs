//! AES-128-CCM-8 cipher implementation using the RustCrypto `ccm` crate.
//!
//! Shared by both aws-lc-rs and rust-crypto backends since aws-lc-rs
//! does not expose CCM in its high-level API.

use ccm::aead::AeadInPlace;
use ccm::aead::KeyInit;
use ccm::consts::{U8, U12};

use super::{Aad, Cipher, Nonce};
use crate::buffer::{Buf, TmpBuf};

/// AES-128-CCM with 8-byte tag, 12-byte nonce.
type Aes128Ccm8 = ccm::Ccm<aes::Aes128, U8, U12>;

/// AES-128-CCM-8 cipher for TLS_PSK_WITH_AES_128_CCM_8.
pub struct AesCcm8Cipher {
    cipher: Box<Aes128Ccm8>,
}

impl std::fmt::Debug for AesCcm8Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesCcm8Cipher").finish_non_exhaustive()
    }
}

impl AesCcm8Cipher {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 16 {
            return Err(format!("Invalid key size for AES-128-CCM-8: {}", key.len()));
        }
        let cipher = Aes128Ccm8::new_from_slice(key)
            .map_err(|_| "Failed to create AES-128-CCM-8 cipher".to_string())?;
        Ok(AesCcm8Cipher {
            cipher: Box::new(cipher),
        })
    }
}

impl Cipher for AesCcm8Cipher {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12, got {}",
                nonce.len()
            ));
        }

        let ccm_nonce = ccm::aead::generic_array::GenericArray::from_slice(&nonce[..12]);
        let tag = self
            .cipher
            .encrypt_in_place_detached(ccm_nonce, &aad[..], plaintext.as_mut())
            .map_err(|_| "AES-128-CCM-8 encryption failed".to_string())?;

        // Append the 8-byte tag
        plaintext.extend_from_slice(&tag);

        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < 8 {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12, got {}",
                nonce.len()
            ));
        }

        let ccm_nonce = ccm::aead::generic_array::GenericArray::from_slice(&nonce[..12]);

        // Split off the 8-byte tag from the end
        let data_len = ciphertext.len() - 8;
        let mut tag_bytes = [0u8; 8];
        tag_bytes.copy_from_slice(&ciphertext.as_ref()[data_len..]);
        let tag = ccm::aead::generic_array::GenericArray::from(tag_bytes);

        // Truncate to just the ciphertext (without tag)
        ciphertext.truncate(data_len);

        self.cipher
            .decrypt_in_place_detached(ccm_nonce, &aad[..], ciphertext.as_mut(), &tag)
            .map_err(|_| "AES-128-CCM-8 decryption failed".to_string())?;

        Ok(())
    }
}
