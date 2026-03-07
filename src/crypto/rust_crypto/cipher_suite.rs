//! Cipher suite implementations using RustCrypto.
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aes::{Aes128, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::ChaCha20Poly1305 as ChaCha20Poly1305Aead;

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
                use generic_array::{GenericArray, typenum::U12};
                let aes_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
                cipher
                    .encrypt_in_place(&aes_nonce, &aad, data)
                    .map_err(|_| "AES-GCM encryption failed".to_string())?;
            }
            AesGcm::Aes256(cipher) => {
                // Create nonce from fixed-size array - AesNonce is GenericArray<u8, U12>
                use generic_array::{GenericArray, typenum::U12};
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
                use generic_array::{GenericArray, typenum::U12};
                let aes_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
                cipher
                    .decrypt_in_place(&aes_nonce, &aad, ciphertext)
                    .map_err(|_| "AES-GCM decryption failed".to_string())?;
            }
            AesGcm::Aes256(cipher) => {
                // Create nonce from fixed-size array - AesNonce is GenericArray<u8, U12>
                use generic_array::{GenericArray, typenum::U12};
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

/// ChaCha20-Poly1305 cipher implementation using RustCrypto.
struct ChaCha20Poly1305Cipher {
    cipher: Box<ChaCha20Poly1305Aead>,
}

impl std::fmt::Debug for ChaCha20Poly1305Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Poly1305Cipher")
            .finish_non_exhaustive()
    }
}

impl ChaCha20Poly1305Cipher {
    fn new(key: &[u8]) -> Result<Self, String> {
        use chacha20poly1305::KeyInit;
        if key.len() != 32 {
            return Err(format!(
                "Invalid key size for CHACHA20-POLY1305: {}",
                key.len()
            ));
        }
        let key = chacha20poly1305::Key::from_slice(key);
        Ok(ChaCha20Poly1305Cipher {
            cipher: Box::new(ChaCha20Poly1305Aead::new(key)),
        })
    }
}

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&mut self, data: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12, got {}",
                nonce.len()
            ));
        }

        let nonce_array: [u8; 12] = nonce[..12].try_into().map_err(|_| "Invalid nonce")?;

        use generic_array::{GenericArray, typenum::U12};
        let chacha_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
        self.cipher
            .encrypt_in_place(&chacha_nonce, &aad, data)
            .map_err(|_| "ChaCha20-Poly1305 encryption failed".to_string())?;

        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String> {
        if ciphertext.len() < 16 {
            return Err(format!("Ciphertext too short: {}", ciphertext.len()));
        }

        if nonce.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12, got {}",
                nonce.len()
            ));
        }

        let nonce_array: [u8; 12] = nonce[..12].try_into().map_err(|_| "Invalid nonce")?;

        use generic_array::{GenericArray, typenum::U12};
        let chacha_nonce = GenericArray::<u8, U12>::clone_from_slice(&nonce_array);
        self.cipher
            .decrypt_in_place(&chacha_nonce, &aad, ciphertext)
            .map_err(|_| "ChaCha20-Poly1305 decryption failed".to_string())?;

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

    fn explicit_nonce_len(&self) -> usize {
        8
    }

    fn tag_len(&self) -> usize {
        16
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

    fn explicit_nonce_len(&self) -> usize {
        8
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(AesGcm::new(key)?))
    }
}

/// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 cipher suite.
#[derive(Debug)]
struct ChaCha20Poly1305Sha256;

impl SupportedDtls12CipherSuite for ChaCha20Poly1305Sha256 {
    fn suite(&self) -> Dtls12CipherSuite {
        Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        (0, 32, 12) // (mac_key_len, enc_key_len, fixed_iv_len)
    }

    fn explicit_nonce_len(&self) -> usize {
        0
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(ChaCha20Poly1305Cipher::new(key)?))
    }
}

/// Static instances of supported DTLS 1.2 cipher suites.
static AES_128_GCM_SHA256: Aes128GcmSha256 = Aes128GcmSha256;
static AES_256_GCM_SHA384: Aes256GcmSha384 = Aes256GcmSha384;
static CHACHA20_POLY1305_SHA256: ChaCha20Poly1305Sha256 = ChaCha20Poly1305Sha256;

/// All supported DTLS 1.2 cipher suites.
pub(super) static ALL_CIPHER_SUITES: &[&dyn SupportedDtls12CipherSuite] = &[
    &AES_128_GCM_SHA256,
    &AES_256_GCM_SHA384,
    &CHACHA20_POLY1305_SHA256,
];

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

/// TLS_CHACHA20_POLY1305_SHA256 cipher suite (TLS 1.3 / DTLS 1.3).
#[derive(Debug)]
struct Tls13ChaCha20Poly1305Sha256;

impl SupportedDtls13CipherSuite for Tls13ChaCha20Poly1305Sha256 {
    fn suite(&self) -> Dtls13CipherSuite {
        Dtls13CipherSuite::CHACHA20_POLY1305_SHA256
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn key_len(&self) -> usize {
        32 // ChaCha20 key
    }

    fn iv_len(&self) -> usize {
        12 // Poly1305 nonce
    }

    fn tag_len(&self) -> usize {
        16 // Poly1305 tag
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        Ok(Box::new(ChaCha20Poly1305Cipher::new(key)?))
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        // RFC 9001 Section 5.4.4: ChaCha20 header protection
        // counter = sample[0..4] (LE u32), nonce = sample[4..16]
        // mask = first 5 bytes of ChaCha20 keystream at given counter
        let counter = u32::from_le_bytes(sample[0..4].try_into().unwrap());
        let nonce: [u8; 12] = sample[4..16].try_into().unwrap();

        let key = chacha20::Key::from_slice(sn_key);
        let nonce = chacha20::Nonce::from_slice(&nonce);

        let mut cipher = chacha20::ChaCha20::new(key, nonce);
        // Seek to the correct block counter position (each block = 64 bytes)
        cipher.seek(counter as u64 * 64);

        let mut out = [0u8; 16];
        cipher.apply_keystream(&mut out);
        out
    }
}

/// Static instances of supported DTLS 1.3 cipher suites.
static TLS13_AES_128_GCM_SHA256: Tls13Aes128GcmSha256 = Tls13Aes128GcmSha256;
static TLS13_AES_256_GCM_SHA384: Tls13Aes256GcmSha384 = Tls13Aes256GcmSha384;
static TLS13_CHACHA20_POLY1305_SHA256: Tls13ChaCha20Poly1305Sha256 = Tls13ChaCha20Poly1305Sha256;

/// All supported DTLS 1.3 cipher suites.
pub(super) static ALL_DTLS13_CIPHER_SUITES: &[&dyn SupportedDtls13CipherSuite] = &[
    &TLS13_AES_128_GCM_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_CHACHA20_POLY1305_SHA256,
];

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chacha20_poly1305_key_len_validation() {
        // incorrect length (should be 32)
        let result = ChaCha20Poly1305Cipher::new(&[0, 1, 2, 3, 4, 5]);
        assert_eq!(
            "Invalid key size for CHACHA20-POLY1305: 6",
            &result.unwrap_err()
        );
    }
}
