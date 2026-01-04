//! DTLS 1.3 Crypto Context
//!
//! This module manages the cryptographic state for DTLS 1.3 connections,
//! including epoch-based key transitions and record encryption/decryption.
//!
//! # Epochs in DTLS 1.3
//!
//! - Epoch 0: Plaintext (ClientHello, HelloRetryRequest)
//! - Epoch 1: Handshake keys (after ServerHello)
//! - Epoch 2: Early data (0-RTT) - NOT SUPPORTED
//! - Epoch 3+: Application data keys
//!
//! Each epoch has its own traffic secrets derived via the TLS 1.3 key schedule.
//!
//! NOTE: This module is prepared for full DTLS 1.3 record layer integration.
//! Some items are currently unused but will be connected in future work.

#![allow(dead_code)]

use crate::buffer::{Buf, TmpBuf};
use crate::crypto::dtls_aead::{Aad13, Iv13, Nonce13};
use crate::crypto::provider::{Cipher, CryptoProvider};
use crate::crypto::tls13_key_schedule::KeySchedule;
use crate::message::{CipherSuite, ContentType, HashAlgorithm};

/// Maximum number of epochs we track (0-7, using 3 bits in header).
const MAX_EPOCHS: usize = 8;

/// Keys for a single direction (send or receive) at a given epoch.
#[derive(Debug)]
struct DirectionalKeys {
    /// The AEAD cipher instance.
    cipher: Box<dyn Cipher>,
    /// Full 12-byte IV for nonce construction.
    iv: Iv13,
    /// Current sequence number (48-bit, we track full value).
    sequence_number: u64,
}

impl DirectionalKeys {
    fn new(cipher: Box<dyn Cipher>, iv: &[u8]) -> Self {
        Self {
            cipher,
            iv: Iv13::new(iv),
            sequence_number: 0,
        }
    }

    /// Get the next nonce and increment the sequence number.
    fn next_nonce(&mut self) -> Nonce13 {
        let nonce = Nonce13::new(self.iv, self.sequence_number);
        self.sequence_number += 1;
        nonce
    }

    /// Compute nonce for a given sequence number (for decryption).
    fn nonce_for_seq(&self, seq: u64) -> Nonce13 {
        Nonce13::new(self.iv, seq)
    }
}

/// Keys for a single epoch (both send and receive directions).
struct EpochKeys {
    /// Keys for sending (client-to-server for client, server-to-client for server).
    send: DirectionalKeys,
    /// Keys for receiving (server-to-client for client, client-to-server for server).
    recv: DirectionalKeys,
}

/// DTLS 1.3 cryptographic context.
///
/// Manages keys across epochs and provides encryption/decryption operations.
pub struct CryptoContext13<'a> {
    /// Reference to the crypto provider.
    provider: &'a CryptoProvider,
    /// The negotiated cipher suite.
    cipher_suite: CipherSuite,
    /// The hash algorithm for the cipher suite.
    hash: HashAlgorithm,
    /// Keys indexed by epoch (epoch & 0x07 for the 3-bit epoch in headers).
    epochs: [Option<EpochKeys>; MAX_EPOCHS],
    /// Current send epoch.
    send_epoch: u16,
    /// Current receive epoch (may differ during key transitions).
    recv_epoch: u16,
    /// Key schedule for deriving new keys.
    key_schedule: Option<KeySchedule<'a>>,
    /// Whether we are the client (affects key direction).
    is_client: bool,
}

impl<'a> CryptoContext13<'a> {
    /// Create a new DTLS 1.3 crypto context.
    pub fn new(provider: &'a CryptoProvider, cipher_suite: CipherSuite, is_client: bool) -> Self {
        let hash = cipher_suite.hash_algorithm();
        Self {
            provider,
            cipher_suite,
            hash,
            epochs: Default::default(),
            send_epoch: 0,
            recv_epoch: 0,
            key_schedule: None,
            is_client,
        }
    }

    /// Initialize the key schedule after receiving ClientHello/ServerHello.
    pub fn init_key_schedule(&mut self) -> Result<(), String> {
        let ks = KeySchedule::new(self.provider.hkdf_provider, self.hash)?;
        self.key_schedule = Some(ks);
        Ok(())
    }

    /// Derive and install handshake keys (epoch 1).
    ///
    /// Called after ECDHE key exchange completes (after ServerHello).
    pub fn install_handshake_keys(
        &mut self,
        ecdhe_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<(), String> {
        // Get key/iv lengths first to avoid borrow issues
        let (key_len, iv_len) = self.key_iv_lengths();

        let ks = self
            .key_schedule
            .as_mut()
            .ok_or("Key schedule not initialized")?;

        // Derive handshake traffic secrets
        let (client_hs_secret, server_hs_secret) =
            ks.derive_handshake_secrets(ecdhe_secret, transcript_hash)?;

        // Derive traffic keys from secrets
        let (client_key, client_iv) = ks.derive_traffic_keys(&client_hs_secret, key_len, iv_len)?;
        let (server_key, server_iv) = ks.derive_traffic_keys(&server_hs_secret, key_len, iv_len)?;

        // Create cipher instances
        let client_cipher = self.create_cipher(&client_key)?;
        let server_cipher = self.create_cipher(&server_key)?;

        // Install keys for epoch 1
        let (send_keys, recv_keys) = if self.is_client {
            (
                DirectionalKeys::new(client_cipher, &client_iv),
                DirectionalKeys::new(server_cipher, &server_iv),
            )
        } else {
            (
                DirectionalKeys::new(server_cipher, &server_iv),
                DirectionalKeys::new(client_cipher, &client_iv),
            )
        };

        self.epochs[1] = Some(EpochKeys {
            send: send_keys,
            recv: recv_keys,
        });

        Ok(())
    }

    /// Transition to handshake epoch for sending (epoch 1).
    pub fn start_sending_handshake(&mut self) {
        self.send_epoch = 1;
    }

    /// Transition to handshake epoch for receiving (epoch 1).
    pub fn start_receiving_handshake(&mut self) {
        self.recv_epoch = 1;
    }

    /// Derive and install application keys (epoch 3).
    ///
    /// Called after Finished messages are verified.
    pub fn install_application_keys(&mut self, transcript_hash: &[u8]) -> Result<(), String> {
        // Get key/iv lengths first to avoid borrow issues
        let (key_len, iv_len) = self.key_iv_lengths();

        let ks = self
            .key_schedule
            .as_mut()
            .ok_or("Key schedule not initialized")?;

        // Derive application traffic secrets
        let (client_app_secret, server_app_secret) =
            ks.derive_application_secrets(transcript_hash)?;

        // Derive traffic keys
        let (client_key, client_iv) =
            ks.derive_traffic_keys(&client_app_secret, key_len, iv_len)?;
        let (server_key, server_iv) =
            ks.derive_traffic_keys(&server_app_secret, key_len, iv_len)?;

        // Create cipher instances
        let client_cipher = self.create_cipher(&client_key)?;
        let server_cipher = self.create_cipher(&server_key)?;

        // Install keys for epoch 3 (skipping epoch 2 which is for 0-RTT)
        let (send_keys, recv_keys) = if self.is_client {
            (
                DirectionalKeys::new(client_cipher, &client_iv),
                DirectionalKeys::new(server_cipher, &server_iv),
            )
        } else {
            (
                DirectionalKeys::new(server_cipher, &server_iv),
                DirectionalKeys::new(client_cipher, &client_iv),
            )
        };

        self.epochs[3] = Some(EpochKeys {
            send: send_keys,
            recv: recv_keys,
        });

        Ok(())
    }

    /// Transition to application epoch for sending (epoch 3).
    pub fn start_sending_application(&mut self) {
        self.send_epoch = 3;
    }

    /// Transition to application epoch for receiving (epoch 3).
    pub fn start_receiving_application(&mut self) {
        self.recv_epoch = 3;
    }

    /// Encrypt a record for sending.
    ///
    /// - Appends the inner content type to the plaintext
    /// - Encrypts with the current send epoch keys
    /// - Returns (epoch_bits, sequence_number, ciphertext)
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        content_type: ContentType,
        header_bytes: &[u8],
    ) -> Result<(u8, u64, Buf), String> {
        let epoch_idx = (self.send_epoch & 0x07) as usize;
        let keys = self.epochs[epoch_idx]
            .as_mut()
            .ok_or_else(|| format!("No keys for send epoch {}", self.send_epoch))?;

        // Build inner plaintext: content || content_type
        let mut inner = Buf::new();
        inner.extend_from_slice(plaintext);
        inner.push(content_type.as_u8());

        // Get nonce
        let seq = keys.send.sequence_number;
        let nonce = keys.send.next_nonce();

        // Create AAD from header (variable length for DTLS 1.3)
        let aad = Aad13::from_header(header_bytes);

        // Encrypt in place (cipher appends tag)
        // Use variable-length AAD for DTLS 1.3 unified header
        let nonce_12 = crate::crypto::Nonce(nonce.0);

        keys.send
            .cipher
            .encrypt_with_aad(&mut inner, aad.as_bytes(), nonce_12)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok(((self.send_epoch & 0x07) as u8, seq, inner))
    }

    /// Decrypt a received record.
    ///
    /// - Decrypts using the appropriate epoch keys
    /// - Extracts the inner content type
    /// - Returns (content_type, plaintext)
    pub fn decrypt(
        &mut self,
        ciphertext: &mut [u8],
        epoch_bits: u8,
        sequence_number: u64,
        header_bytes: &[u8],
    ) -> Result<(ContentType, usize), String> {
        // Reconstruct full epoch from bits (for now, assume recv_epoch matches)
        let epoch_idx = (epoch_bits & 0x07) as usize;
        let keys = self.epochs[epoch_idx]
            .as_mut()
            .ok_or_else(|| format!("No keys for receive epoch {}", epoch_idx))?;

        // Compute nonce for this sequence
        let nonce = keys.recv.nonce_for_seq(sequence_number);

        // Create AAD from header (variable length for DTLS 1.3)
        let aad = Aad13::from_header(header_bytes);

        // Decrypt in place using variable-length AAD for DTLS 1.3
        let mut tmp = TmpBuf::new(ciphertext);

        let nonce_12 = crate::crypto::Nonce(nonce.0);

        keys.recv
            .cipher
            .decrypt_with_aad(&mut tmp, aad.as_bytes(), nonce_12)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        // Extract inner content type (last non-zero byte)
        let decrypted_len = tmp.len();
        if decrypted_len == 0 {
            return Err("Decrypted record is empty".to_string());
        }

        // Find content type (scan backwards for first non-zero)
        let decrypted = tmp.as_ref();
        let mut idx = decrypted_len - 1;
        while idx > 0 && decrypted[idx] == 0 {
            idx -= 1;
        }

        let content_type = ContentType::from_u8(decrypted[idx]);
        let plaintext_len = idx;

        Ok((content_type, plaintext_len))
    }

    /// Get the current send epoch.
    pub fn send_epoch(&self) -> u16 {
        self.send_epoch
    }

    /// Get the current receive epoch.
    pub fn recv_epoch(&self) -> u16 {
        self.recv_epoch
    }

    /// Get the next sequence number for the current send epoch (without incrementing).
    pub fn next_send_sequence(&self) -> Option<u64> {
        let epoch_idx = (self.send_epoch & 0x07) as usize;
        self.epochs[epoch_idx]
            .as_ref()
            .map(|k| k.send.sequence_number)
    }

    /// Derive the exporter secret for SRTP keying material.
    pub fn derive_exporter_secret(&mut self, transcript_hash: &[u8]) -> Result<Buf, String> {
        let ks = self
            .key_schedule
            .as_mut()
            .ok_or("Key schedule not initialized")?;
        ks.derive_exporter_secret(transcript_hash)
    }

    // Helper methods

    fn key_iv_lengths(&self) -> (usize, usize) {
        match self.cipher_suite {
            CipherSuite::TLS_AES_128_GCM_SHA256 => (16, 12),
            CipherSuite::TLS_AES_256_GCM_SHA384 => (32, 12),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => (32, 12),
            // DTLS 1.2 suites (shouldn't be used here but handle gracefully)
            CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => (16, 4),
            CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => (32, 4),
            CipherSuite::Unknown(_) => (16, 12), // Default
        }
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
        // Find the matching supported cipher suite in the provider
        for suite in self.provider.cipher_suites {
            if suite.suite() == self.cipher_suite
                || (self.cipher_suite.is_tls13()
                    && suite.hash_algorithm() == self.cipher_suite.hash_algorithm())
            {
                return suite.create_cipher(key);
            }
        }

        // For TLS 1.3, we may need to map to a DTLS 1.2 cipher suite implementation
        // since the underlying AEAD is the same (AES-GCM)
        let compatible_suite = match self.cipher_suite {
            CipherSuite::TLS_AES_128_GCM_SHA256 => CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384 => CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
            _ => {
                return Err(format!(
                    "No cipher implementation for {:?}",
                    self.cipher_suite
                ))
            }
        };

        for suite in self.provider.cipher_suites {
            if suite.suite() == compatible_suite {
                return suite.create_cipher(key);
            }
        }

        Err(format!(
            "No cipher suite implementation for {:?}",
            self.cipher_suite
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_provider() -> CryptoProvider {
        #[cfg(feature = "aws-lc-rs")]
        {
            crate::crypto::aws_lc_rs::default_provider()
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
        {
            crate::crypto::rust_crypto::default_provider()
        }
    }

    #[test]
    fn test_nonce13_construction() {
        let iv = Iv13::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ]);
        let nonce = Nonce13::new(iv, 1);

        // First 4 bytes unchanged
        assert_eq!(nonce.0[0..4], [0x01, 0x02, 0x03, 0x04]);
        // Last byte XORed with 0x01
        assert_eq!(nonce.0[11], 0x0c ^ 0x01);
    }

    #[test]
    fn test_crypto_context_creation() {
        let provider = get_provider();
        let ctx = CryptoContext13::new(&provider, CipherSuite::TLS_AES_128_GCM_SHA256, true);
        assert_eq!(ctx.send_epoch(), 0);
        assert_eq!(ctx.recv_epoch(), 0);
    }

    #[test]
    fn test_key_schedule_init() {
        let provider = get_provider();
        let mut ctx = CryptoContext13::new(&provider, CipherSuite::TLS_AES_128_GCM_SHA256, true);
        ctx.init_key_schedule().unwrap();
    }
}
