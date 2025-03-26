// Crypto functionality for DTLS 1.2
// Implements support for:
// - ECDHE+AESGCM (EECDH_AESGCM)
// - DHE+AESGCM (EDH_AESGCM)
// - ECDHE+AES256 (AES256_EECDH)
// - DHE+AES256 (AES256_EDH)

mod certificate;
mod encryption;
mod key_exchange;
mod prf;

pub use certificate::{calculate_fingerprint, format_fingerprint, CertificateError, TrustStore};
pub use encryption::{generate_nonce, AesGcm, Cipher};
pub use key_exchange::{DhKeyExchange, EcdhKeyExchange, KeyExchange};
pub use prf::{calculate_master_secret, key_expansion, prf_tls12};

use crate::message::{CipherSuite, NamedCurve};

/// DTLS 1.2 crypto context
pub struct CryptoContext {
    /// Key exchange mechanism
    key_exchange: Option<Box<dyn KeyExchange>>,

    /// Client write key
    client_write_key: Option<Vec<u8>>,

    /// Server write key
    server_write_key: Option<Vec<u8>>,

    /// Client write IV (for AES-GCM)
    client_write_iv: Option<Vec<u8>>,

    /// Server write IV (for AES-GCM)
    server_write_iv: Option<Vec<u8>>,

    /// Client MAC key (not used for AEAD ciphers)
    client_mac_key: Option<Vec<u8>>,

    /// Server MAC key (not used for AEAD ciphers)
    server_mac_key: Option<Vec<u8>>,

    /// Master secret
    master_secret: Option<Vec<u8>>,

    /// Pre-master secret (temporary)
    pre_master_secret: Option<Vec<u8>>,

    /// Client cipher
    client_cipher: Option<Box<dyn Cipher>>,

    /// Server cipher
    server_cipher: Option<Box<dyn Cipher>>,

    /// Trust store for certificate validation
    trust_store: TrustStore,
}

impl CryptoContext {
    /// Create a new crypto context
    pub fn new() -> Self {
        CryptoContext {
            key_exchange: None,
            client_write_key: None,
            server_write_key: None,
            client_write_iv: None,
            server_write_iv: None,
            client_mac_key: None,
            server_mac_key: None,
            master_secret: None,
            pre_master_secret: None,
            client_cipher: None,
            server_cipher: None,
            trust_store: TrustStore::new(),
        }
    }

    /// Initialize key exchange based on cipher suite
    pub fn init_key_exchange(&mut self, cipher_suite: CipherSuite) -> Result<(), String> {
        self.key_exchange = Some(match cipher_suite.as_key_exchange_algorithm() {
            crate::message::KeyExchangeAlgorithm::EECDH => {
                // Use P-256 as the default curve
                Box::new(EcdhKeyExchange::new(NamedCurve::Secp256r1))
            }
            crate::message::KeyExchangeAlgorithm::EDH => {
                // For DHE, we need prime and generator values (typically from server)
                // This is a placeholder - real implementation would use values from ServerKeyExchange
                let prime = vec![0u8; 256]; // Placeholder
                let generator = vec![2]; // Common generator value g=2
                Box::new(DhKeyExchange::new(prime, generator))
            }
            _ => return Err("Unsupported key exchange algorithm".to_string()),
        });

        Ok(())
    }

    /// Generate key exchange public key
    pub fn generate_key_exchange(&mut self) -> Result<Vec<u8>, String> {
        match &mut self.key_exchange {
            Some(ke) => Ok(ke.generate()),
            None => Err("Key exchange not initialized".to_string()),
        }
    }

    /// Process peer's public key and compute shared secret
    pub fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<(), String> {
        match &self.key_exchange {
            Some(ke) => {
                self.pre_master_secret = Some(ke.compute_shared_secret(peer_public_key)?);
                Ok(())
            }
            None => Err("Key exchange not initialized".to_string()),
        }
    }

    /// Derive master secret from pre-master secret
    pub fn derive_master_secret(
        &mut self,
        client_random: &[u8],
        server_random: &[u8],
    ) -> Result<(), String> {
        match &self.pre_master_secret {
            Some(pms) => {
                self.master_secret =
                    Some(calculate_master_secret(pms, client_random, server_random)?);
                // Clear pre-master secret after use (security measure)
                self.pre_master_secret = None;
                Ok(())
            }
            None => Err("Pre-master secret not available".to_string()),
        }
    }

    /// Derive keys for encryption/decryption
    pub fn derive_keys(
        &mut self,
        cipher_suite: CipherSuite,
        client_random: &[u8],
        server_random: &[u8],
    ) -> Result<(), String> {
        let master_secret = match &self.master_secret {
            Some(ms) => ms,
            None => return Err("Master secret not available".to_string()),
        };

        // Key sizes depend on the cipher suite
        let (mac_key_len, enc_key_len, fixed_iv_len) = match cipher_suite {
            CipherSuite::EECDH_AESGCM | CipherSuite::EDH_AESGCM => (0, 16, 4), // AES-128-GCM
            CipherSuite::AES256_EECDH | CipherSuite::AES256_EDH => (0, 32, 4), // AES-256-GCM
            _ => return Err("Unsupported cipher suite for key derivation".to_string()),
        };

        // Calculate total key material length
        let key_material_len = 2 * (mac_key_len + enc_key_len + fixed_iv_len);

        // Generate key material
        let key_block = key_expansion(
            master_secret,
            client_random,
            server_random,
            key_material_len,
        )?;

        // Split key material
        let mut offset = 0;

        // Extract MAC keys (if used)
        if mac_key_len > 0 {
            self.client_mac_key = Some(key_block[offset..offset + mac_key_len].to_vec());
            offset += mac_key_len;
            self.server_mac_key = Some(key_block[offset..offset + mac_key_len].to_vec());
            offset += mac_key_len;
        }

        // Extract encryption keys
        self.client_write_key = Some(key_block[offset..offset + enc_key_len].to_vec());
        offset += enc_key_len;
        self.server_write_key = Some(key_block[offset..offset + enc_key_len].to_vec());
        offset += enc_key_len;

        // Extract IVs
        self.client_write_iv = Some(key_block[offset..offset + fixed_iv_len].to_vec());
        offset += fixed_iv_len;
        self.server_write_iv = Some(key_block[offset..offset + fixed_iv_len].to_vec());

        // Initialize ciphers
        match cipher_suite {
            CipherSuite::EECDH_AESGCM
            | CipherSuite::EDH_AESGCM
            | CipherSuite::AES256_EECDH
            | CipherSuite::AES256_EDH => {
                // AES-GCM ciphers
                self.client_cipher = Some(Box::new(AesGcm::new(
                    self.client_write_key.as_ref().unwrap(),
                )?));

                self.server_cipher = Some(Box::new(AesGcm::new(
                    self.server_write_key.as_ref().unwrap(),
                )?));

                Ok(())
            }
            _ => Err("Unsupported cipher suite".to_string()),
        }
    }

    /// Encrypt data (client to server)
    pub fn encrypt_client_to_server(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, String> {
        match &self.client_cipher {
            Some(cipher) => cipher.encrypt(plaintext, aad, nonce),
            None => Err("Client cipher not initialized".to_string()),
        }
    }

    /// Decrypt data (server to client)
    pub fn decrypt_server_to_client(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, String> {
        match &self.server_cipher {
            Some(cipher) => cipher.decrypt(ciphertext, aad, nonce),
            None => Err("Server cipher not initialized".to_string()),
        }
    }

    /// Generate a random nonce for encryption
    pub fn generate_client_nonce(&self) -> Result<Vec<u8>, String> {
        match &self.client_cipher {
            Some(cipher) => Ok(cipher.generate_nonce()),
            None => Err("Client cipher not initialized".to_string()),
        }
    }

    /// Generate a random nonce for decryption
    pub fn generate_server_nonce(&self) -> Result<Vec<u8>, String> {
        match &self.server_cipher {
            Some(cipher) => Ok(cipher.generate_nonce()),
            None => Err("Server cipher not initialized".to_string()),
        }
    }

    /// Get reference to the trust store
    pub fn trust_store(&self) -> &TrustStore {
        &self.trust_store
    }

    /// Get mutable reference to the trust store
    pub fn trust_store_mut(&mut self) -> &mut TrustStore {
        &mut self.trust_store
    }

    /// Verify a server certificate chain against our trust store
    pub fn verify_server_cert_chain(
        &self,
        cert_chain: &[&[u8]],
        hostname: &str,
    ) -> Result<(), String> {
        self.trust_store
            .verify_cert_chain(cert_chain, hostname)
            .map_err(|err| match err {
                CertificateError::InvalidFormat => "Invalid certificate format".to_string(),
                CertificateError::FingerprintMismatch => {
                    format!("Certificate fingerprint mismatch for {}", hostname)
                }
                CertificateError::GenerationFailed => "Certificate generation failed".to_string(),
            })
    }

    /// Check if we have a client certificate available
    pub fn has_client_certificate(&self) -> bool {
        self.trust_store.has_client_certificate()
    }

    /// Get client certificate for authentication
    pub fn get_client_certificate(&self) -> Option<crate::message::Certificate> {
        self.trust_store.get_client_certificate()
    }
}
