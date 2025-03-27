// Crypto functionality for DTLS 1.2
// Implements support for:
// - ECDHE+AESGCM (EECDH_AESGCM)
// - DHE+AESGCM (EDH_AESGCM)
// - ECDHE+AES256 (AES256_EECDH)
// - DHE+AES256 (AES256_EDH)

use std::str;

use pkcs8::DecodePrivateKey;
use tinyvec::array_vec;

// Crypto-related imports
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256, Sha384};

// Internal module imports
mod encryption;
mod key_exchange;
mod keying;
mod prf;
mod signing;

// Public re-exports
pub use encryption::{AesGcm, Cipher};
pub use key_exchange::{DhKeyExchange, EcdhKeyExchange, KeyExchange};
pub use keying::KeyingMaterial;
pub use prf::{calculate_master_secret, key_expansion, prf_tls12};

// Message-related imports
use crate::message::{
    Asn1Cert, Certificate, CipherSuite, CurveType, HashAlgorithm, KeyExchangeAlgorithm, NamedCurve,
    ServerKeyExchangeParams, SignatureAlgorithm, SignatureAndHashAlgorithm,
};

/// Certificate verifier trait for DTLS connections
pub trait CertVerifier: Send + Sync {
    /// Verify a certificate by its binary DER representation
    fn verify_certificate(&self, der: &[u8]) -> Result<(), String>;
}

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

    /// Client certificate (DER format)
    client_cert: Vec<u8>,

    /// Client private key (DER or PEM format)
    client_private_key: Vec<u8>,

    /// Certificate verifier
    cert_verifier: Box<dyn CertVerifier>,

    /// Signature algorithm based on client certificate type
    signature_algorithm: SignatureAndHashAlgorithm,
}

impl CryptoContext {
    /// Create a new crypto context
    pub fn new(
        client_cert: Vec<u8>,
        client_private_key: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
    ) -> Self {
        // Validate that we have a certificate and private key
        if client_cert.is_empty() {
            panic!("Client certificate cannot be empty");
        }

        if client_private_key.is_empty() {
            panic!("Client private key cannot be empty");
        }

        // Determine the signature algorithm based on the private key
        let signature_algorithm = Self::determine_signature_algorithm(&client_private_key);

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
            client_cert,
            client_private_key,
            cert_verifier,
            signature_algorithm,
        }
    }

    /// Determine signature algorithm from the client certificate
    fn determine_signature_algorithm(cert_data: &[u8]) -> SignatureAndHashAlgorithm {
        // Check if it's a PEM encoded key
        if let Ok(pem_str) = str::from_utf8(cert_data) {
            // Try as RSA key
            if RsaPrivateKey::from_pkcs8_pem(pem_str).is_ok() {
                return SignatureAndHashAlgorithm::new(
                    HashAlgorithm::SHA256,
                    SignatureAlgorithm::RSA,
                );
            }

            // Try as P-256 key
            if P256SigningKey::from_pkcs8_pem(pem_str).is_ok() {
                return SignatureAndHashAlgorithm::new(
                    HashAlgorithm::SHA256,
                    SignatureAlgorithm::ECDSA,
                );
            }

            // Try as P-384 key
            if P384SigningKey::from_pkcs8_pem(pem_str).is_ok() {
                return SignatureAndHashAlgorithm::new(
                    HashAlgorithm::SHA384,
                    SignatureAlgorithm::ECDSA,
                );
            }
        }

        // Try as DER encoded key
        // Try as RSA key
        if RsaPrivateKey::from_pkcs8_der(cert_data).is_ok() {
            return SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA);
        }

        // Try as P-256 key
        if P256SigningKey::from_pkcs8_der(cert_data).is_ok() {
            return SignatureAndHashAlgorithm::new(
                HashAlgorithm::SHA256,
                SignatureAlgorithm::ECDSA,
            );
        }

        // Try as P-384 key
        if P384SigningKey::from_pkcs8_der(cert_data).is_ok() {
            return SignatureAndHashAlgorithm::new(
                HashAlgorithm::SHA384,
                SignatureAlgorithm::ECDSA,
            );
        }

        // Default to RSA + SHA256 if we can't determine
        SignatureAndHashAlgorithm::new(HashAlgorithm::SHA256, SignatureAlgorithm::RSA)
    }

    /// Initialize key exchange based on cipher suite
    pub fn init_key_exchange(&mut self, cipher_suite: CipherSuite) -> Result<(), String> {
        self.key_exchange = Some(match cipher_suite.as_key_exchange_algorithm() {
            KeyExchangeAlgorithm::EECDH => {
                // Use P-256 as the default curve
                Box::new(EcdhKeyExchange::new(NamedCurve::Secp256r1))
            }
            KeyExchangeAlgorithm::EDH => {
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

    /// Process a ServerKeyExchange message and set up key exchange accordingly
    pub fn process_server_key_exchange(
        &mut self,
        server_key_exchange: &crate::message::ServerKeyExchange,
    ) -> Result<(), String> {
        // Process the server key exchange message based on the parameter type
        match &server_key_exchange.params {
            ServerKeyExchangeParams::ServerDhParams(dh_params) => {
                // For DHE, create a new DhKeyExchange with server parameters
                let prime = dh_params.p.to_vec();
                let generator = dh_params.g.to_vec();
                let server_public = dh_params.ys.to_vec();

                // Update our key exchange
                self.key_exchange = Some(Box::new(DhKeyExchange::new(prime, generator)));

                // Generate our keypair
                let _our_public = self.generate_key_exchange()?;

                // Compute shared secret with the server's public key
                self.compute_shared_secret(&server_public)?;

                Ok(())
            }
            ServerKeyExchangeParams::ServerEcdhParams(ecdh_params) => {
                // For ECDHE, create a new EcdhKeyExchange with the specified curve
                let curve = ecdh_params.named_curve;
                let server_public = ecdh_params.public_key.to_vec();

                // Update our key exchange
                self.key_exchange = Some(Box::new(EcdhKeyExchange::new(curve)));

                // Generate our keypair
                let _our_public = self.generate_key_exchange()?;

                // Compute shared secret with the server's public key
                self.compute_shared_secret(&server_public)?;

                Ok(())
            }
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

    /// Get client certificate for authentication
    pub fn get_client_certificate(&self) -> Certificate {
        // We validate in constructor, so we can assume we have a certificate
        let cert = Asn1Cert(self.client_cert.as_slice());
        let certs = array_vec![[Asn1Cert; 32] => cert];
        Certificate::new(certs)
    }

    /// Get the client private key
    ///
    /// This should only be used for operations like signing where the private key is needed
    pub fn get_client_private_key(&self) -> &[u8] {
        // We validate in constructor, so we can assume we have a private key
        &self.client_private_key
    }

    /// Sign the provided data using the client's private key
    /// Returns the signature or an error if signing fails
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Use the signing module to sign the data
        signing::sign_data(
            self.get_client_private_key(),
            data,
            self.get_signature_algorithm(),
        )
    }

    /// Get the recommended hash and signature algorithms for this client
    pub fn get_signature_algorithm(&self) -> SignatureAndHashAlgorithm {
        // Return the signature algorithm determined from the certificate
        self.signature_algorithm
    }

    /// Calculate a hash using the specified algorithm
    pub fn calculate_hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, String> {
        match algorithm {
            HashAlgorithm::SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            // For other hash algorithms, which we don't need for our supported cipher suites
            _ => Err(format!(
                "Hash algorithm {:?} not supported for our cipher suites",
                algorithm
            )),
        }
    }

    /// Verify a server certificate
    pub fn verify_server_certificate(&self, der: &[u8]) -> Result<(), String> {
        self.cert_verifier.verify_certificate(der)
    }

    /// Generate verify data for a Finished message using PRF
    pub fn generate_verify_data(
        &self,
        handshake_messages: &[u8],
        is_client: bool,
    ) -> Result<Vec<u8>, String> {
        // Get master secret
        let master_secret = match &self.master_secret {
            Some(ms) => ms,
            None => return Err("Master secret not available".to_string()),
        };

        // Hash the handshake messages
        let handshake_hash = self.calculate_hash(handshake_messages, HashAlgorithm::SHA256)?;

        // Use the appropriate label based on whether this is for client or server
        let label = if is_client {
            "client finished"
        } else {
            "server finished"
        };

        // Generate 12 bytes of verify data using PRF
        prf_tls12(master_secret, label, &handshake_hash, 12)
    }

    /// Get curve info for ECDHE key exchange
    pub fn get_key_exchange_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        match &self.key_exchange {
            Some(ke) => ke.get_curve_info(),
            None => None,
        }
    }
}
