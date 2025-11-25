//! Cryptographic primitives and helpers used by the DTLS engine.

use std::ops::Deref;
use std::sync::Arc;

use arrayvec::ArrayVec;

// Internal module imports
pub(crate) mod dtls_aead;
mod keying;

// Provider traits and implementations
#[cfg(feature = "aws-lc-rs")]
pub mod aws_lc_rs;

mod provider;
mod validation;

pub use keying::{KeyingMaterial, SrtpProfile};

// Re-export message enums needed for provider trait implementations
pub use crate::message::{CipherSuite, HashAlgorithm, NamedGroup, SignatureAlgorithm};

// Re-export all provider traits and types (similar to rustls structure)
// This allows users to do: use dimpl::crypto::{CryptoProvider, SupportedCipherSuite, ...};
pub use provider::{
    ActiveKeyExchange, Cipher, CryptoProvider, CryptoSafe, HashContext, HashProvider,
};
pub use provider::{HmacProvider, KeyProvider, PrfProvider};
pub use provider::{SecureRandom, SignatureVerifier, SigningKey};
pub use provider::{SupportedCipherSuite, SupportedKxGroup};

use crate::buffer::{Buf, TmpBuf, ToBuf};
use crate::message::DigitallySigned;
use crate::message::{Asn1Cert, Certificate, CurveType};

use dtls_aead::{Aad, Iv, Nonce};

/// DTLS crypto context
/// Crypto context holding negotiated keys and ciphers for a DTLS session.
pub(crate) struct CryptoContext {
    /// Configuration (contains crypto provider)
    config: Arc<crate::Config>,

    /// Key exchange mechanism
    key_exchange: Option<Box<dyn provider::ActiveKeyExchange>>,

    /// Our public key from the key exchange (stored for reuse)
    key_exchange_public_key: Option<Vec<u8>>,

    /// Group info from the key exchange (stored for reuse)
    key_exchange_group: Option<NamedGroup>,

    /// Client write key
    client_write_key: Option<Buf>,

    /// Server write key
    server_write_key: Option<Buf>,

    /// Client write IV (for AES-GCM)
    client_write_iv: Option<Iv>,

    /// Server write IV (for AES-GCM)
    server_write_iv: Option<Iv>,

    /// Client MAC key (not used for AEAD ciphers)
    client_mac_key: Option<Buf>,

    /// Server MAC key (not used for AEAD ciphers)
    server_mac_key: Option<Buf>,

    /// Master secret
    master_secret: Option<ArrayVec<u8, 128>>,

    /// Pre-master secret (temporary)
    pre_master_secret: Option<Buf>,

    /// Client cipher
    client_cipher: Option<Box<dyn provider::Cipher>>,

    /// Server cipher
    server_cipher: Option<Box<dyn provider::Cipher>>,

    /// Certificate (DER format)
    certificate: Vec<u8>,

    /// Parsed private key for the certificate with signature algorithm
    private_key: Arc<dyn provider::SigningKey>,

    /// Client random (needed for SRTP key export per RFC 5705)
    client_random: Option<ArrayVec<u8, 32>>,

    /// Server random (needed for SRTP key export per RFC 5705)
    server_random: Option<ArrayVec<u8, 32>>,
}

impl CryptoContext {
    /// Create a new crypto context
    pub fn new(
        certificate: Vec<u8>,
        private_key_bytes: Vec<u8>,
        config: Arc<crate::Config>,
    ) -> Self {
        // Validate that we have a certificate and private key
        if certificate.is_empty() {
            panic!("Client certificate cannot be empty");
        }

        if private_key_bytes.is_empty() {
            panic!("Client private key cannot be empty");
        }

        // Parse the private key using the provider
        let private_key = config
            .crypto_provider()
            .key_provider
            .load_private_key(&private_key_bytes)
            .expect("Failed to parse client private key");

        CryptoContext {
            config,
            key_exchange: None,
            key_exchange_public_key: None,
            key_exchange_group: None,
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
            certificate,
            private_key,
            client_random: None,
            server_random: None,
        }
    }

    pub fn provider(&self) -> &provider::CryptoProvider {
        self.config.crypto_provider()
    }

    /// Generate key exchange public key
    pub fn maybe_init_key_exchange(&mut self) -> Result<&[u8], String> {
        // If we already have the public key stored, return it
        if let Some(ref pk) = self.key_exchange_public_key {
            return Ok(pk);
        }

        // Otherwise, get it from the key exchange and store it
        match &self.key_exchange {
            Some(ke) => {
                let pub_key = ke.pub_key().to_vec();
                let group = ke.group();
                self.key_exchange_public_key = Some(pub_key);
                self.key_exchange_group = Some(group);
                Ok(self.key_exchange_public_key.as_ref().unwrap())
            }
            None => Err("Key exchange not initialized".to_string()),
        }
    }

    /// Process peer's public key and compute shared secret
    pub fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<(), String> {
        let ke = self
            .key_exchange
            .take()
            .ok_or_else(|| "Key exchange not initialized".to_string())?;
        self.pre_master_secret = Some(ke.complete(peer_public_key)?);
        // Note: we keep key_exchange_public_key since it may be needed later
        Ok(())
    }

    /// Initialize ECDHE key exchange (server role) and return our ephemeral public key
    pub fn init_ecdh_server(&mut self, named_group: NamedGroup) -> Result<&[u8], String> {
        // Find the matching key exchange group from the provider
        let kx_group = self
            .provider()
            .kx_groups
            .iter()
            .find(|g| g.name() == named_group)
            .ok_or_else(|| format!("Unsupported ECDHE named group: {:?}", named_group))?;

        self.key_exchange = Some(kx_group.start_exchange()?);
        self.maybe_init_key_exchange()
    }

    /// Process a ServerKeyExchange message and set up key exchange accordingly
    pub fn process_ecdh_params(
        &mut self,
        group: NamedGroup,
        server_public: &[u8],
    ) -> Result<(), String> {
        // Find the matching key exchange group from the provider
        let kx_group = self
            .provider()
            .kx_groups
            .iter()
            .find(|g| g.name() == group)
            .ok_or_else(|| format!("Unsupported ECDHE named group: {:?}", group))?;

        // Create a new ECDH key exchange
        self.key_exchange = Some(kx_group.start_exchange()?);

        // Generate our keypair
        let _our_public = self.maybe_init_key_exchange()?;

        // Compute shared secret with the server's public key
        self.compute_shared_secret(server_public)?;

        Ok(())
    }

    /// Derive master secret using Extended Master Secret (RFC 7627)
    pub fn derive_extended_master_secret(
        &mut self,
        session_hash: &[u8],
        hash: HashAlgorithm,
    ) -> Result<(), String> {
        trace!("Deriving extended master secret");
        let Some(pms) = &self.pre_master_secret else {
            return Err("Pre-master secret not available".to_string());
        };
        let master_secret_vec = self.provider().prf_provider.prf_tls12(
            pms,
            "extended master secret",
            session_hash,
            48,
            hash,
        )?;
        let mut master_secret = ArrayVec::new();
        master_secret
            .try_extend_from_slice(&master_secret_vec)
            .map_err(|_| "Master secret too long".to_string())?;
        self.master_secret = Some(master_secret);
        // Clear pre-master secret after use (security measure)
        self.pre_master_secret = None;
        Ok(())
    }

    /// Derive keys for encryption/decryption
    pub fn derive_keys(
        &mut self,
        cipher_suite: CipherSuite,
        client_random: &[u8],
        server_random: &[u8],
    ) -> Result<(), String> {
        let Some(master_secret) = &self.master_secret else {
            return Err("Master secret not available".to_string());
        };

        // Store the randoms for later SRTP key export (RFC 5705)
        let mut client_random_arr = ArrayVec::new();
        client_random_arr
            .try_extend_from_slice(client_random)
            .expect("client_random too long");
        self.client_random = Some(client_random_arr);

        let mut server_random_arr = ArrayVec::new();
        server_random_arr
            .try_extend_from_slice(server_random)
            .expect("server_random too long");
        self.server_random = Some(server_random_arr);

        // Find the cipher suite from the provider
        let supported_cipher_suite = self
            .provider()
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == cipher_suite)
            .ok_or_else(|| format!("Unsupported cipher suite: {:?}", cipher_suite))?;

        // Get key sizes from the provider
        let (mac_key_len, enc_key_len, fixed_iv_len) = supported_cipher_suite.key_lengths();

        // Calculate total key material length
        let key_material_len = 2 * (mac_key_len + enc_key_len + fixed_iv_len);

        // Compute seed for key expansion: server_random + client_random
        let mut seed = Vec::with_capacity(server_random.len() + client_random.len());
        seed.extend_from_slice(server_random);
        seed.extend_from_slice(client_random);

        // Generate key material using PRF
        let key_block = self.provider().prf_provider.prf_tls12(
            master_secret,
            "key expansion",
            &seed,
            key_material_len,
            cipher_suite.hash_algorithm(),
        )?;

        // Split key material
        let mut offset = 0;

        // Extract MAC keys (if used)
        if mac_key_len > 0 {
            self.client_mac_key = Some(key_block[offset..offset + mac_key_len].to_buf());
            offset += mac_key_len;
            self.server_mac_key = Some(key_block[offset..offset + mac_key_len].to_buf());
            offset += mac_key_len;
        }

        // Extract encryption keys
        self.client_write_key = Some(key_block[offset..offset + enc_key_len].to_buf());
        offset += enc_key_len;
        self.server_write_key = Some(key_block[offset..offset + enc_key_len].to_buf());
        offset += enc_key_len;

        // Extract IVs
        self.client_write_iv = Some(Iv::new(&key_block[offset..offset + fixed_iv_len]));
        offset += fixed_iv_len;
        self.server_write_iv = Some(Iv::new(&key_block[offset..offset + fixed_iv_len]));

        // Initialize ciphers using the provider
        self.client_cipher =
            Some(supported_cipher_suite.create_cipher(self.client_write_key.as_ref().unwrap())?);

        self.server_cipher =
            Some(supported_cipher_suite.create_cipher(self.server_write_key.as_ref().unwrap())?);

        Ok(())
    }

    /// Encrypt data (client to server)
    pub fn encrypt_client_to_server(
        &mut self,
        plaintext: &mut Buf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), String> {
        match &mut self.client_cipher {
            Some(cipher) => cipher.encrypt(plaintext, aad, nonce),
            None => Err("Client cipher not initialized".to_string()),
        }
    }

    /// Decrypt data (server to client)
    pub fn decrypt_server_to_client(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), String> {
        match &mut self.server_cipher {
            Some(cipher) => cipher.decrypt(ciphertext, aad, nonce),
            None => Err("Server cipher not initialized".to_string()),
        }
    }

    /// Encrypt data (server to client)
    pub fn encrypt_server_to_client(
        &mut self,
        plaintext: &mut Buf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), String> {
        match &mut self.server_cipher {
            Some(cipher) => cipher.encrypt(plaintext, aad, nonce),
            None => Err("Server cipher not initialized".to_string()),
        }
    }

    /// Decrypt data (client to server)
    pub fn decrypt_client_to_server(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), String> {
        match &mut self.client_cipher {
            Some(cipher) => cipher.decrypt(ciphertext, aad, nonce),
            None => Err("Client cipher not initialized".to_string()),
        }
    }

    /// Get client certificate for authentication
    pub fn get_client_certificate(&self) -> Certificate {
        // We validate in constructor, so we can assume we have a certificate
        // Create an Asn1Cert with a range covering the entire certificate
        let cert = Asn1Cert(0..self.certificate.len());
        let mut certs = ArrayVec::new();
        certs.push(cert);
        Certificate::new(certs)
    }

    /// Serialize client certificate for authentication
    pub fn serialize_client_certificate(&self, output: &mut Buf) {
        let cert = self.get_client_certificate();
        cert.serialize(&self.certificate, output);
    }

    /// Sign the provided data using the client's private key
    /// Returns the signature or an error if signing fails
    pub fn sign_data(&self, data: &[u8], _hash_alg: HashAlgorithm) -> Result<Vec<u8>, String> {
        self.private_key.sign(data)
    }

    /// Generate verify data for a Finished message using PRF
    pub fn generate_verify_data(
        &self,
        handshake_hash: &[u8],
        is_client: bool,
        hash: HashAlgorithm,
    ) -> Result<ArrayVec<u8, 128>, String> {
        let master_secret = match &self.master_secret {
            Some(ms) => ms,
            None => return Err("No master secret available".to_string()),
        };

        let label = if is_client {
            "client finished"
        } else {
            "server finished"
        };

        // Generate 12 bytes of verify data using PRF
        let verify_data_vec = self.provider().prf_provider.prf_tls12(
            master_secret,
            label,
            handshake_hash,
            12,
            hash,
        )?;
        let mut verify_data = ArrayVec::new();
        verify_data
            .try_extend_from_slice(&verify_data_vec)
            .map_err(|_| "Verify data too long".to_string())?;
        Ok(verify_data)
    }

    /// Extract SRTP keying material from the master secret
    /// This is per RFC 5764 (DTLS-SRTP) section 4.2 and RFC 5705 (TLS Exporter)
    pub fn extract_srtp_keying_material(
        &self,
        profile: SrtpProfile,
        hash: HashAlgorithm,
    ) -> Result<ArrayVec<u8, 128>, String> {
        const DTLS_SRTP_KEY_LABEL: &str = "EXTRACTOR-dtls_srtp";

        let master_secret = match &self.master_secret {
            Some(ms) => ms,
            None => return Err("No master secret available".to_string()),
        };

        let client_random = match &self.client_random {
            Some(cr) => cr,
            None => return Err("No client random available".to_string()),
        };

        let server_random = match &self.server_random {
            Some(sr) => sr,
            None => return Err("No server random available".to_string()),
        };

        // Per RFC 5705, the exporter uses: PRF(master_secret, label, client_random + server_random)
        // The seed for DTLS-SRTP exporter is client_random + server_random (no additional context)
        let mut seed = ArrayVec::<u8, 64>::new();
        seed.try_extend_from_slice(client_random)
            .expect("client_random too long");
        seed.try_extend_from_slice(server_random)
            .expect("server_random too long");

        let keying_material_vec = self.provider().prf_provider.prf_tls12(
            master_secret,
            DTLS_SRTP_KEY_LABEL,
            &seed,
            profile.keying_material_len(),
            hash,
        )?;
        let mut keying_material = ArrayVec::new();
        keying_material
            .try_extend_from_slice(&keying_material_vec)
            .map_err(|_| "Keying material too long".to_string())?;

        Ok(keying_material)
    }

    /// Get group info for ECDHE key exchange
    pub fn get_key_exchange_group_info(&self) -> Option<(CurveType, NamedGroup)> {
        // Use stored group if available (after key exchange is consumed)
        if let Some(group) = self.key_exchange_group {
            return Some((CurveType::NamedCurve, group));
        }

        // Otherwise get it from the active key exchange
        let Some(ke) = &self.key_exchange else {
            return None;
        };
        Some((CurveType::NamedCurve, ke.group()))
    }

    /// Signature algorithm for the configured private key
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.private_key.algorithm()
    }

    /// Default hash algorithm for the configured private key
    pub fn private_key_default_hash_algorithm(&self) -> HashAlgorithm {
        self.private_key.hash_algorithm()
    }

    /// Create a hash context for the given algorithm
    pub fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn provider::HashContext> {
        self.provider().hash_provider.create_hash(algorithm)
    }

    /// Check if the client's private key is compatible with a given cipher suite.
    pub fn is_cipher_suite_compatible(&self, cipher_suite: CipherSuite) -> bool {
        self.private_key.is_compatible(cipher_suite)
    }

    /// Get the client write IV if derived.
    pub fn get_client_write_iv(&self) -> Option<Iv> {
        self.client_write_iv
    }

    /// Get the server write IV if derived.
    pub fn get_server_write_iv(&self) -> Option<Iv> {
        self.server_write_iv
    }

    /// Verify a DigitallySigned structure against a certificate's public key.
    pub fn verify_signature(
        &self,
        data: &Buf,
        signature: &DigitallySigned,
        signature_buf: &[u8],
        cert_der: &[u8],
    ) -> Result<(), String> {
        self.provider().signature_verification.verify_signature(
            cert_der,
            data,
            signature.signature(signature_buf),
            signature.algorithm.hash,
            signature.algorithm.signature,
        )
    }
}

impl Deref for Aad {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Nonce {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
