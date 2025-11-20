//! Cryptographic primitives and helpers used by the DTLS engine.

use std::ops::Deref;

use arrayvec::ArrayVec;
use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1};

// Internal module imports
mod encryption;
mod hash;
mod key_exchange;
mod keying;
mod parsed_key;
mod prf;
mod signing;

pub use encryption::{AesGcm, Cipher};
pub use hash::Hash;
pub use key_exchange::KeyExchange;
pub use keying::{KeyingMaterial, SrtpProfile};
pub use parsed_key::ParsedKey;
pub use prf::calculate_extended_master_secret;
pub use prf::{key_expansion, prf_tls12};

use crate::buffer::{Buf, TmpBuf, ToBuf};
use crate::message::{
    Asn1Cert, Certificate, CipherSuite, ContentType, CurveType, ServerKeyExchange,
};
use crate::message::{DigitallySigned, HashAlgorithm};
use crate::message::{NamedCurve, Sequence, ServerKeyExchangeParams, SignatureAlgorithm};

use der::Decode;
use spki::ObjectIdentifier;
use x509_cert::Certificate as X509Certificate;

/// DTLS AEAD (AES-GCM) record formatting constants
///
/// For GCM ciphers in DTLS (RFC 6347 + RFC 5288):
/// - Each encrypted record fragment starts with an 8-byte explicit nonce
/// - The GCM authentication tag is 16 bytes and appended to the ciphertext
/// - The AAD length is the plaintext length (TLSCompressed.length / DTLSCompressed.length)
///
/// Explicit nonce length for DTLS AEAD records.
///
/// The explicit nonce is transmitted with each record.
pub const DTLS_EXPLICIT_NONCE_LEN: usize = 8;
/// GCM authentication tag length.
///
/// The tag is appended to the ciphertext.
pub const GCM_TAG_LEN: usize = 16;
/// Overhead per AEAD record (explicit nonce + tag).
///
/// This equals 24 bytes for DTLS AES-GCM.
pub const DTLS_AEAD_OVERHEAD: usize = DTLS_EXPLICIT_NONCE_LEN + GCM_TAG_LEN; // 24

/// Return the AAD length given a plaintext length. For DTLS AEAD this is the plaintext length.
#[inline]
#[allow(dead_code)]
/// Compute AAD length from plaintext length for AEAD records.
pub fn aad_len_from_plaintext_len(plaintext_len: u16) -> u16 {
    plaintext_len
}

/// Compute the DTLS record fragment length given a plaintext length for AEAD ciphers.
/// fragment_len = explicit_nonce(8) + ciphertext(plaintext_len + 16 tag)
#[inline]
#[allow(dead_code)]
/// Compute fragment length from plaintext length for AEAD records.
pub fn fragment_len_from_plaintext_len(plaintext_len: usize) -> usize {
    DTLS_EXPLICIT_NONCE_LEN + plaintext_len + GCM_TAG_LEN
}

/// Compute the plaintext length from a DTLS AEAD record fragment length.
/// Returns None if the fragment is smaller than the mandatory AEAD overhead.
#[inline]
#[allow(dead_code)]
/// Compute plaintext length from fragment length, if large enough.
pub fn plaintext_len_from_fragment_len(fragment_len: usize) -> Option<usize> {
    fragment_len.checked_sub(DTLS_AEAD_OVERHEAD)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed IV portion for DTLS AEAD.
pub struct Iv(pub [u8; 4]);
impl Iv {
    fn new(iv: &[u8]) -> Self {
        // invariant: the iv is 4 bytes.
        Self(iv.try_into().unwrap())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Full AEAD nonce (fixed IV + explicit nonce).
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    pub fn new(iv: Iv, explicit_nonce: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&iv.0);
        nonce[4..].copy_from_slice(explicit_nonce);
        Self(nonce)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Additional Authenticated Data for DTLS records.
pub struct Aad(pub [u8; 13]);

impl Aad {
    pub fn new(content_type: ContentType, sequence: Sequence, length: u16) -> Self {
        // Exactly match the format used in the working dtls implementation
        let mut aad = [0u8; 13];

        // First set the full 8-byte sequence number
        aad[..8].copy_from_slice(&sequence.sequence_number.to_be_bytes());

        // Then overwrite the first 2 bytes with epoch
        aad[..2].copy_from_slice(&sequence.epoch.to_be_bytes());

        // Content type at index 8
        aad[8] = content_type.as_u8();

        // Protocol version bytes (major:minor) at indexes 9-10
        aad[9] = 0xfe; // DTLS 1.2 major version
        aad[10] = 0xfd; // DTLS 1.2 minor version

        // Payload length (2 bytes) at indexes 11-12
        aad[11..].copy_from_slice(&length.to_be_bytes());

        Aad(aad)
    }
}

/// DTLS crypto context
/// Crypto context holding negotiated keys and ciphers for a DTLS session.
pub struct CryptoContext {
    /// Key exchange mechanism
    key_exchange: Option<KeyExchange>,

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
    client_cipher: Option<Box<dyn Cipher>>,

    /// Server cipher
    server_cipher: Option<Box<dyn Cipher>>,

    /// Certificate (DER format)
    certificate: Vec<u8>,

    /// Parsed private key for the certificate with signature algorithm
    private_key: ParsedKey,

    /// Client random (needed for SRTP key export per RFC 5705)
    client_random: Option<ArrayVec<u8, 32>>,

    /// Server random (needed for SRTP key export per RFC 5705)
    server_random: Option<ArrayVec<u8, 32>>,
}

impl CryptoContext {
    /// Create a new crypto context
    pub fn new(certificate: Vec<u8>, private_key: Vec<u8>) -> Self {
        // Validate that we have a certificate and private key
        if certificate.is_empty() {
            panic!("Client certificate cannot be empty");
        }

        if private_key.is_empty() {
            panic!("Client private key cannot be empty");
        }

        // Parse the private key
        let private_key =
            ParsedKey::try_parse_key(&private_key).expect("Failed to parse client private key");

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
            certificate,
            private_key,
            client_random: None,
            server_random: None,
        }
    }

    /// Generate key exchange public key
    pub fn maybe_init_key_exchange(&mut self) -> Result<&[u8], String> {
        match &mut self.key_exchange {
            Some(ke) => Ok(ke.maybe_init()),
            None => Err("Key exchange not initialized".to_string()),
        }
    }

    /// Process peer's public key and compute shared secret
    pub fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<(), String> {
        match &mut self.key_exchange {
            Some(ke) => {
                self.pre_master_secret = Some(ke.compute_shared_secret(peer_public_key)?);
                Ok(())
            }
            None => Err("Key exchange not initialized".to_string()),
        }
    }

    /// Initialize ECDHE key exchange (server role) and return our ephemeral public key
    pub fn init_ecdh_server(&mut self, named_curve: NamedCurve) -> Result<&[u8], String> {
        // Only support P-256 and P-384 for now
        match named_curve {
            NamedCurve::Secp256r1 | NamedCurve::Secp384r1 => {}
            _ => return Err("Unsupported ECDHE named curve".to_string()),
        }

        self.key_exchange = Some(KeyExchange::new_ecdh(named_curve));
        self.maybe_init_key_exchange()
    }

    /// Process a ServerKeyExchange message and set up key exchange accordingly
    pub fn process_server_key_exchange(&mut self, ske: &ServerKeyExchange) -> Result<(), String> {
        // Process the server key exchange message based on the parameter type
        match &ske.params {
            ServerKeyExchangeParams::Ecdh(ecdh_params) => {
                // For ECDHE, create a new EcdhKeyExchange with the specified curve
                let curve = ecdh_params.named_curve;
                let server_public = ecdh_params.public_key.to_vec();

                // Only support P-256 and P-384
                match curve {
                    NamedCurve::Secp256r1 | NamedCurve::Secp384r1 => {}
                    _ => return Err("Unsupported ECDHE named curve".to_string()),
                }

                // Update our key exchange
                self.key_exchange = Some(KeyExchange::new_ecdh(curve));

                // Generate our keypair
                let _our_public = self.maybe_init_key_exchange()?;

                // Compute shared secret with the server's public key
                self.compute_shared_secret(&server_public)?;

                Ok(())
            }
        }
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
        self.master_secret = Some(calculate_extended_master_secret(pms, session_hash, hash)?);
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

        // Key sizes depend on the cipher suite
        let (mac_key_len, enc_key_len, fixed_iv_len) = match cipher_suite {
            // AES-128-GCM suites
            CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => (0, 16, 4),

            // AES-256-GCM suites
            CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => (0, 32, 4),

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

        // Initialize ciphers
        match cipher_suite {
            // AES-GCM suites
            CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
            | CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => {
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
        let cert = Asn1Cert(self.certificate.as_slice());
        let mut certs = ArrayVec::new();
        certs.push(cert);
        Certificate::new(certs)
    }

    /// Sign the provided data using the client's private key
    /// Returns the signature or an error if signing fails
    pub fn sign_data(&self, data: &[u8], _hash_alg: HashAlgorithm) -> Result<Vec<u8>, String> {
        // Use the signing module to sign the data
        signing::sign_data(&self.private_key, data)
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
        prf_tls12(master_secret, label, handshake_hash, 12, hash)
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

        let keying_material = prf_tls12(
            master_secret,
            DTLS_SRTP_KEY_LABEL,
            &seed,
            profile.keying_material_len(),
            hash,
        )?;

        Ok(keying_material)
    }

    /// Get curve info for ECDHE key exchange
    pub fn get_key_exchange_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        let Some(ke) = &self.key_exchange else {
            return None;
        };
        ke.get_curve_info()
    }

    /// Signature algorithm for the configured private key
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.private_key.signature_algorithm()
    }

    /// Default hash algorithm for the configured private key
    pub fn private_key_default_hash_algorithm(&self) -> HashAlgorithm {
        self.private_key.default_hash_algorithm()
    }

    /// Check if the client's private key is compatible with a given cipher suite
    /// Whether the configured private key is compatible with the cipher suite
    pub fn is_cipher_suite_compatible(&self, cipher_suite: CipherSuite) -> bool {
        self.private_key.is_compatible(cipher_suite)
    }

    /// Get client write IV
    /// Get the client write IV if derived
    pub fn get_client_write_iv(&self) -> Option<Iv> {
        self.client_write_iv
    }

    /// Get server write IV
    /// Get the server write IV if derived
    pub fn get_server_write_iv(&self) -> Option<Iv> {
        self.server_write_iv
    }

    /// Verify a DigitallySigned structure against a certificate's public key.
    pub fn verify_signature(
        &self,
        data: &Buf,
        signature: &DigitallySigned<'_>,
        cert_der: &[u8],
    ) -> Result<(), String> {
        // Parse the server certificate to extract SubjectPublicKeyInfo
        let cert = X509Certificate::from_der(cert_der)
            .map_err(|e| format!("Failed to parse server certificate: {e}"))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;

        // OIDs we care about
        // id-ecPublicKey: 1.2.840.10045.2.1
        const OID_EC_PUBLIC_KEY: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

        let alg_oid = spki.algorithm.oid;

        match alg_oid {
            OID_EC_PUBLIC_KEY => {
                // Signature type must be ECDSA
                if signature.algorithm.signature != SignatureAlgorithm::ECDSA {
                    return Err("Signature algorithm mismatch: expected ECDSA".to_string());
                }

                // Extract uncompressed EC point bytes
                let pubkey_bytes = spki
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| "Invalid EC subject_public_key bitstring".to_string())?;

                // Determine the algorithm based on hash and key size
                let algorithm = match signature.algorithm.hash {
                    HashAlgorithm::SHA256 => {
                        // P-256 with SHA-256
                        &ECDSA_P256_SHA256_ASN1
                    }
                    HashAlgorithm::SHA384 => {
                        // P-384 with SHA-384
                        &ECDSA_P384_SHA384_ASN1
                    }
                    _ => {
                        return Err(format!(
                            "Unsupported hash algorithm for ECDSA: {:?}",
                            signature.algorithm.hash
                        ));
                    }
                };

                let public_key = UnparsedPublicKey::new(algorithm, pubkey_bytes);

                public_key.verify(data, signature.signature).map_err(|_| {
                    format!(
                        "ECDSA signature verification failed for {:?}",
                        signature.algorithm.hash
                    )
                })
            }
            other => Err(format!(
                "Unsupported public key algorithm OID in certificate: {other}"
            )),
        }
    }
}

impl CipherSuite {
    /// Return (mac_key_len, enc_key_len, fixed_iv_len) for this suite.
    pub fn key_length(&self) -> (usize, usize, usize) {
        match self {
            // AES-128-GCM suites
            CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => (0, 16, 4),

            // AES-256-GCM suites
            CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => (0, 32, 4),

            CipherSuite::Unknown(_) => (0, 32, 4), // Default to AES-256-GCM
        }
    }

    /// Whether this suite is an AEAD GCM cipher.
    pub fn is_gcm(&self) -> bool {
        matches!(
            self,
            CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 | CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_constants_and_length_helpers() {
        assert_eq!(DTLS_EXPLICIT_NONCE_LEN, 8);
        assert_eq!(GCM_TAG_LEN, 16);
        assert_eq!(DTLS_AEAD_OVERHEAD, 24);

        for &pt_len in &[0usize, 1, 37, 512, 1350, 16384] {
            let aad_len = aad_len_from_plaintext_len(pt_len as u16);
            assert_eq!(aad_len as usize, pt_len);

            let frag_len = fragment_len_from_plaintext_len(pt_len);
            assert_eq!(frag_len, DTLS_EXPLICIT_NONCE_LEN + pt_len + GCM_TAG_LEN);

            let roundtrip =
                plaintext_len_from_fragment_len(frag_len).expect("frag_len >= overhead");
            assert_eq!(roundtrip, pt_len);
        }

        assert!(plaintext_len_from_fragment_len(0).is_none());
        assert!(plaintext_len_from_fragment_len(3).is_none());
        assert!(plaintext_len_from_fragment_len(DTLS_AEAD_OVERHEAD - 1).is_none());
    }
}
