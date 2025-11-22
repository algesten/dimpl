//! Cryptographic provider traits for pluggable crypto backends.
//!
//! This module defines the trait-based interface for cryptographic operations
//! in dimpl, allowing users to provide custom crypto implementations.
//!
//! # Overview
//!
//! The crypto provider system is inspired by rustls's design and uses a component-based
//! approach where the [`CryptoProvider`] struct holds static references to various
//! trait objects, each representing a specific cryptographic capability.
//!
//! # Architecture
//!
//! The provider system is organized into these main components:
//!
//! - **Cipher Suites** ([`SupportedCipherSuite`]): Factory for AEAD ciphers
//! - **Key Exchange Groups** ([`SupportedKxGroup`]): Factory for ECDHE key exchanges
//! - **Signature Verification** ([`SignatureVerifier`]): Verify signatures in certificates
//! - **Key Provider** ([`KeyProvider`]): Parse and load private keys
//! - **Secure Random** ([`SecureRandom`]): Cryptographically secure RNG
//! - **Hash Provider** ([`HashProvider`]): Factory for hash contexts
//! - **PRF Provider** ([`PrfProvider`]): TLS 1.2 PRF for key derivation
//!
//! # Using a Custom Provider
//!
//! To use a custom crypto provider, create one and pass it to the [`Config`](crate::Config):
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use dimpl::{Config, Dtls};
//! use dimpl::crypto::{CryptoProvider, aws_lc_rs};
//!
//! let mut config = Config::default();
//!
//! // Use the default aws-lc-rs provider
//! config.crypto_provider = Some(Arc::new(aws_lc_rs::default_provider()));
//!
//! // Or create your own custom provider
//! // config.crypto_provider = Some(Arc::new(my_custom_provider()));
//!
//! let dtls = Dtls::new(config);
//! ```
//!
//! # Implementing a Custom Provider
//!
//! To implement a custom provider, you need to:
//!
//! 1. Implement the required traits for your crypto backend
//! 2. Create static instances of your implementations
//! 3. Build a [`CryptoProvider`] struct with references to those statics
//!
//! ## Example: Custom Cipher Suite
//!
//! ```rust,ignore
//! use dimpl::crypto::{SupportedCipherSuite, Cipher, CipherSuite, HashAlgorithm};
//!
//! #[derive(Debug)]
//! struct MyCipherSuite;
//!
//! impl SupportedCipherSuite for MyCipherSuite {
//!     fn suite(&self) -> CipherSuite {
//!         CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
//!     }
//!
//!     fn hash_algorithm(&self) -> HashAlgorithm {
//!         HashAlgorithm::SHA256
//!     }
//!
//!     fn key_lengths(&self) -> (usize, usize, usize) {
//!         (0, 16, 4) // (mac_key_len, enc_key_len, fixed_iv_len)
//!     }
//!
//!     fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String> {
//!         // Create your cipher implementation here
//!         Ok(Box::new(MyCipher::new(key)?))
//!     }
//! }
//!
//! static MY_CIPHER_SUITE: MyCipherSuite = MyCipherSuite;
//! static ALL_CIPHER_SUITES: &[&dyn SupportedCipherSuite] = &[&MY_CIPHER_SUITE];
//! ```
//!
//! # Requirements
//!
//! For DTLS 1.2, implementations must support:
//!
//! - **Cipher suites**: ECDHE_ECDSA with AES-128-GCM or AES-256-GCM
//! - **Key exchange**: ECDHE with P-256 or P-384 curves
//! - **Signatures**: ECDSA with P-256/SHA-256 or P-384/SHA-384
//! - **Hash**: SHA-256 and SHA-384
//! - **PRF**: TLS 1.2 PRF (using HMAC-SHA256 or HMAC-SHA384)
//!
//! # Thread Safety
//!
//! All provider traits require `Send + Sync + UnwindSafe + RefUnwindSafe` to ensure
//! safe usage across threads and panic boundaries.

use std::fmt::Debug;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};
use crate::message::{CipherSuite, HashAlgorithm, NamedCurve, SignatureAlgorithm};

// ============================================================================
// Marker Trait
// ============================================================================

/// Marker trait for types that are safe to use in crypto provider components.
///
/// This trait combines the common bounds required for crypto provider trait objects:
/// - [`Send`] + [`Sync`]: Thread-safe
/// - [`Debug`]: Support debugging
/// - [`UnwindSafe`] + [`RefUnwindSafe`]: Panic-safe
///
/// This trait is automatically implemented for all types that satisfy these bounds.
pub trait CryptoSafe: Send + Sync + Debug + UnwindSafe + RefUnwindSafe {}

/// Blanket implementation: any type satisfying the bounds implements [`CryptoSafe`].
impl<T: Send + Sync + Debug + UnwindSafe + RefUnwindSafe> CryptoSafe for T {}

// ============================================================================
// Instance Traits (Level 2 - created by factories)
// ============================================================================

/// AEAD cipher for in-place encryption/decryption.
pub trait Cipher: Send + Sync + UnwindSafe {
    /// Encrypt plaintext in-place, appending authentication tag.
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), String>;

    /// Decrypt ciphertext in-place, verifying and removing authentication tag.
    fn decrypt(&mut self, ciphertext: &mut TmpBuf, aad: Aad, nonce: Nonce) -> Result<(), String>;
}

/// Stateful hash context for incremental hashing.
pub trait HashContext: Send {
    /// Update the hash with new data.
    fn update(&mut self, data: &[u8]);

    /// Clone the context and finalize it, returning the hash.
    /// The original context can continue to be updated.
    fn clone_and_finalize(&self) -> Vec<u8>;
}

/// Signing key for generating digital signatures.
pub trait SigningKey: Send + Sync + Debug + RefUnwindSafe {
    /// Sign data and return the signature.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Signature algorithm used by this key.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Default hash algorithm for this key.
    fn hash_algorithm(&self) -> HashAlgorithm;

    /// Check if this key is compatible with a cipher suite.
    fn is_compatible(&self, cipher_suite: CipherSuite) -> bool;
}

/// Active key exchange instance (ephemeral keypair for one handshake).
pub trait ActiveKeyExchange: Send + Sync + UnwindSafe {
    /// Get the public key for this exchange.
    fn pub_key(&self) -> &[u8];

    /// Complete exchange with peer's public key, returning shared secret.
    fn complete(self: Box<Self>, peer_pub: &[u8]) -> Result<Buf, String>;

    /// Get the named curve for this exchange.
    fn group(&self) -> NamedCurve;
}

// ============================================================================
// Factory Traits (Level 1 - used by CryptoProvider)
// ============================================================================

/// Cipher suite support (factory for Cipher instances).
pub trait SupportedCipherSuite: CryptoSafe {
    /// The cipher suite this supports.
    fn suite(&self) -> CipherSuite;

    /// Hash algorithm used by this suite.
    fn hash_algorithm(&self) -> HashAlgorithm;

    /// Key material lengths: (mac_key_len, enc_key_len, fixed_iv_len).
    fn key_lengths(&self) -> (usize, usize, usize);

    /// Create a cipher instance with the given key.
    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, String>;
}

/// Key exchange group support (factory for ActiveKeyExchange).
pub trait SupportedKxGroup: CryptoSafe {
    /// Named curve for this group.
    fn name(&self) -> NamedCurve;

    /// Start a new key exchange, generating ephemeral keypair.
    fn start_exchange(&self) -> Result<Box<dyn ActiveKeyExchange>, String>;
}

/// Signature verification against certificates.
pub trait SignatureVerifier: CryptoSafe {
    /// Verify a signature on data using a DER-encoded X.509 certificate.
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlgorithm,
        sig_alg: SignatureAlgorithm,
    ) -> Result<(), String>;
}

/// Private key parser (factory for SigningKey).
pub trait KeyProvider: CryptoSafe {
    /// Parse and load a private key from DER/PEM bytes.
    fn load_private_key(&self, key_der: &[u8]) -> Result<Arc<dyn SigningKey>, String>;
}

/// Secure random number generator.
pub trait SecureRandom: CryptoSafe {
    /// Fill buffer with cryptographically secure random bytes.
    fn fill(&self, buf: &mut [u8]) -> Result<(), String>;
}

/// Hash provider (factory for HashContext).
pub trait HashProvider: CryptoSafe {
    /// Create a new hash context for the specified algorithm.
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext>;
}

/// PRF (Pseudo-Random Function) for TLS 1.2 key derivation.
pub trait PrfProvider: CryptoSafe {
    /// TLS 1.2 PRF: PRF(secret, label, seed) with specified output length.
    fn prf_tls12(
        &self,
        secret: &[u8],
        label: &str,
        seed: &[u8],
        output_len: usize,
        hash: HashAlgorithm,
    ) -> Result<Vec<u8>, String>;
}

// ============================================================================
// Core Provider Struct
// ============================================================================

/// Cryptographic provider for DTLS operations.
///
/// This struct holds references to all cryptographic components needed
/// for DTLS 1.2. Users can provide custom implementations of each component
/// to replace the default aws-lc-rs-based provider.
///
/// # Design
///
/// The provider uses static trait object references (`&'static dyn Trait`) which
/// provides zero runtime overhead for trait dispatch. This design is inspired by
/// rustls's CryptoProvider and ensures efficient crypto operations.
///
/// # Example
///
/// ```rust,ignore
/// use dimpl::crypto::{CryptoProvider, aws_lc_rs};
///
/// // Use the default provider
/// let provider = aws_lc_rs::default_provider();
///
/// // Or build a custom one
/// let custom_provider = CryptoProvider {
///     cipher_suites: my_cipher_suites::ALL,
///     kx_groups: my_kx_groups::ALL,
///     signature_verification: &my_verifier::VERIFIER,
///     key_provider: &my_keys::KEY_PROVIDER,
///     secure_random: &my_rng::RNG,
///     hash_provider: &my_hash::HASH_PROVIDER,
///     prf_provider: &my_prf::PRF_PROVIDER,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CryptoProvider {
    /// Supported cipher suites (for negotiation).
    pub cipher_suites: &'static [&'static dyn SupportedCipherSuite],

    /// Supported key exchange groups (P-256, P-384).
    pub kx_groups: &'static [&'static dyn SupportedKxGroup],

    /// Signature verification for certificates.
    pub signature_verification: &'static dyn SignatureVerifier,

    /// Key provider for parsing private keys.
    pub key_provider: &'static dyn KeyProvider,

    /// Secure random number generator.
    pub secure_random: &'static dyn SecureRandom,

    /// Hash provider for handshake hashing.
    pub hash_provider: &'static dyn HashProvider,

    /// PRF for TLS 1.2 key derivation.
    pub prf_provider: &'static dyn PrfProvider,
}
