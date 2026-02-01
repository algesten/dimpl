//! RustCrypto cryptographic provider implementation for dimpl.
//!
//! This module provides a pure Rust cryptographic backend for dimpl using
//! crates from the [RustCrypto](https://github.com/RustCrypto) organization.
//!
//! # Feature Flag
//!
//! This module is only available when the `rust-crypto` feature is enabled. The `rust-crypto`
//! feature is included in the default features, so it's enabled by default. To use
//! dimpl without this module, disable default features:
//!
//! ```toml
//! dimpl = { version = "...", default-features = false }
//! ```
//!
//! # Usage
//!
//! The rust-crypto provider is used automatically as a fallback when aws-lc-rs is not available
//! or when explicitly specified:
//!
//! ```
//! # #[cfg(feature = "rcgen")]
//! # fn main() {
//! use std::sync::Arc;
//! use std::time::Instant;
//! use dimpl::{Config, Dtls, certificate};
//! use dimpl::crypto::rust_crypto;
//!
//! let cert = certificate::generate_self_signed_certificate().unwrap();
//! let config = Arc::new(
//!     Config::builder()
//!         .with_crypto_provider(rust_crypto::default_provider())
//!         .build()
//!         .unwrap()
//! );
//! let dtls = Dtls::new(config, cert, Instant::now());
//! # }
//! # #[cfg(not(feature = "rcgen"))]
//! # fn main() {}
//! ```

mod cipher_suite;
mod hash;
mod hmac;
mod kx_group;
mod sign;
mod tls12;

use crate::crypto::provider::CryptoProvider;

/// Get the default RustCrypto-based crypto provider.
///
/// This provider implements all cryptographic operations required for DTLS 1.2
/// using pure Rust crates from the RustCrypto organization.
///
/// # Supported Cipher Suites
///
/// - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B)
/// - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C)
///
/// # Supported Key Exchange Groups
///
/// - `secp256r1` (P-256, NIST Curve)
/// - `secp384r1` (P-384, NIST Curve)
///
/// # Supported Signature Algorithms
///
/// - ECDSA with P-256 and SHA-256
/// - ECDSA with P-384 and SHA-384
///
/// # Supported Hash Algorithms
///
/// - SHA-256
/// - SHA-384
///
/// # Key Formats
///
/// The key provider supports loading private keys in:
/// - PKCS#8 DER format (most common)
/// - SEC1 DER format (OpenSSL EC private key format)
/// - PEM encoded versions of the above
///
/// # TLS 1.2 PRF
///
/// Implements the TLS 1.2 PRF for key derivation, including:
/// - Standard PRF for master secret and key expansion
/// - Extended Master Secret (RFC 7627) for improved security
///
/// # Random Number Generation
///
/// Uses `OsRng` from the `rand` crate for cryptographically secure random number generation.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: cipher_suite::ALL_CIPHER_SUITES,
        kx_groups: kx_group::ALL_KX_GROUPS,
        signature_verification: &sign::SIGNATURE_VERIFIER,
        key_provider: &sign::KEY_PROVIDER,
        secure_random: &tls12::SECURE_RANDOM,
        hash_provider: &hash::HASH_PROVIDER,
        prf_provider: &tls12::PRF_PROVIDER,
        hmac_provider: &tls12::HMAC_PROVIDER,
    }
}
