//! Apple Crypto cryptographic provider implementation for dimpl.
//!
//! This module provides a cryptographic backend for dimpl using pure Rust
//! crates from the [RustCrypto](https://github.com/RustCrypto) organization,
//! optimized for Apple platforms (macOS and iOS).
//!
//! # Feature Flag
//!
//! This module is only available when the `apple-crypto` feature is enabled
//! and only compiles on Apple platforms (macOS, iOS, tvOS, watchOS).
//!
//! ```toml
//! dimpl = { version = "...", features = ["apple-crypto"] }
//! ```
//!
//! # Usage
//!
//! The apple-crypto provider can be explicitly specified:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use dimpl::{Config, Dtls};
//! use dimpl::crypto::apple_crypto;
//!
//! let config = Arc::new(
//!     Config::builder()
//!         .with_crypto_provider(apple_crypto::default_provider())
//!         .build()
//!         .unwrap()
//! );
//! let dtls = Dtls::new(config, cert.certificate, cert.private_key);
//! ```

mod cipher_suite;
mod hash;
mod hmac;
mod kx_group;
mod sign;
mod tls12;

use crate::crypto::provider::CryptoProvider;

/// Get the default Apple Crypto-based crypto provider.
///
/// This provider implements all cryptographic operations required for DTLS 1.2
/// using pure Rust crates from the RustCrypto organization, optimized for
/// Apple platforms.
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
