//! AWS-LC-RS cryptographic provider implementation for dimpl.
//!
//! This module provides the default cryptographic backend for dimpl using
//! [aws-lc-rs](https://github.com/aws/aws-lc-rs), Amazon's cryptographic library
//! based on AWS-LC (a fork of BoringSSL).
//!
//! # Usage
//!
//! The default provider is used automatically when no custom provider is specified:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use dimpl::{Config, Dtls};
//!
//! // Implicitly uses aws-lc-rs default provider
//! let config = Arc::new(Config::default());
//! let dtls = Dtls::new(config, cert.certificate, cert.private_key);
//! ```
//!
//! Or explicitly:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use dimpl::{Config, Dtls};
//! use dimpl::crypto::aws_lc_rs;
//!
//! let config = Arc::new(
//!     Config::builder()
//!         .with_crypto_provider(aws_lc_rs::default_provider())
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

/// Get the default aws-lc-rs based crypto provider.
///
/// This provider implements all cryptographic operations required for DTLS 1.2
/// using the aws-lc-rs library (AWS's cryptographic library based on BoringSSL/AWS-LC).
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
/// Uses `SystemRandom` from aws-lc-rs for cryptographically secure random number generation.
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
