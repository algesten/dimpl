//! Cryptographic primitives and helpers used by the DTLS engine.

use std::ops::Deref;

// Internal module imports
mod keying;

// Provider traits and implementations
#[cfg(feature = "aws-lc-rs")]
pub mod aws_lc_rs;

#[cfg(feature = "rust-crypto")]
pub mod rust_crypto;

mod dtls_aead;
mod provider;
mod validation;

pub use keying::{KeyingMaterial, SrtpProfile};

// Re-export AEAD types needed for Cipher trait implementations (public API)
pub use dtls_aead::{Aad, Nonce};

// Re-export internal AEAD constants/types for crate-internal use
pub(crate) use dtls_aead::{Iv, DTLS_AEAD_OVERHEAD, DTLS_EXPLICIT_NONCE_LEN};

// Re-export buffer types for provider trait implementations
pub use crate::buffer::{Buf, TmpBuf};

// Re-export all provider traits and types (similar to rustls structure)
// This allows users to do: use dimpl::crypto::{CryptoProvider, SupportedDtls12CipherSuite, ...};
pub use provider::{
    check_verify_scheme, ActiveKeyExchange, Cipher, CryptoProvider, CryptoSafe, HashContext,
    HashProvider, HkdfProvider, HmacProvider, KeyProvider, PrfProvider, SecureRandom,
    SignatureVerifier, SigningKey, SupportedDtls12CipherSuite, SupportedDtls13CipherSuite,
    SupportedKxGroup,
};

// Re-export shared types for provider trait implementations
pub use crate::dtls12::message::Dtls12CipherSuite;
pub use crate::types::{
    Dtls13CipherSuite, HashAlgorithm, NamedGroup, SignatureAlgorithm, SignatureScheme,
};

impl Deref for Aad {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

impl Deref for Nonce {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
