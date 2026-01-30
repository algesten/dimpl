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
pub mod provider;
mod validation;

pub use keying::{KeyingMaterial, SrtpProfile};

// Re-export AEAD types needed for Cipher trait implementations (public API)
pub use dtls_aead::{Aad, Nonce};

// Re-export internal AEAD constants/types for crate-internal use
pub(crate) use dtls_aead::{Iv, DTLS_AEAD_OVERHEAD, DTLS_EXPLICIT_NONCE_LEN};

// Re-export all provider traits and types (similar to rustls structure)
// This allows users to do: use dimpl::crypto::{CryptoProvider, SupportedDtls12CipherSuite, ...};
pub use provider::{
    ActiveKeyExchange, Cipher, CryptoProvider, CryptoSafe, HashContext, HashProvider,
};
pub use provider::{HmacProvider, KeyProvider, PrfProvider};
pub use provider::{SecureRandom, SignatureVerifier, SigningKey};
pub use provider::{SupportedDtls12CipherSuite, SupportedKxGroup};
// DTLS 1.3 provider traits
pub use provider::{HkdfProvider, SupportedDtls13CipherSuite};

// Re-export shared types for provider trait implementations
pub use crate::types::{HashAlgorithm, NamedGroup, SignatureAlgorithm, SignatureScheme};
// Version-specific cipher suite types
pub use crate::dtls12::message::Dtls12CipherSuite;
pub use crate::types::Dtls13CipherSuite;

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
