//! Secure random number generation using RustCrypto.

use super::super::SecureRandom;

/// Secure random number generator implementation.
#[derive(Debug)]
pub(super) struct RustCryptoSecureRandom;

impl SecureRandom for RustCryptoSecureRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), String> {
        use rand_core::OsRng;
        use rand_core::RngCore;
        OsRng.fill_bytes(buf);
        Ok(())
    }
}

/// Static instance of the secure random generator.
pub(super) static SECURE_RANDOM: RustCryptoSecureRandom = RustCryptoSecureRandom;
