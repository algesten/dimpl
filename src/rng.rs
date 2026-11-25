//! The engine's random source.
//!
//! Every random value dimpl draws (handshake randoms, cookie secrets, DTLS 1.2
//! explicit nonces, dummy PSKs, retransmit timer jitter and the AEAD KeyUpdate
//! threshold jitter) comes from the configured crypto provider's
//! [`SecureRandom`], the same source the provider uses for its own keys.
//!
//! When a seed is provided via [`Config::rng_seed`], those values come from a
//! deterministic generator instead. This is useful for testing and debugging.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use crate::CryptoError;
use crate::crypto::SecureRandom;

/// The engine's random source: the crypto provider's [`SecureRandom`], or a
/// deterministic generator when seeded.
pub struct SeededRng {
    source: &'static dyn SecureRandom,
    seeded: Option<StdRng>,
}

impl SeededRng {
    /// Create a random source drawing from `source`.
    ///
    /// If `seed` is `Some`, values come from a deterministic generator and
    /// `source` is not used.
    pub fn new(seed: Option<u64>, source: &'static dyn SecureRandom) -> Self {
        let seeded = seed.map(StdRng::seed_from_u64);
        Self { source, seeded }
    }

    /// `N` random bytes. A failure of the provider's source is returned.
    pub fn random<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        if let Some(rng) = self.seeded.as_mut() {
            return Ok(rng.random());
        }
        let mut out = [0; N];
        self.source.fill(&mut out)?;
        Ok(out)
    }

    /// A random `u64` for jitter.
    ///
    /// Jitter is not secret, so a failure of the provider's source yields 0
    /// (no jitter) instead of an error.
    pub fn jitter_u64(&mut self) -> u64 {
        if let Some(rng) = self.seeded.as_mut() {
            return rng.random();
        }
        self.random::<8>().map(u64::from_be_bytes).unwrap_or(0)
    }

    /// A random `f32` in `[0, 1)` for jitter.
    ///
    /// Jitter is not secret, so a failure of the provider's source yields 0.5
    /// (the midpoint, no jitter) instead of an error.
    pub fn jitter_unit_f32(&mut self) -> f32 {
        if let Some(rng) = self.seeded.as_mut() {
            return rng.random();
        }
        match self.random::<4>() {
            // 24 random bits, the precision of an f32 mantissa.
            Ok(b) => (u32::from_be_bytes(b) >> 8) as f32 / (1u32 << 24) as f32,
            Err(_) => 0.5,
        }
    }

    /// A seeded source for tests that must never touch the provider.
    #[cfg(test)]
    pub fn seeded(seed: u64) -> Self {
        Self::new(Some(seed), &tests::Unused)
    }
}

impl std::fmt::Debug for SeededRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_seeded = self.seeded.is_some();
        f.debug_struct("SeededRng")
            .field("seeded", &is_seeded)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::CryptoOperation;

    /// A source that must not be drawn from.
    #[derive(Debug)]
    pub struct Unused;

    impl SecureRandom for Unused {
        fn fill(&self, _buf: &mut [u8]) -> Result<(), CryptoError> {
            panic!("a seeded source drew from the provider");
        }
    }

    /// Counts the bytes drawn and fills them with a fixed value.
    #[derive(Debug)]
    struct Counting(AtomicUsize);

    impl SecureRandom for Counting {
        fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
            self.0.fetch_add(buf.len(), Ordering::Relaxed);
            buf.fill(0xA5);
            Ok(())
        }
    }

    /// Always fails.
    #[derive(Debug)]
    struct Failing;

    impl SecureRandom for Failing {
        fn fill(&self, _buf: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::OperationFailed(CryptoOperation::FillRandom))
        }
    }

    #[test]
    fn unseeded_draws_come_from_the_provider() {
        static SOURCE: Counting = Counting(AtomicUsize::new(0));
        let mut rng = SeededRng::new(None, &SOURCE);

        assert_eq!(rng.random::<16>().unwrap(), [0xA5; 16]);
        let _ = rng.jitter_u64();
        let _ = rng.jitter_unit_f32();

        assert_eq!(SOURCE.0.load(Ordering::Relaxed), 16 + 8 + 4);
    }

    #[test]
    fn provider_failure_is_returned_for_values_and_ignored_for_jitter() {
        let mut rng = SeededRng::new(None, &Failing);

        assert!(rng.random::<32>().is_err());
        assert_eq!(rng.jitter_u64(), 0);
        assert_eq!(rng.jitter_unit_f32(), 0.5);
    }

    #[test]
    fn unit_jitter_is_below_one() {
        #[derive(Debug)]
        struct Max;
        impl SecureRandom for Max {
            fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
                buf.fill(0xFF);
                Ok(())
            }
        }
        let mut rng = SeededRng::new(None, &Max);
        assert!(rng.jitter_unit_f32() < 1.0);
    }

    #[test]
    fn seeded_rng_is_deterministic() {
        let mut rng1 = SeededRng::seeded(12345);
        let mut rng2 = SeededRng::seeded(12345);

        assert_eq!(
            rng1.random::<32>().unwrap(),
            rng2.random::<32>().unwrap(),
            "Same seed should produce same values"
        );
        assert_eq!(rng1.jitter_u64(), rng2.jitter_u64());
    }

    #[test]
    fn different_seeds_produce_different_values() {
        let mut rng1 = SeededRng::seeded(12345);
        let mut rng2 = SeededRng::seeded(54321);

        assert_ne!(
            rng1.random::<8>().unwrap(),
            rng2.random::<8>().unwrap(),
            "Different seeds should produce different values"
        );
    }
}
