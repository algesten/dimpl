#![cfg(all(feature = "rcgen", feature = "aws-lc-rs"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::crypto::{CryptoProvider, SecureRandom, aws_lc_rs};
use dimpl::{Config, CryptoError, CryptoOperation, Dtls};

/// Counts the bytes drawn from it, filling them from the aws-lc-rs source.
#[derive(Debug)]
struct Counting(AtomicUsize);

impl SecureRandom for Counting {
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        self.0.fetch_add(buf.len(), Ordering::Relaxed);
        aws_lc_rs::default_provider().secure_random.fill(buf)
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

#[derive(Clone, Copy, Debug)]
enum Version {
    Dtls12,
    Dtls13,
}

fn config(secure_random: &'static dyn SecureRandom) -> Arc<Config> {
    let provider = CryptoProvider {
        secure_random,
        ..aws_lc_rs::default_provider()
    };
    Arc::new(
        Config::builder()
            .with_crypto_provider(provider)
            .build()
            .expect("valid config"),
    )
}

fn endpoint(version: Version, secure_random: &'static dyn SecureRandom, active: bool) -> Dtls {
    let certificate = generate_self_signed_certificate().expect("certificate");
    let now = Instant::now();
    let mut dtls = match version {
        Version::Dtls12 => Dtls::new_12(config(secure_random), certificate, now),
        Version::Dtls13 => Dtls::new_13(config(secure_random), certificate, now),
    };
    dtls.set_active(active);
    dtls
}

#[test]
fn handshake_random_comes_from_the_provider() {
    static DTLS12_CLIENT: Counting = Counting(AtomicUsize::new(0));
    static DTLS12_SERVER: Counting = Counting(AtomicUsize::new(0));
    static DTLS13_CLIENT: Counting = Counting(AtomicUsize::new(0));
    static DTLS13_SERVER: Counting = Counting(AtomicUsize::new(0));
    let cases: [(Version, &'static Counting, bool); 4] = [
        (Version::Dtls12, &DTLS12_CLIENT, true),
        (Version::Dtls12, &DTLS12_SERVER, false),
        (Version::Dtls13, &DTLS13_CLIENT, true),
        (Version::Dtls13, &DTLS13_SERVER, false),
    ];

    for (version, source, active) in cases {
        let mut dtls = endpoint(version, source, active);
        dtls.handle_timeout(Instant::now())
            .expect("handle_timeout with a working source");

        // At least the 28 random bytes of the handshake Random (DTLS 1.2) or 32 (DTLS 1.3).
        let drawn = source.0.load(Ordering::Relaxed);
        assert!(
            drawn >= 28,
            "{version:?} active={active}: {drawn} bytes drawn from the provider"
        );
    }
}

#[test]
fn provider_random_failure_is_an_error() {
    static FAILING: Failing = Failing;

    for version in [Version::Dtls12, Version::Dtls13] {
        for active in [true, false] {
            let mut dtls = endpoint(version, &FAILING, active);
            assert!(
                dtls.handle_timeout(Instant::now()).is_err(),
                "{version:?} active={active}: a failing source must fail the handshake"
            );
        }
    }
}
