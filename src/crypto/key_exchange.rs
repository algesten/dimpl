use crate::buffer::Buf;
use crate::message::{CurveType, NamedCurve};
use aws_lc_rs::agreement::{agree_ephemeral, EphemeralPrivateKey};
use aws_lc_rs::agreement::{UnparsedPublicKey, ECDH_P256, ECDH_P384};

pub struct KeyExchange {
    inner: Inner,
    cached_public_key: Option<Vec<u8>>,
}

/// Trait for key exchange mechanisms
enum Inner {
    Ecdh(EcdhKeyExchange),
}

impl KeyExchange {
    pub fn new_ecdh(curve: NamedCurve) -> Self {
        Self::new(Inner::Ecdh(EcdhKeyExchange::new(curve)))
    }

    fn new(inner: Inner) -> Self {
        Self {
            inner,
            cached_public_key: None,
        }
    }

    /// Generate new ephemeral keys and return the public key
    pub fn maybe_init(&mut self) -> &[u8] {
        // First time we generate the exchange.
        if self.cached_public_key.is_none() {
            let public_key = match &mut self.inner {
                Inner::Ecdh(ecdh) => ecdh.maybe_init(),
            };
            self.cached_public_key = Some(public_key.to_vec());
        }

        // Return the cached public key.
        self.cached_public_key.as_ref().unwrap()
    }

    /// Compute shared secret using peer's public key
    pub fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Buf, String> {
        match &mut self.inner {
            Inner::Ecdh(ecdh) => ecdh.compute_shared_secret(peer_public_key),
        }
    }

    /// Get curve info for ECDHE
    pub fn get_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        match &self.inner {
            Inner::Ecdh(ecdh) => ecdh.get_curve_info(),
        }
    }
}

/// ECDHE Key Exchange
pub struct EcdhKeyExchange {
    curve: NamedCurve,
    private_key: Option<EphemeralPrivateKey>,
}

impl EcdhKeyExchange {
    pub fn new(curve: NamedCurve) -> Self {
        match curve {
            NamedCurve::Secp256r1 | NamedCurve::Secp384r1 => Self {
                curve,
                private_key: None,
            },
            _ => panic!("Unsupported curve"),
        }
    }

    fn algorithm(&self) -> &'static aws_lc_rs::agreement::Algorithm {
        match self.curve {
            NamedCurve::Secp256r1 => &ECDH_P256,
            NamedCurve::Secp384r1 => &ECDH_P384,
            _ => unreachable!("Unsupported curve"),
        }
    }

    fn compute_public_key(&self) -> Result<Vec<u8>, String> {
        self.private_key
            .as_ref()
            .ok_or_else(|| "Private key not generated".to_string())?
            .compute_public_key()
            .map(|pk| pk.as_ref().to_vec())
            .map_err(|_| "Failed to compute public key".to_string())
    }
}

impl EcdhKeyExchange {
    fn maybe_init(&mut self) -> Vec<u8> {
        if self.private_key.is_none() {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let ephemeral = EphemeralPrivateKey::generate(self.algorithm(), &rng)
                .expect("Failed to generate ephemeral key");
            self.private_key = Some(ephemeral);
        }

        self.compute_public_key()
            .expect("Failed to compute public key")
    }

    fn compute_shared_secret(&mut self, peer_public_key: &[u8]) -> Result<Buf, String> {
        // aws-lc-rs agreement consumes the private key, so we take ownership
        let priv_key = self
            .private_key
            .take()
            .ok_or_else(|| "Private key not generated".to_string())?;

        let algorithm = self.algorithm();
        let peer_key = UnparsedPublicKey::new(algorithm, peer_public_key);

        agree_ephemeral(priv_key, peer_key, "ECDH agreement failed", |secret| {
            let mut buf = Buf::new();
            buf.extend_from_slice(secret);
            Ok(buf)
        })
        .map_err(|e| e.to_string())
    }

    fn get_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        Some((CurveType::NamedCurve, self.curve))
    }
}
