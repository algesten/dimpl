use crate::message::{CurveType, NamedCurve};
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use num_bigint::{BigUint, RandomBits};
use p256::{ecdh::EphemeralSecret as P256EphemeralSecret, PublicKey as P256PublicKey};
use p384::{ecdh::EphemeralSecret as P384EphemeralSecret, PublicKey as P384PublicKey};
use rand::distributions::Distribution;
use rand::rngs::OsRng;

pub struct KeyExchange {
    inner: Inner,
    cached_public_key: Option<Vec<u8>>,
}

/// Trait for key exchange mechanisms
enum Inner {
    Ecdh(EcdhKeyExchange),
    Dh(DhKeyExchange),
}

impl KeyExchange {
    pub fn new_ecdh(curve: NamedCurve) -> Self {
        Self::new(Inner::Ecdh(EcdhKeyExchange::new(curve)))
    }

    pub fn new_dh(prime: Vec<u8>, generator: Vec<u8>) -> Self {
        Self::new(Inner::Dh(DhKeyExchange::new(prime, generator)))
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
                Inner::Dh(dh) => dh.maybe_init(),
            };
            self.cached_public_key = Some(public_key.to_vec());
        }

        // Return the cached public key.
        self.cached_public_key.as_ref().unwrap()
    }

    /// Compute shared secret using peer's public key
    pub fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, String> {
        match &self.inner {
            Inner::Ecdh(ecdh) => ecdh.compute_shared_secret(peer_public_key),
            Inner::Dh(dh) => dh.compute_shared_secret(peer_public_key),
        }
    }

    /// Get curve info for ECDHE
    pub fn get_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        match &self.inner {
            Inner::Ecdh(ecdh) => ecdh.get_curve_info(),
            Inner::Dh(dh) => dh.get_curve_info(),
        }
    }
}

/// ECDHE Key Exchange
pub enum EcdhKeyExchange {
    P256 {
        private_key: Option<P256EphemeralSecret>,
    },
    P384 {
        private_key: Option<P384EphemeralSecret>,
    },
}

impl EcdhKeyExchange {
    pub fn new(curve: NamedCurve) -> Self {
        match curve {
            NamedCurve::Secp256r1 => EcdhKeyExchange::P256 { private_key: None },
            NamedCurve::Secp384r1 => EcdhKeyExchange::P384 { private_key: None },
            _ => panic!("Unsupported curve"),
        }
    }
}

impl EcdhKeyExchange {
    fn maybe_init(&mut self) -> Vec<u8> {
        match self {
            EcdhKeyExchange::P256 { private_key } => {
                if private_key.is_none() {
                    let secret = P256EphemeralSecret::random(&mut OsRng);
                    *private_key = Some(secret);
                }
                let secret = private_key.as_ref().unwrap();
                let public_key = P256PublicKey::from(secret);
                let encoded_point = public_key.to_encoded_point(false);
                encoded_point.as_bytes().to_vec()
            }
            EcdhKeyExchange::P384 { private_key } => {
                if private_key.is_none() {
                    let secret = P384EphemeralSecret::random(&mut OsRng);
                    *private_key = Some(secret);
                }
                let secret = private_key.as_ref().unwrap();
                let public_key = P384PublicKey::from(secret);
                let encoded_point = public_key.to_encoded_point(false);
                encoded_point.as_bytes().to_vec()
            }
        }
    }

    fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            EcdhKeyExchange::P256 { private_key } => {
                let Some(secret) = private_key else {
                    return Err("Private key not generated".to_string());
                };

                let encoded_point = p256::EncodedPoint::from_bytes(peer_public_key)
                    .map_err(|_| "Invalid peer public key for P-256".to_string())?;

                let public_key_opt = P256PublicKey::from_encoded_point(&encoded_point);
                let Some(public_key) = Option::<P256PublicKey>::from(public_key_opt) else {
                    return Err("Invalid peer public key format for P-256".to_string());
                };

                let shared_secret = secret.diffie_hellman(&public_key);
                Ok(shared_secret.raw_secret_bytes().as_slice().to_vec())
            }
            EcdhKeyExchange::P384 { private_key } => {
                let Some(secret) = private_key else {
                    return Err("Private key not generated".to_string());
                };

                let encoded_point = p384::EncodedPoint::from_bytes(peer_public_key)
                    .map_err(|_| "Invalid peer public key for P-384".to_string())?;

                let public_key_opt = P384PublicKey::from_encoded_point(&encoded_point);
                let Some(public_key) = Option::<P384PublicKey>::from(public_key_opt) else {
                    return Err("Invalid peer public key format for P-384".to_string());
                };

                // Compute the shared secret point
                let shared_secret = secret.diffie_hellman(&public_key);

                // Extract the raw bytes from the shared secret
                let raw_bytes = shared_secret.raw_secret_bytes().as_slice();

                // Create a properly formatted buffer that matches OpenSSL's behavior
                // For P-384, ECDH shared secret is the x-coordinate of the resulting point
                // Ensure it's exactly 48 bytes with proper padding in big-endian format
                let mut formatted_secret = vec![0u8; 48];

                // Copy the raw bytes to the buffer with proper alignment
                // If raw_bytes.len() < 48, preserve leading zeros as needed
                // If raw_bytes.len() == 48, just copy the bytes
                let copy_len = std::cmp::min(raw_bytes.len(), 48);
                let start_idx = 48 - copy_len;
                formatted_secret[start_idx..]
                    .copy_from_slice(&raw_bytes[raw_bytes.len() - copy_len..]);

                // Return the formatted secret
                Ok(formatted_secret)
            }
        }
    }

    fn get_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        match self {
            EcdhKeyExchange::P256 { .. } => Some((CurveType::NamedCurve, NamedCurve::Secp256r1)),
            EcdhKeyExchange::P384 { .. } => Some((CurveType::NamedCurve, NamedCurve::Secp384r1)),
        }
    }
}

/// DHE Key Exchange implementation
pub struct DhKeyExchange {
    /// Diffie-Hellman prime modulus
    prime: BigUint,

    /// Diffie-Hellman generator
    generator: BigUint,

    /// Our private key (random exponent)
    private_key: Option<BigUint>,
}

impl DhKeyExchange {
    pub fn new(prime: Vec<u8>, generator: Vec<u8>) -> Self {
        DhKeyExchange {
            prime: BigUint::from_bytes_be(&prime),
            generator: BigUint::from_bytes_be(&generator),
            private_key: None,
        }
    }
}

impl DhKeyExchange {
    fn maybe_init(&mut self) -> Vec<u8> {
        // Determine bit size of prime
        let prime_bits = self.prime.bits();

        // Generate a random private key smaller than the prime
        let mut rng = OsRng;
        let distribution = RandomBits::new(prime_bits - 1); // One bit less than prime
        let private_key: BigUint = distribution.sample(&mut rng);

        // Compute public key as g^private_key mod p
        let public_key = self.generator.modpow(&private_key, &self.prime);

        // Store private key for later use
        self.private_key = Some(private_key);

        // Return public key as bytes
        public_key.to_bytes_be()
    }

    fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, String> {
        // Convert peer's public key to BigUint
        let peer_public = BigUint::from_bytes_be(peer_public_key);

        // Get our private key
        let Some(private_key) = &self.private_key else {
            return Err("DH private key not generated".to_string());
        };

        // Compute shared secret as peer_public^private_key mod p
        let shared_secret = peer_public.modpow(private_key, &self.prime);

        // Return shared secret as big-endian bytes
        Ok(shared_secret.to_bytes_be())
    }

    fn get_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        None // DHE doesn't use named curves
    }
}
