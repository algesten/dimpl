use crate::message::{CurveType, NamedCurve};
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use num_bigint::{BigUint, RandomBits};
use p256::{ecdh::EphemeralSecret as P256EphemeralSecret, PublicKey as P256PublicKey};
use p384::{ecdh::EphemeralSecret as P384EphemeralSecret, PublicKey as P384PublicKey};
use rand::distributions::Distribution;
use rand::rngs::OsRng;

/// Trait for key exchange mechanisms
pub trait KeyExchange {
    /// Generate new ephemeral keys and return the public key
    fn generate(&mut self) -> Vec<u8>;

    /// Compute shared secret using peer's public key
    fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, String>;

    /// Get curve info for ECDHE
    fn get_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        None
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

impl KeyExchange for EcdhKeyExchange {
    fn generate(&mut self) -> Vec<u8> {
        match self {
            EcdhKeyExchange::P256 { private_key } => {
                let secret = P256EphemeralSecret::random(&mut OsRng);
                let public_key = P256PublicKey::from(&secret);
                let encoded_point = public_key.to_encoded_point(false);
                *private_key = Some(secret);
                encoded_point.as_bytes().to_vec()
            }
            EcdhKeyExchange::P384 { private_key } => {
                let secret = P384EphemeralSecret::random(&mut OsRng);
                let public_key = P384PublicKey::from(&secret);
                let encoded_point = public_key.to_encoded_point(false);
                *private_key = Some(secret);
                encoded_point.as_bytes().to_vec()
            }
        }
    }

    fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            EcdhKeyExchange::P256 { private_key } => {
                if let Some(secret) = private_key {
                    let encoded_point = p256::EncodedPoint::from_bytes(peer_public_key)
                        .map_err(|_| "Invalid peer public key for P-256".to_string())?;

                    let public_key_opt = P256PublicKey::from_encoded_point(&encoded_point);

                    if public_key_opt.is_some().into() {
                        let public_key = public_key_opt.unwrap();

                        let shared_secret = secret.diffie_hellman(&public_key);

                        Ok(shared_secret.raw_secret_bytes().as_slice().to_vec())
                    } else {
                        Err("Invalid peer public key format for P-256".to_string())
                    }
                } else {
                    Err("Private key not generated".to_string())
                }
            }
            EcdhKeyExchange::P384 { private_key } => {
                if let Some(secret) = private_key {
                    let encoded_point = p384::EncodedPoint::from_bytes(peer_public_key)
                        .map_err(|_| "Invalid peer public key for P-384".to_string())?;

                    let public_key_opt = P384PublicKey::from_encoded_point(&encoded_point);

                    if public_key_opt.is_some().into() {
                        let public_key = public_key_opt.unwrap();

                        let shared_secret = secret.diffie_hellman(&public_key);

                        Ok(shared_secret.raw_secret_bytes().as_slice().to_vec())
                    } else {
                        Err("Invalid peer public key format for P-384".to_string())
                    }
                } else {
                    Err("Private key not generated".to_string())
                }
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

impl KeyExchange for DhKeyExchange {
    fn generate(&mut self) -> Vec<u8> {
        // Determine bit size of prime
        let prime_bits = self.prime.bits() as u64;

        // Generate a random private key smaller than the prime
        let mut rng = rand::thread_rng();
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
        match &self.private_key {
            Some(private_key) => {
                // Compute shared secret as peer_public^private_key mod p
                let shared_secret = peer_public.modpow(private_key, &self.prime);

                // Return shared secret as big-endian bytes
                Ok(shared_secret.to_bytes_be())
            }
            None => Err("DH private key not generated".to_string()),
        }
    }

    fn get_curve_info(&self) -> Option<(CurveType, NamedCurve)> {
        None // DHE doesn't use named curves
    }
}
