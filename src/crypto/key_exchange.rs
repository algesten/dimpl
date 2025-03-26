use crate::message::{CurveType, NamedCurve};
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::{EncodedPoint, ToEncodedPoint};
use p256::{
    ecdh::{EphemeralSecret as P256EphemeralSecret, SharedSecret as P256SharedSecret},
    PublicKey as P256PublicKey,
};
use p384::{
    ecdh::{EphemeralSecret as P384EphemeralSecret, SharedSecret as P384SharedSecret},
    PublicKey as P384PublicKey,
};
use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

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

/// DHE Key Exchange - we'll implement a simple version
pub struct DhKeyExchange {
    // For a real implementation, we would use a proper DH library
    // This is a simplified version for example purposes
    private_key: Option<Vec<u8>>,
    prime: Vec<u8>,
    generator: Vec<u8>,
}

impl DhKeyExchange {
    pub fn new(prime: Vec<u8>, generator: Vec<u8>) -> Self {
        DhKeyExchange {
            private_key: None,
            prime,
            generator,
        }
    }
}

impl KeyExchange for DhKeyExchange {
    fn generate(&mut self) -> Vec<u8> {
        // Generate a random private key
        let mut private_key = [0u8; 32];
        OsRng.fill(&mut private_key);
        self.private_key = Some(private_key.to_vec());

        // For a real implementation, we would compute g^private_key mod p
        // For now, we'll just return a dummy public key
        vec![1, 2, 3, 4]
    }

    fn compute_shared_secret(&self, _peer_public_key: &[u8]) -> Result<Vec<u8>, String> {
        // In a real implementation, we would compute (peer_public_key)^private_key mod p
        // For now, return a dummy shared secret
        Ok(vec![0x12, 0x34, 0x56, 0x78])
    }
}
