//! Key exchange group implementations using RustCrypto.

use p256::{ecdh::EphemeralSecret, PublicKey as P256PublicKey};
use p384::{ecdh::EphemeralSecret as P384EphemeralSecret, PublicKey as P384PublicKey};

use crate::buffer::Buf;
use crate::crypto::provider::{ActiveKeyExchange, SupportedKxGroup};
use crate::types::NamedGroup;

/// ECDHE key exchange implementation.
enum EcdhKeyExchange {
    P256 {
        secret: EphemeralSecret,
        public_key: Buf,
    },
    P384 {
        secret: P384EphemeralSecret,
        public_key: Buf,
    },
}

impl std::fmt::Debug for EcdhKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcdhKeyExchange::P256 { public_key, .. } => f
                .debug_struct("EcdhKeyExchange::P256")
                .field("public_key_len", &public_key.len())
                .finish_non_exhaustive(),
            EcdhKeyExchange::P384 { public_key, .. } => f
                .debug_struct("EcdhKeyExchange::P384")
                .field("public_key_len", &public_key.len())
                .finish_non_exhaustive(),
        }
    }
}

impl EcdhKeyExchange {
    fn new(group: NamedGroup, mut buf: Buf) -> Result<Self, String> {
        match group {
            NamedGroup::Secp256r1 => {
                use rand_core::OsRng;
                let secret = EphemeralSecret::random(&mut OsRng);
                let public_key_obj = P256PublicKey::from(&secret);
                let public_key_bytes = public_key_obj.to_sec1_bytes();
                buf.clear();
                buf.extend_from_slice(&public_key_bytes);
                Ok(EcdhKeyExchange::P256 {
                    secret,
                    public_key: buf,
                })
            }
            NamedGroup::Secp384r1 => {
                use rand_core::OsRng;
                let secret = P384EphemeralSecret::random(&mut OsRng);
                let public_key_obj = P384PublicKey::from(&secret);
                let public_key_bytes = public_key_obj.to_sec1_bytes();
                buf.clear();
                buf.extend_from_slice(&public_key_bytes);
                Ok(EcdhKeyExchange::P384 {
                    secret,
                    public_key: buf,
                })
            }
            _ => Err("Unsupported group".to_string()),
        }
    }
}

impl ActiveKeyExchange for EcdhKeyExchange {
    fn pub_key(&self) -> &[u8] {
        match self {
            EcdhKeyExchange::P256 { public_key, .. } => public_key,
            EcdhKeyExchange::P384 { public_key, .. } => public_key,
        }
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        match *self {
            EcdhKeyExchange::P256 { secret, .. } => {
                let peer_key = P256PublicKey::from_sec1_bytes(peer_pub)
                    .map_err(|_| "Invalid P-256 public key".to_string())?;
                let shared_secret = secret.diffie_hellman(&peer_key);
                out.clear();
                out.extend_from_slice(shared_secret.raw_secret_bytes().as_slice());
                Ok(())
            }
            EcdhKeyExchange::P384 { secret, .. } => {
                let peer_key = P384PublicKey::from_sec1_bytes(peer_pub)
                    .map_err(|_| "Invalid P-384 public key".to_string())?;
                let shared_secret = secret.diffie_hellman(&peer_key);
                out.clear();
                out.extend_from_slice(shared_secret.raw_secret_bytes().as_slice());
                Ok(())
            }
        }
    }

    fn group(&self) -> NamedGroup {
        match self {
            EcdhKeyExchange::P256 { .. } => NamedGroup::Secp256r1,
            EcdhKeyExchange::P384 { .. } => NamedGroup::Secp384r1,
        }
    }
}

/// P-256 (secp256r1) key exchange group.
#[derive(Debug)]
struct P256;

impl SupportedKxGroup for P256 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp256r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp256r1, buf)?))
    }
}

/// P-384 (secp384r1) key exchange group.
#[derive(Debug)]
struct P384;

impl SupportedKxGroup for P384 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp384r1
    }

    fn start_exchange(&self, buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp384r1, buf)?))
    }
}

/// Static instances of supported key exchange groups.
static KX_GROUP_P256: P256 = P256;
static KX_GROUP_P384: P384 = P384;

/// All supported key exchange groups.
pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&KX_GROUP_P256, &KX_GROUP_P384];
