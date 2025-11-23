//! Key exchange group implementations using aws-lc-rs.

use aws_lc_rs::agreement::{agree_ephemeral, EphemeralPrivateKey};
use aws_lc_rs::agreement::{UnparsedPublicKey, ECDH_P256, ECDH_P384};

use crate::buffer::Buf;
use crate::crypto::provider::{ActiveKeyExchange, SupportedKxGroup};
use crate::message::NamedGroup;

/// ECDHE key exchange implementation.
struct EcdhKeyExchange {
    group: NamedGroup,
    private_key: EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl EcdhKeyExchange {
    fn new(group: NamedGroup) -> Result<Self, String> {
        let algorithm = match group {
            NamedGroup::Secp256r1 => &ECDH_P256,
            NamedGroup::Secp384r1 => &ECDH_P384,
            _ => return Err("Unsupported group".to_string()),
        };

        let rng = aws_lc_rs::rand::SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(algorithm, &rng)
            .map_err(|_| "Failed to generate ephemeral key".to_string())?;

        let public_key = private_key
            .compute_public_key()
            .map(|pk| pk.as_ref().to_vec())
            .map_err(|_| "Failed to compute public key".to_string())?;

        Ok(EcdhKeyExchange {
            group,
            private_key,
            public_key,
        })
    }

    fn algorithm(&self) -> &'static aws_lc_rs::agreement::Algorithm {
        match self.group {
            NamedGroup::Secp256r1 => &ECDH_P256,
            NamedGroup::Secp384r1 => &ECDH_P384,
            _ => unreachable!("Unsupported group"),
        }
    }
}

impl ActiveKeyExchange for EcdhKeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn complete(self: Box<Self>, peer_pub: &[u8]) -> Result<Buf, String> {
        let algorithm = self.algorithm();
        let peer_key = UnparsedPublicKey::new(algorithm, peer_pub);

        agree_ephemeral(
            self.private_key,
            peer_key,
            "ECDH agreement failed",
            |secret| {
                let mut buf = Buf::new();
                buf.extend_from_slice(secret);
                Ok(buf)
            },
        )
        .map_err(|e| e.to_string())
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

/// P-256 (secp256r1) key exchange group.
#[derive(Debug)]
struct P256;

impl SupportedKxGroup for P256 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp256r1
    }

    fn start_exchange(&self) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp256r1)?))
    }
}

/// P-384 (secp384r1) key exchange group.
#[derive(Debug)]
struct P384;

impl SupportedKxGroup for P384 {
    fn name(&self) -> NamedGroup {
        NamedGroup::Secp384r1
    }

    fn start_exchange(&self) -> Result<Box<dyn ActiveKeyExchange>, String> {
        Ok(Box::new(EcdhKeyExchange::new(NamedGroup::Secp384r1)?))
    }
}

/// Static instances of supported key exchange groups.
static KX_GROUP_P256: P256 = P256;
static KX_GROUP_P384: P384 = P384;

/// All supported key exchange groups.
pub(super) static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&KX_GROUP_P256, &KX_GROUP_P384];
