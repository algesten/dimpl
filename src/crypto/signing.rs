use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use rand::thread_rng;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::RsaPrivateKey;
use sha2::{Sha256, Sha384};
use signature::{RandomizedSigner, SignatureEncoding, Signer};

use crate::crypto::ParsedKey;
use crate::message::HashAlgorithm;

/// Sign data using RSA with the provided private key and hash algorithm
pub fn sign_rsa(
    private_key: &RsaPrivateKey,
    data: &[u8],
    hash_alg: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    // Select the appropriate padding scheme based on the hash algorithm
    match hash_alg {
        HashAlgorithm::SHA256 => {
            let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key.clone());
            let mut rng = thread_rng();
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_bytes().to_vec())
        }
        HashAlgorithm::SHA384 => {
            let signing_key = RsaPkcs1v15SigningKey::<Sha384>::new(private_key.clone());
            let mut rng = thread_rng();
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_bytes().to_vec())
        }
        _ => Err(format!(
            "Unsupported hash algorithm for RSA: {:?}",
            hash_alg
        )),
    }
}

/// Sign data using ECDSA with the provided private key
pub fn sign_ecdsa_p256(signing_key: &P256SigningKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let signature: P256Signature = signing_key.sign(data);
    Ok(signature.to_der().to_vec())
}

pub fn sign_ecdsa_p384(signing_key: &P384SigningKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let signature: P384Signature = signing_key.sign(data);
    Ok(signature.to_der().to_vec())
}

/// Sign data using the provided parsed key and hash algorithm
pub fn sign_data(
    parsed_key: &ParsedKey,
    data: &[u8],
    hash_alg: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    match parsed_key {
        ParsedKey::Rsa(private_key) => sign_rsa(private_key, data, hash_alg),
        ParsedKey::P256(signing_key) => sign_ecdsa_p256(signing_key, data),
        ParsedKey::P384(signing_key) => sign_ecdsa_p384(signing_key, data),
    }
}
