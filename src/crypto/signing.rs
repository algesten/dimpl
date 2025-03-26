use crate::message::{HashAlgorithm, SignatureAlgorithm, SignatureAndHashAlgorithm};

use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use pkcs8::DecodePrivateKey;
use rand::thread_rng;
use rsa::{pkcs8, RsaPrivateKey};
use sha2::{Sha256, Sha384};
use signature::{RandomizedSigner, SignatureEncoding, Signer};

/// Sign data using RSA with the provided private key and hash algorithm
pub fn sign_rsa(
    private_key_data: &[u8],
    data: &[u8],
    hash_alg: HashAlgorithm,
) -> Result<Vec<u8>, String> {
    // Try to decode the private key data in PKCS#8 format
    // In a real implementation, you might need to handle different key formats
    let private_key = match RsaPrivateKey::from_pkcs8_der(private_key_data) {
        Ok(key) => key,
        Err(_) => {
            // Try PEM format if DER fails
            RsaPrivateKey::from_pkcs8_pem(
                std::str::from_utf8(private_key_data)
                    .map_err(|e| format!("Invalid UTF-8 in private key: {}", e))?,
            )
            .map_err(|e| format!("Failed to parse RSA private key: {}", e))?
        }
    };

    // Select the appropriate padding scheme based on the hash algorithm
    match hash_alg {
        HashAlgorithm::SHA256 => {
            use rsa::pkcs1v15::{Signature, SigningKey};

            let signing_key = SigningKey::<Sha256>::new_with_prefix(private_key);
            let mut rng = rand::thread_rng();
            let signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(signature.to_bytes().to_vec())
        }
        HashAlgorithm::SHA384 => {
            use rsa::pkcs1v15::{Signature, SigningKey};

            let signing_key = SigningKey::<Sha384>::new_with_prefix(private_key);
            let mut rng = rand::thread_rng();
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
pub fn sign_ecdsa(private_key_data: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    // Try to decode as P-256 key
    if let Ok(signing_key) = P256SigningKey::from_pkcs8_der(private_key_data) {
        // Sign with P-256
        let signature: P256Signature = signing_key.sign(data);
        return Ok(signature.to_der().to_vec());
    }

    // Try to decode as P-384 key
    if let Ok(signing_key) = P384SigningKey::from_pkcs8_der(private_key_data) {
        // Sign with P-384
        let signature: P384Signature = signing_key.sign(data);
        return Ok(signature.to_der().to_vec());
    }

    // If we can't determine the curve or load the key, try PEM format
    if let Ok(key_pem) = std::str::from_utf8(private_key_data) {
        if let Ok(signing_key) = P256SigningKey::from_pkcs8_pem(key_pem) {
            // Sign with P-256
            let signature: P256Signature = signing_key.sign(data);
            return Ok(signature.to_der().to_vec());
        }

        if let Ok(signing_key) = P384SigningKey::from_pkcs8_pem(key_pem) {
            // Sign with P-384
            let signature: P384Signature = signing_key.sign(data);
            return Ok(signature.to_der().to_vec());
        }
    }

    // If we couldn't load the key in any recognized format
    Err("Failed to parse ECDSA private key or unsupported curve".to_string())
}

/// Sign data using the provided private key, signature algorithm, and hash algorithm
pub fn sign_data(
    private_key_data: &[u8],
    data: &[u8],
    sig_alg: SignatureAndHashAlgorithm,
) -> Result<Vec<u8>, String> {
    match sig_alg.signature {
        SignatureAlgorithm::RSA => sign_rsa(private_key_data, data, sig_alg.hash),
        SignatureAlgorithm::ECDSA => sign_ecdsa(private_key_data, data),
        _ => Err(format!(
            "Unsupported signature algorithm: {:?}",
            sig_alg.signature
        )),
    }
}
