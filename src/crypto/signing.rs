use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use signature::{SignatureEncoding, Signer};

use crate::crypto::ParsedKey;

/// Sign data using ECDSA with the provided private key
pub fn sign_ecdsa_p256(signing_key: &P256SigningKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let signature: P256Signature = signing_key.sign(data);

    // Use DER format for TLS 1.2 compatibility with OpenSSL
    let sig_bytes = signature.to_der().to_vec();
    Ok(sig_bytes)
}

pub fn sign_ecdsa_p384(signing_key: &P384SigningKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let signature: P384Signature = signing_key.sign(data);

    // Use DER format for TLS 1.2 compatibility with OpenSSL
    let sig_bytes = signature.to_der().to_vec();
    Ok(sig_bytes)
}

/// Sign data using the provided parsed key and hash algorithm
pub fn sign_data(parsed_key: &ParsedKey, data: &[u8]) -> Result<Vec<u8>, String> {
    match parsed_key {
        ParsedKey::P256(signing_key) => sign_ecdsa_p256(signing_key, data),
        ParsedKey::P384(signing_key) => sign_ecdsa_p384(signing_key, data),
    }
}
