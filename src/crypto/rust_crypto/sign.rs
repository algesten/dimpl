//! Signing and key loading implementations using RustCrypto.

use std::str;

use der::{Decode, Encode};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::NistP256;
use p384::NistP384;
use pkcs8::DecodePrivateKey;
use spki::ObjectIdentifier;
use x509_cert::Certificate as X509Certificate;

use super::super::{check_verify_scheme, KeyProvider, SignatureVerifier, SigningKey as SigningKeyTrait};
use crate::buffer::Buf;
use crate::types::{HashAlgorithm, NamedGroup, SignatureAlgorithm};

/// ECDSA signing key implementation.
enum EcdsaSigningKey {
    P256(SigningKey<NistP256>),
    P384(SigningKey<NistP384>),
}

impl std::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcdsaSigningKey::P256(_) => f.debug_tuple("EcdsaSigningKey::P256").finish(),
            EcdsaSigningKey::P384(_) => f.debug_tuple("EcdsaSigningKey::P384").finish(),
        }
    }
}

impl SigningKeyTrait for EcdsaSigningKey {
    fn sign(&mut self, data: &[u8], out: &mut Buf) -> Result<(), String> {
        match self {
            EcdsaSigningKey::P256(key) => {
                use ecdsa::signature::hazmat::PrehashSigner;
                use sha2::{Digest, Sha256};

                // Hash the data before signing (PrehashSigner expects a hash digest)
                let mut hasher = Sha256::new();
                hasher.update(data);
                let hash = hasher.finalize();

                let signature: Signature<NistP256> = key
                    .sign_prehash(&hash)
                    .map_err(|_| "Signing failed".to_string())?;
                let sig_der = signature.to_der();
                let sig_bytes = sig_der.as_bytes();
                out.clear();
                out.extend_from_slice(sig_bytes);
                Ok(())
            }
            EcdsaSigningKey::P384(key) => {
                use ecdsa::signature::hazmat::PrehashSigner;
                use sha2::{Digest, Sha384};

                // Hash the data before signing (PrehashSigner expects a hash digest)
                let mut hasher = Sha384::new();
                hasher.update(data);
                let hash = hasher.finalize();

                let signature: Signature<NistP384> = key
                    .sign_prehash(&hash)
                    .map_err(|_| "Signing failed".to_string())?;
                let sig_der = signature.to_der();
                let sig_bytes = sig_der.as_bytes();
                out.clear();
                out.extend_from_slice(sig_bytes);
                Ok(())
            }
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            EcdsaSigningKey::P256(_) => HashAlgorithm::SHA256,
            EcdsaSigningKey::P384(_) => HashAlgorithm::SHA384,
        }
    }
}

/// Key provider implementation.
#[derive(Debug)]
pub(super) struct RustCryptoKeyProvider;

impl KeyProvider for RustCryptoKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, String> {
        // Try PKCS#8 DER format first (most common)
        if let Ok(key) = SigningKey::<NistP256>::from_pkcs8_der(key_der) {
            return Ok(Box::new(EcdsaSigningKey::P256(key)));
        }
        if let Ok(key) = SigningKey::<NistP384>::from_pkcs8_der(key_der) {
            return Ok(Box::new(EcdsaSigningKey::P384(key)));
        }

        // Try parsing as SEC1 DER format (OpenSSL EC private key format)
        if let Ok(ec_key) = sec1::EcPrivateKey::try_from(key_der) {
            let private_key_len = ec_key.private_key.len();

            let curve_oid = if let Some(params) = &ec_key.parameters {
                match params {
                    sec1::EcParameters::NamedCurve(oid) => Some(*oid),
                }
            } else if private_key_len == 32 {
                Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")) // P-256
            } else if private_key_len == 48 {
                Some(ObjectIdentifier::new_unwrap("1.3.132.0.34")) // P-384
            } else {
                None
            };

            if let Some(curve_oid) = curve_oid {
                let ec_alg_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
                let curve_params_der = curve_oid
                    .to_der()
                    .map_err(|_| "Failed to encode curve OID".to_string())?;
                let curve_params_any = der::asn1::AnyRef::try_from(curve_params_der.as_slice())
                    .map_err(|_| "Failed to create AnyRef".to_string())?;

                let algorithm = spki::AlgorithmIdentifierRef {
                    oid: ec_alg_oid,
                    parameters: Some(curve_params_any),
                };

                let pkcs8 = pkcs8::PrivateKeyInfo {
                    algorithm,
                    private_key: key_der,
                    public_key: None,
                };

                let pkcs8_der = pkcs8
                    .to_der()
                    .map_err(|_| "Failed to encode PKCS#8".to_string())?;

                let p256_curve = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
                if curve_oid == p256_curve {
                    if let Ok(key) = SigningKey::<NistP256>::from_pkcs8_der(pkcs8_der.as_slice()) {
                        return Ok(Box::new(EcdsaSigningKey::P256(key)));
                    }
                }

                let p384_curve = ObjectIdentifier::new_unwrap("1.3.132.0.34");
                if curve_oid == p384_curve {
                    if let Ok(key) = SigningKey::<NistP384>::from_pkcs8_der(pkcs8_der.as_slice()) {
                        return Ok(Box::new(EcdsaSigningKey::P384(key)));
                    }
                }
            }
        }

        // Check if it's a PEM encoded key
        if let Ok(pem_str) = str::from_utf8(key_der) {
            if pem_str.contains("-----BEGIN") {
                if let Ok((_label, doc)) = pkcs8::Document::from_pem(pem_str) {
                    return self.load_private_key(doc.as_bytes());
                }
            }
        }

        Err("Failed to parse private key in any supported format".to_string())
    }
}

/// Signature verifier implementation.
#[derive(Debug)]
pub(super) struct RustCryptoSignatureVerifier;

impl SignatureVerifier for RustCryptoSignatureVerifier {
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlgorithm,
        sig_alg: SignatureAlgorithm,
    ) -> Result<(), String> {
        if sig_alg != SignatureAlgorithm::ECDSA {
            return Err(format!("Unsupported signature algorithm: {:?}", sig_alg));
        }

        let cert = X509Certificate::from_der(cert_der)
            .map_err(|e| format!("Failed to parse certificate: {e}"))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;

        const OID_EC_PUBLIC_KEY: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

        if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
            return Err(format!(
                "Unsupported public key algorithm: {}",
                spki.algorithm.oid
            ));
        }

        let pubkey_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| "Invalid EC subject_public_key bitstring".to_string())?;

        let curve_oid: ObjectIdentifier = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or("Missing EC curve parameter in certificate")?
            .decode_as()
            .map_err(|_| "Invalid EC curve parameter in certificate".to_string())?;

        const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

        let group = match curve_oid {
            OID_P256 => NamedGroup::Secp256r1,
            OID_P384 => NamedGroup::Secp384r1,
            _ => return Err(format!("Unsupported EC curve: {}", curve_oid)),
        };

        check_verify_scheme(sig_alg, hash_alg, group)?;

        use ecdsa::signature::hazmat::PrehashVerifier;
        use sha2::Digest;

        // Hash the data before verification (PrehashVerifier expects a hash digest)
        let hash: Box<[u8]> = match hash_alg {
            HashAlgorithm::SHA256 => Box::from(sha2::Sha256::digest(data).as_slice()),
            HashAlgorithm::SHA384 => Box::from(sha2::Sha384::digest(data).as_slice()),
            // unreachable: check_verify_scheme already validated
            _ => unreachable!(),
        };

        match group {
            NamedGroup::Secp256r1 => {
                let verifying_key = VerifyingKey::<NistP256>::from_sec1_bytes(pubkey_bytes)
                    .map_err(|_| "Invalid P-256 public key".to_string())?;
                let sig = Signature::<NistP256>::from_der(signature)
                    .map_err(|_| "Invalid signature format".to_string())?;
                verifying_key
                    .verify_prehash(&hash, &sig)
                    .map_err(|_| format!("ECDSA signature verification failed for {:?}", hash_alg))
            }
            NamedGroup::Secp384r1 => {
                let verifying_key = VerifyingKey::<NistP384>::from_sec1_bytes(pubkey_bytes)
                    .map_err(|_| "Invalid P-384 public key".to_string())?;
                let sig = Signature::<NistP384>::from_der(signature)
                    .map_err(|_| "Invalid signature format".to_string())?;
                verifying_key
                    .verify_prehash(&hash, &sig)
                    .map_err(|_| format!("ECDSA signature verification failed for {:?}", hash_alg))
            }
            // unreachable: OID match above only produces Secp256r1/Secp384r1
            _ => unreachable!(),
        }
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: RustCryptoKeyProvider = RustCryptoKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: RustCryptoSignatureVerifier = RustCryptoSignatureVerifier;
