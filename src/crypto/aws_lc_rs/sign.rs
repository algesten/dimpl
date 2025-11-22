//! Signing and key loading implementations using aws-lc-rs.

use std::str;
use std::sync::Arc;

use aws_lc_rs::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, UnparsedPublicKey};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING};
use aws_lc_rs::signature::{ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING};
use der::{Decode, Encode};
use spki::ObjectIdentifier;
use x509_cert::Certificate as X509Certificate;

use crate::crypto::provider::{KeyProvider, SignatureVerifier, SigningKey};
use crate::message::{CipherSuite, HashAlgorithm, SignatureAlgorithm};

/// ECDSA signing key implementation.
#[derive(Debug)]
struct EcdsaSigningKey {
    key_pair: EcdsaKeyPair,
    signing_algorithm: &'static EcdsaSigningAlgorithm,
}

impl SigningKey for EcdsaSigningKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, data)
            .map_err(|_| "Signing failed".to_string())?;
        Ok(signature.as_ref().to_vec())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        if self.signing_algorithm == &ECDSA_P256_SHA256_ASN1_SIGNING {
            HashAlgorithm::SHA256
        } else if self.signing_algorithm == &ECDSA_P384_SHA384_ASN1_SIGNING {
            HashAlgorithm::SHA384
        } else {
            panic!("Unsupported signing algorithm")
        }
    }

    fn is_compatible(&self, cipher_suite: CipherSuite) -> bool {
        matches!(
            cipher_suite,
            CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 | CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
        )
    }
}

/// Key provider implementation.
#[derive(Debug)]
pub(super) struct AwsLcKeyProvider;

impl KeyProvider for AwsLcKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Arc<dyn SigningKey>, String> {
        // Try PKCS#8 DER format first (most common)
        if let Ok(key_pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_der) {
            return Ok(Arc::new(EcdsaSigningKey {
                key_pair,
                signing_algorithm: &ECDSA_P256_SHA256_ASN1_SIGNING,
            }));
        }
        if let Ok(key_pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, key_der) {
            return Ok(Arc::new(EcdsaSigningKey {
                key_pair,
                signing_algorithm: &ECDSA_P384_SHA384_ASN1_SIGNING,
            }));
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
                    if let Ok(key_pair) =
                        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der)
                    {
                        return Ok(Arc::new(EcdsaSigningKey {
                            key_pair,
                            signing_algorithm: &ECDSA_P256_SHA256_ASN1_SIGNING,
                        }));
                    }
                }

                let p384_curve = ObjectIdentifier::new_unwrap("1.3.132.0.34");
                if curve_oid == p384_curve {
                    if let Ok(key_pair) =
                        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &pkcs8_der)
                    {
                        return Ok(Arc::new(EcdsaSigningKey {
                            key_pair,
                            signing_algorithm: &ECDSA_P384_SHA384_ASN1_SIGNING,
                        }));
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
pub(super) struct AwsLcSignatureVerifier;

impl SignatureVerifier for AwsLcSignatureVerifier {
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

        let algorithm = match hash_alg {
            HashAlgorithm::SHA256 => &ECDSA_P256_SHA256_ASN1,
            HashAlgorithm::SHA384 => &ECDSA_P384_SHA384_ASN1,
            _ => {
                return Err(format!(
                    "Unsupported hash algorithm for ECDSA: {:?}",
                    hash_alg
                ));
            }
        };

        let public_key = UnparsedPublicKey::new(algorithm, pubkey_bytes);
        public_key
            .verify(data, signature)
            .map_err(|_| format!("ECDSA signature verification failed for {:?}", hash_alg))
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: AwsLcKeyProvider = AwsLcKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: AwsLcSignatureVerifier = AwsLcSignatureVerifier;
