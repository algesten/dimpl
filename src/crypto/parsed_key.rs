//! Private key parsing and handling for DTLS.

use std::str;

use aws_lc_rs::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING};
use der::Encode;

use crate::message::{CipherSuite, HashAlgorithm, SignatureAlgorithm};

/// Parsed private key supported by this crate.
pub struct ParsedKey {
    key_pair: EcdsaKeyPair,
    signing_algorithm: &'static EcdsaSigningAlgorithm,
}

impl ParsedKey {
    /// Get the signature algorithm type for this key
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    /// Check if this key is compatible with a given cipher suite
    pub fn is_compatible(&self, cipher_suite: CipherSuite) -> bool {
        matches!(
            cipher_suite,
            CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 | CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256
        )
    }

    /// Get a reference to the key pair
    pub fn key_pair(&self) -> &EcdsaKeyPair {
        &self.key_pair
    }

    /// Try to parse a private key from raw bytes
    pub fn try_parse_key(key_data: &[u8]) -> Result<Self, String> {
        // Try PKCS#8 DER format first (most common)
        if let Ok(key_pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key_data) {
            return Ok(ParsedKey {
                key_pair,
                signing_algorithm: &ECDSA_P256_SHA256_ASN1_SIGNING,
            });
        }
        if let Ok(key_pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, key_data) {
            return Ok(ParsedKey {
                key_pair,
                signing_algorithm: &ECDSA_P384_SHA384_ASN1_SIGNING,
            });
        }

        // Try parsing as SEC1 DER format (OpenSSL EC private key format)
        if let Ok(ec_key) = sec1::EcPrivateKey::try_from(key_data) {
            // SEC1 format detected - need to wrap in PKCS#8 for aws-lc-rs
            // Determine curve from key size or parameters
            let private_key_len = ec_key.private_key.len();

            // Get curve OID from parameters if present, otherwise infer from key length
            let curve_oid = if let Some(params) = &ec_key.parameters {
                match params {
                    sec1::EcParameters::NamedCurve(oid) => Some(*oid),
                }
            } else if private_key_len == 32 {
                // P-256
                Some(spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))
            } else if private_key_len == 48 {
                // P-384
                Some(spki::ObjectIdentifier::new_unwrap("1.3.132.0.34"))
            } else {
                None
            };

            if let Some(curve_oid) = curve_oid {
                // Build PKCS#8 structure wrapping the SEC1 data
                let ec_alg_oid = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"); // ecPublicKey

                // Encode curve OID as parameters
                let curve_params_der = curve_oid
                    .to_der()
                    .map_err(|_| "Failed to encode curve OID".to_string())?;
                let curve_params_any = der::asn1::AnyRef::try_from(curve_params_der.as_slice())
                    .map_err(|_| "Failed to create AnyRef".to_string())?;

                let algorithm = spki::AlgorithmIdentifierRef {
                    oid: ec_alg_oid,
                    parameters: Some(curve_params_any),
                };

                // For PKCS#8 with aws-lc-rs, we wrap the SEC1 key as-is
                // The SEC1 structure already contains the public key, so don't duplicate it
                let pkcs8 = pkcs8::PrivateKeyInfo {
                    algorithm,
                    private_key: key_data, // SEC1 DER bytes will be wrapped in OCTET STRING
                    public_key: None,      // Already in SEC1 structure
                };

                let pkcs8_der = pkcs8
                    .to_der()
                    .map_err(|_| "Failed to encode PKCS#8".to_string())?;

                // Try to parse with aws-lc-rs
                let p256_curve = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
                if curve_oid == p256_curve {
                    if let Ok(key_pair) =
                        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_der)
                    {
                        return Ok(ParsedKey {
                            key_pair,
                            signing_algorithm: &ECDSA_P256_SHA256_ASN1_SIGNING,
                        });
                    }
                }

                let p384_curve = spki::ObjectIdentifier::new_unwrap("1.3.132.0.34");
                if curve_oid == p384_curve {
                    if let Ok(key_pair) =
                        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &pkcs8_der)
                    {
                        return Ok(ParsedKey {
                            key_pair,
                            signing_algorithm: &ECDSA_P384_SHA384_ASN1_SIGNING,
                        });
                    }
                }
            }
        }

        // Check if it's a PEM encoded key
        if let Ok(pem_str) = str::from_utf8(key_data) {
            // PEM keys start with "-----BEGIN"
            if pem_str.contains("-----BEGIN") {
                // Try to decode the PEM using the pkcs8 crate's pem support
                if let Ok((_label, doc)) = pkcs8::Document::from_pem(pem_str) {
                    // Recursively try to parse the DER bytes
                    return Self::try_parse_key(doc.as_bytes());
                }
            }
        }

        Err("Failed to parse private key in any supported format".to_string())
    }

    pub(crate) fn default_hash_algorithm(&self) -> HashAlgorithm {
        // Determine hash algorithm from the signing algorithm
        if self.signing_algorithm == &ECDSA_P256_SHA256_ASN1_SIGNING {
            HashAlgorithm::SHA256
        } else if self.signing_algorithm == &ECDSA_P384_SHA384_ASN1_SIGNING {
            HashAlgorithm::SHA384
        } else {
            panic!("Unsupported signing algorithm")
        }
    }
}
