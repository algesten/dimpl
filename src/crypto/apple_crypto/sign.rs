//! Signing and key loading implementations for Apple platforms using Security framework.

use std::ffi::c_void;
use std::str;

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use der::{Decode, Encode};
use pkcs8::DecodePrivateKey;
use security_framework::key::{Algorithm, SecKey};
use security_framework_sys::key::{
    kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic, kSecAttrKeyTypeECSECPrimeRandom,
    SecKeyCreateSignature, SecKeyCreateWithData, SecKeyVerifySignature,
};
use spki::ObjectIdentifier;
use x509_cert::Certificate as X509Certificate;

use crate::buffer::Buf;
use crate::crypto::provider::{KeyProvider, SignatureVerifier, SigningKey as SigningKeyTrait};
use crate::message::{CipherSuite, HashAlgorithm, SignatureAlgorithm};

use super::common_crypto::{
    CcSha256Ctx, CcSha512Ctx, CC_SHA256_Final, CC_SHA256_Init, CC_SHA256_Update, CC_SHA384_Final,
    CC_SHA384_Init, CC_SHA384_Update, CC_SHA256_DIGEST_LENGTH, CC_SHA384_DIGEST_LENGTH,
};

/// ECDSA signing key implementation using Security framework.
struct EcdsaSigningKey {
    key: SecKey,
    curve: EcCurve,
}

#[derive(Clone, Copy)]
enum EcCurve {
    P256,
    P384,
}

impl std::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.curve {
            EcCurve::P256 => f.debug_tuple("EcdsaSigningKey::P256").finish(),
            EcCurve::P384 => f.debug_tuple("EcdsaSigningKey::P384").finish(),
        }
    }
}

impl SigningKeyTrait for EcdsaSigningKey {
    fn sign(&mut self, data: &[u8], out: &mut Buf) -> Result<(), String> {
        // Hash the data first (Security framework needs pre-hashed data for digest algorithms)
        let (hash, algorithm) = match self.curve {
            EcCurve::P256 => {
                let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
                unsafe {
                    let mut ctx = std::mem::zeroed::<CcSha256Ctx>();
                    CC_SHA256_Init(&mut ctx);
                    CC_SHA256_Update(&mut ctx, data.as_ptr() as *const c_void, data.len() as u32);
                    CC_SHA256_Final(hash.as_mut_ptr(), &mut ctx);
                }
                (hash.to_vec(), Algorithm::ECDSASignatureDigestX962SHA256)
            }
            EcCurve::P384 => {
                let mut hash = [0u8; CC_SHA384_DIGEST_LENGTH];
                unsafe {
                    let mut ctx = std::mem::zeroed::<CcSha512Ctx>();
                    CC_SHA384_Init(&mut ctx);
                    CC_SHA384_Update(&mut ctx, data.as_ptr() as *const c_void, data.len() as u32);
                    CC_SHA384_Final(hash.as_mut_ptr(), &mut ctx);
                }
                (hash.to_vec(), Algorithm::ECDSASignatureDigestX962SHA384)
            }
        };

        // Sign using Security framework
        let signature = self
            .key
            .create_signature(algorithm, &hash)
            .map_err(|e| format!("Signing failed: {}", e))?;

        out.clear();
        out.extend_from_slice(&signature);
        Ok(())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self.curve {
            EcCurve::P256 => HashAlgorithm::SHA256,
            EcCurve::P384 => HashAlgorithm::SHA384,
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
pub(super) struct AppleCryptoKeyProvider;

impl KeyProvider for AppleCryptoKeyProvider {
    fn load_private_key(&self, key_der: &[u8]) -> Result<Box<dyn SigningKeyTrait>, String> {
        // Try to parse as PKCS#8 to determine the curve
        let curve = determine_curve_from_key(key_der)?;

        let key_size = match curve {
            EcCurve::P256 => 256,
            EcCurve::P384 => 384,
        };

        // Create key attributes for EC private key
        let key_data = CFData::from_buffer(key_der);

        let key_type_key =
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) };
        let key_class_key =
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeyClass) };
        let key_class_value = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate) };

        let key_size_key = unsafe {
            CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeySizeInBits)
        };
        let key_size_value = core_foundation::number::CFNumber::from(key_size as i32);

        let key_type_attr_key =
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeyType) };

        // Build attributes dictionary
        let keys = vec![
            key_class_key.as_CFType(),
            key_type_attr_key.as_CFType(),
            key_size_key.as_CFType(),
        ];
        let values = vec![
            key_class_value.as_CFType(),
            key_type_key.as_CFType(),
            key_size_value.as_CFType(),
        ];

        let attributes =
            CFDictionary::from_CFType_pairs(&keys.iter().zip(values.iter()).collect::<Vec<_>>());

        // Create key from data
        let mut error: core_foundation::base::CFTypeRef = std::ptr::null();
        let key_ref = unsafe {
            SecKeyCreateWithData(
                key_data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            )
        };

        if key_ref.is_null() {
            // Try to check if it's PEM encoded
            if let Ok(pem_str) = str::from_utf8(key_der) {
                if pem_str.contains("-----BEGIN") {
                    if let Ok((_label, doc)) = pkcs8::Document::from_pem(pem_str) {
                        return self.load_private_key(doc.as_bytes());
                    }
                }
            }
            return Err("Failed to load private key".to_string());
        }

        let key = unsafe { SecKey::wrap_under_create_rule(key_ref) };

        Ok(Box::new(EcdsaSigningKey { key, curve }))
    }
}

/// Determine the EC curve from a private key DER encoding
fn determine_curve_from_key(key_der: &[u8]) -> Result<EcCurve, String> {
    // Try PKCS#8 format first
    if let Ok(info) = pkcs8::PrivateKeyInfo::from_der(key_der) {
        if let Some(params) = info.algorithm.parameters {
            if let Ok(oid) = params.decode_as::<ObjectIdentifier>() {
                let p256_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
                let p384_oid = ObjectIdentifier::new_unwrap("1.3.132.0.34");

                if oid == p256_oid {
                    return Ok(EcCurve::P256);
                } else if oid == p384_oid {
                    return Ok(EcCurve::P384);
                }
            }
        }
    }

    // Try SEC1 format
    if let Ok(ec_key) = sec1::EcPrivateKey::try_from(key_der) {
        let private_key_len = ec_key.private_key.len();

        // Check curve from parameters or infer from key length
        if let Some(params) = &ec_key.parameters {
            match params {
                sec1::EcParameters::NamedCurve(oid) => {
                    let p256_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
                    let p384_oid = ObjectIdentifier::new_unwrap("1.3.132.0.34");

                    if *oid == p256_oid {
                        return Ok(EcCurve::P256);
                    } else if *oid == p384_oid {
                        return Ok(EcCurve::P384);
                    }
                }
            }
        }

        // Infer from key length
        if private_key_len == 32 {
            return Ok(EcCurve::P256);
        } else if private_key_len == 48 {
            return Ok(EcCurve::P384);
        }
    }

    // Could not determine curve from key
    Err("Could not determine EC curve from key".to_string())
}

/// Signature verifier implementation.
#[derive(Debug)]
pub(super) struct AppleCryptoSignatureVerifier;

impl SignatureVerifier for AppleCryptoSignatureVerifier {
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

        // Determine key size from public key length or algorithm parameters
        let key_size = if pubkey_bytes.len() == 65 {
            256 // P-256: 1 byte prefix + 32 bytes X + 32 bytes Y
        } else if pubkey_bytes.len() == 97 {
            384 // P-384: 1 byte prefix + 48 bytes X + 48 bytes Y
        } else {
            return Err(format!(
                "Unsupported EC public key size: {} bytes",
                pubkey_bytes.len()
            ));
        };

        // Hash the data
        let (hash, algorithm) = match hash_alg {
            HashAlgorithm::SHA256 => {
                let mut hash = [0u8; CC_SHA256_DIGEST_LENGTH];
                unsafe {
                    let mut ctx = std::mem::zeroed::<CcSha256Ctx>();
                    CC_SHA256_Init(&mut ctx);
                    CC_SHA256_Update(&mut ctx, data.as_ptr() as *const c_void, data.len() as u32);
                    CC_SHA256_Final(hash.as_mut_ptr(), &mut ctx);
                }
                (hash.to_vec(), Algorithm::ECDSASignatureDigestX962SHA256)
            }
            HashAlgorithm::SHA384 => {
                let mut hash = [0u8; CC_SHA384_DIGEST_LENGTH];
                unsafe {
                    let mut ctx = std::mem::zeroed::<CcSha512Ctx>();
                    CC_SHA384_Init(&mut ctx);
                    CC_SHA384_Update(&mut ctx, data.as_ptr() as *const c_void, data.len() as u32);
                    CC_SHA384_Final(hash.as_mut_ptr(), &mut ctx);
                }
                (hash.to_vec(), Algorithm::ECDSASignatureDigestX962SHA384)
            }
            _ => {
                return Err(format!(
                    "Unsupported hash algorithm for ECDSA: {:?}",
                    hash_alg
                ))
            }
        };

        // Create public key from data
        let key_data = CFData::from_buffer(pubkey_bytes);

        let key_type_key =
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) };
        let key_class_key =
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeyClass) };
        let key_class_value = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyClassPublic) };

        let key_size_key = unsafe {
            CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeySizeInBits)
        };
        let key_size_value = core_foundation::number::CFNumber::from(key_size as i32);

        let key_type_attr_key =
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeyType) };

        // Build attributes dictionary
        let keys = vec![
            key_class_key.as_CFType(),
            key_type_attr_key.as_CFType(),
            key_size_key.as_CFType(),
        ];
        let values = vec![
            key_class_value.as_CFType(),
            key_type_key.as_CFType(),
            key_size_value.as_CFType(),
        ];

        let attributes =
            CFDictionary::from_CFType_pairs(&keys.iter().zip(values.iter()).collect::<Vec<_>>());

        // Create key from data
        let mut error: core_foundation::base::CFTypeRef = std::ptr::null();
        let key_ref = unsafe {
            SecKeyCreateWithData(
                key_data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            )
        };

        if key_ref.is_null() {
            return Err("Failed to create public key for verification".to_string());
        }

        let public_key = unsafe { SecKey::wrap_under_create_rule(key_ref) };

        // Verify the signature
        let hash_data = CFData::from_buffer(&hash);
        let signature_data = CFData::from_buffer(signature);

        let mut error: core_foundation::base::CFTypeRef = std::ptr::null();
        let result = unsafe {
            SecKeyVerifySignature(
                public_key.as_concrete_TypeRef(),
                algorithm.into(),
                hash_data.as_concrete_TypeRef(),
                signature_data.as_concrete_TypeRef(),
                &mut error,
            )
        };

        if result == 0 {
            return Err(format!("ECDSA signature verification failed for {:?}", hash_alg));
        }

        Ok(())
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: AppleCryptoKeyProvider = AppleCryptoKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: AppleCryptoSignatureVerifier = AppleCryptoSignatureVerifier;
