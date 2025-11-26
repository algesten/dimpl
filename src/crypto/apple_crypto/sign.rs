//! Signing and key loading implementations for Apple platforms using Security framework.

use std::ffi::c_void;
use std::str;

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use der::Decode;
use security_framework::key::{Algorithm, SecKey};
use spki::ObjectIdentifier;
use x509_cert::Certificate as X509Certificate;

use crate::buffer::Buf;
use crate::crypto::provider::{KeyProvider, SignatureVerifier, SigningKey as SigningKeyTrait};
use crate::message::{CipherSuite, HashAlgorithm, SignatureAlgorithm};

use super::common_crypto::{
    CcSha256Ctx, CcSha512Ctx, CC_SHA256_Final, CC_SHA256_Init, CC_SHA256_Update, CC_SHA384_Final,
    CC_SHA384_Init, CC_SHA384_Update, CC_SHA256_DIGEST_LENGTH, CC_SHA384_DIGEST_LENGTH,
};

// Security framework FFI bindings
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecAttrKeyType: core_foundation::string::CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: core_foundation::string::CFStringRef;
    static kSecAttrKeyClass: core_foundation::string::CFStringRef;
    static kSecAttrKeyClassPrivate: core_foundation::string::CFStringRef;
    static kSecAttrKeyClassPublic: core_foundation::string::CFStringRef;
    static kSecAttrKeySizeInBits: core_foundation::string::CFStringRef;

    fn SecKeyCreateWithData(
        key_data: *const c_void,
        attributes: *const c_void,
        error: *mut *const c_void,
    ) -> *mut c_void;
}

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

        // Build attributes dictionary using CFMutableDictionary
        let attributes = unsafe {
            let dict = CFMutableDictionary::new();

            let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
            let key_type_value = CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom);
            dict.set(key_type_key, key_type_value);

            let key_class_key = CFString::wrap_under_get_rule(kSecAttrKeyClass);
            let key_class_value = CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate);
            dict.set(key_class_key, key_class_value);

            let key_size_key = CFString::wrap_under_get_rule(kSecAttrKeySizeInBits);
            let key_size_value = CFNumber::from(key_size as i32);
            dict.set(key_size_key, key_size_value);

            dict
        };

        // Create key from data
        let mut error: *const c_void = std::ptr::null();
        let key_ref = unsafe {
            SecKeyCreateWithData(
                key_data.as_concrete_TypeRef() as *const _,
                attributes.as_concrete_TypeRef() as *const _,
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

        let key = unsafe { SecKey::wrap_under_create_rule(key_ref as *mut _) };

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

        // Build attributes dictionary using CFMutableDictionary
        let attributes = unsafe {
            let dict = CFMutableDictionary::new();

            let key_type_key = CFString::wrap_under_get_rule(kSecAttrKeyType);
            let key_type_value = CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom);
            dict.set(key_type_key, key_type_value);

            let key_class_key = CFString::wrap_under_get_rule(kSecAttrKeyClass);
            let key_class_value = CFString::wrap_under_get_rule(kSecAttrKeyClassPublic);
            dict.set(key_class_key, key_class_value);

            let key_size_key = CFString::wrap_under_get_rule(kSecAttrKeySizeInBits);
            let key_size_value = CFNumber::from(key_size as i32);
            dict.set(key_size_key, key_size_value);

            dict
        };

        // Create key from data
        let mut error: *const c_void = std::ptr::null();
        let key_ref = unsafe {
            SecKeyCreateWithData(
                key_data.as_concrete_TypeRef() as *const _,
                attributes.as_concrete_TypeRef() as *const _,
                &mut error,
            )
        };

        if key_ref.is_null() {
            return Err("Failed to create public key for verification".to_string());
        }

        let public_key = unsafe { SecKey::wrap_under_create_rule(key_ref as *mut _) };

        // Verify the signature using the high-level API
        public_key
            .verify_signature(algorithm, &hash, signature)
            .map_err(|e| format!("ECDSA signature verification failed: {}", e))?;

        Ok(())
    }
}

/// Static instance of the key provider.
pub(super) static KEY_PROVIDER: AppleCryptoKeyProvider = AppleCryptoKeyProvider;

/// Static instance of the signature verifier.
pub(super) static SIGNATURE_VERIFIER: AppleCryptoSignatureVerifier = AppleCryptoSignatureVerifier;
