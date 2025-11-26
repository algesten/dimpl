//! Key exchange group implementations for Apple platforms using Security framework.

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};

use crate::buffer::Buf;
use crate::crypto::provider::{ActiveKeyExchange, SupportedKxGroup};
use crate::message::NamedGroup;

// Security framework key exchange algorithm
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecKeyAlgorithmECDHKeyExchangeStandard: *const std::ffi::c_void;

    fn SecKeyCopyKeyExchangeResult(
        private_key: *const std::ffi::c_void,
        algorithm: *const std::ffi::c_void,
        public_key: *const std::ffi::c_void,
        parameters: *const std::ffi::c_void,
        error: *mut *const std::ffi::c_void,
    ) -> *const std::ffi::c_void;

    fn SecKeyCreateWithData(
        key_data: *const std::ffi::c_void,
        attributes: *const std::ffi::c_void,
        error: *mut *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void;

    // Key attribute constants
    static kSecAttrKeyType: *const std::ffi::c_void;
    static kSecAttrKeyTypeECSECPrimeRandom: *const std::ffi::c_void;
    static kSecAttrKeyClass: *const std::ffi::c_void;
    static kSecAttrKeyClassPublic: *const std::ffi::c_void;
    static kSecAttrKeySizeInBits: *const std::ffi::c_void;
}

/// ECDHE key exchange implementation using Security framework.
struct EcdhKeyExchange {
    private_key: SecKey,
    public_key_bytes: Buf,
    group: NamedGroup,
}

impl std::fmt::Debug for EcdhKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.group {
            NamedGroup::Secp256r1 => f
                .debug_struct("EcdhKeyExchange::P256")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            NamedGroup::Secp384r1 => f
                .debug_struct("EcdhKeyExchange::P384")
                .field("public_key_len", &self.public_key_bytes.len())
                .finish_non_exhaustive(),
            _ => f
                .debug_struct("EcdhKeyExchange::Unknown")
                .finish_non_exhaustive(),
        }
    }
}

impl EcdhKeyExchange {
    fn new(group: NamedGroup, mut buf: Buf) -> Result<Self, String> {
        let key_size = match group {
            NamedGroup::Secp256r1 => 256,
            NamedGroup::Secp384r1 => 384,
            _ => return Err("Unsupported group".to_string()),
        };

        // Generate ephemeral EC key pair using Security framework
        let mut options = GenerateKeyOptions::default();
        options.set_key_type(KeyType::ec());
        options.set_size_in_bits(key_size);

        let private_key = SecKey::new(&options)
            .map_err(|e| format!("Failed to generate EC key pair: {}", e))?;

        let public_key = private_key
            .public_key()
            .ok_or_else(|| "Failed to get public key".to_string())?;

        // Export public key as SEC1 uncompressed point format
        let public_key_data = public_key
            .external_representation()
            .ok_or_else(|| "Failed to export public key".to_string())?;

        buf.clear();
        buf.extend_from_slice(&public_key_data);

        Ok(EcdhKeyExchange {
            private_key,
            public_key_bytes: buf,
            group,
        })
    }
}

impl ActiveKeyExchange for EcdhKeyExchange {
    fn pub_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), String> {
        // Import the peer's public key
        let peer_key_data = CFData::from_buffer(peer_pub);

        let key_size = match self.group {
            NamedGroup::Secp256r1 => 256,
            NamedGroup::Secp384r1 => 384,
            _ => return Err("Unsupported group".to_string()),
        };

        // Build attributes dictionary using Core Foundation types
        let key_size_cf = core_foundation::number::CFNumber::from(key_size as i32);

        // Create dictionary with key attributes
        let keys: Vec<core_foundation::string::CFString> = unsafe {
            vec![
                core_foundation::string::CFString::wrap_under_get_rule(
                    kSecAttrKeyType as *const _,
                ),
                core_foundation::string::CFString::wrap_under_get_rule(
                    kSecAttrKeyClass as *const _,
                ),
                core_foundation::string::CFString::wrap_under_get_rule(
                    kSecAttrKeySizeInBits as *const _,
                ),
            ]
        };

        let values: Vec<core_foundation::base::CFType> = unsafe {
            vec![
                core_foundation::string::CFString::wrap_under_get_rule(
                    kSecAttrKeyTypeECSECPrimeRandom as *const _,
                )
                .as_CFType(),
                core_foundation::string::CFString::wrap_under_get_rule(
                    kSecAttrKeyClassPublic as *const _,
                )
                .as_CFType(),
                key_size_cf.as_CFType(),
            ]
        };

        let pairs: Vec<_> = keys
            .iter()
            .map(|k| k.as_CFType())
            .zip(values.iter().cloned())
            .collect();

        let attributes = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&pairs);

        // Create peer public key from data
        let mut error: *const std::ffi::c_void = std::ptr::null();
        let peer_public_key = unsafe {
            SecKeyCreateWithData(
                peer_key_data.as_concrete_TypeRef() as *const _,
                attributes.as_concrete_TypeRef() as *const _,
                &mut error,
            )
        };

        if peer_public_key.is_null() {
            return Err("Failed to import peer public key".to_string());
        }

        let peer_public_key =
            unsafe { SecKey::wrap_under_create_rule(peer_public_key as *mut _) };

        // Perform ECDH key exchange
        let mut error: *const std::ffi::c_void = std::ptr::null();

        let shared_secret = unsafe {
            SecKeyCopyKeyExchangeResult(
                self.private_key.as_concrete_TypeRef() as *const _,
                kSecKeyAlgorithmECDHKeyExchangeStandard,
                peer_public_key.as_concrete_TypeRef() as *const _,
                std::ptr::null(),
                &mut error,
            )
        };

        if shared_secret.is_null() {
            return Err("ECDH key exchange failed".to_string());
        }

        let shared_secret_data =
            unsafe { CFData::wrap_under_create_rule(shared_secret as *const _) };

        out.clear();
        out.extend_from_slice(&shared_secret_data);

        Ok(())
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
