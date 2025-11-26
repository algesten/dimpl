//! Key exchange group implementations for Apple platforms using Security framework.

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey};
use security_framework_sys::key::{
    kSecAttrKeyTypeECSECPrimeRandom, kSecKeyAlgorithmECDHKeyExchangeStandard,
    SecKeyCopyKeyExchangeResult,
};

use crate::buffer::Buf;
use crate::crypto::provider::{ActiveKeyExchange, SupportedKxGroup};
use crate::message::NamedGroup;

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

        // Create key attributes for EC public key
        let key_type_key = unsafe { CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom) };
        let key_class_key =
            unsafe { CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeyClass) };
        let key_class_value = unsafe {
            CFString::wrap_under_get_rule(security_framework_sys::key::kSecAttrKeyClassPublic)
        };

        let key_size = match self.group {
            NamedGroup::Secp256r1 => 256,
            NamedGroup::Secp384r1 => 384,
            _ => return Err("Unsupported group".to_string()),
        };

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

        // Create peer public key from data
        let mut error: core_foundation::base::CFTypeRef = std::ptr::null();
        let peer_public_key = unsafe {
            security_framework_sys::key::SecKeyCreateWithData(
                peer_key_data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            )
        };

        if peer_public_key.is_null() {
            return Err("Failed to import peer public key".to_string());
        }

        let peer_public_key = unsafe { SecKey::wrap_under_create_rule(peer_public_key) };

        // Perform ECDH key exchange
        let algorithm = unsafe { kSecKeyAlgorithmECDHKeyExchangeStandard };
        let mut error: core_foundation::base::CFTypeRef = std::ptr::null();

        let shared_secret = unsafe {
            SecKeyCopyKeyExchangeResult(
                self.private_key.as_concrete_TypeRef(),
                algorithm,
                peer_public_key.as_concrete_TypeRef(),
                std::ptr::null(),
                &mut error,
            )
        };

        if shared_secret.is_null() {
            return Err("ECDH key exchange failed".to_string());
        }

        let shared_secret_data = unsafe { CFData::wrap_under_create_rule(shared_secret) };

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
