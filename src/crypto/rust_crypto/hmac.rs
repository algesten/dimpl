//! HMAC implementation using RustCrypto.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

use super::super::HmacProvider;
use crate::types::HashAlgorithm;

/// HMAC provider implementation.
#[derive(Debug)]
pub(crate) struct RustCryptoHmacProvider;

impl HmacProvider for RustCryptoHmacProvider {
    fn hmac(
        &self,
        hash: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, String> {
        match hash {
            HashAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| "Invalid HMAC key".to_string())?;
                mac.update(data);
                let result = mac.finalize().into_bytes();
                let len = result.len();
                out[..len].copy_from_slice(&result);
                Ok(len)
            }
            HashAlgorithm::SHA384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| "Invalid HMAC key".to_string())?;
                mac.update(data);
                let result = mac.finalize().into_bytes();
                let len = result.len();
                out[..len].copy_from_slice(&result);
                Ok(len)
            }
            _ => Err(format!("Unsupported HMAC hash algorithm: {:?}", hash)),
        }
    }
}

/// Static instance of the HMAC provider.
pub(crate) static HMAC_PROVIDER: RustCryptoHmacProvider = RustCryptoHmacProvider;
