//! HMAC utilities using Apple CommonCrypto.

use std::ffi::c_void;

use crate::buffer::Buf;
use crate::message::HashAlgorithm;

use super::common_crypto::*;

/// Compute HMAC using TLS 1.2 P_hash algorithm.
pub(super) fn p_hash(
    hash_alg: HashAlgorithm,
    secret: &[u8],
    full_seed: &[u8],
    out: &mut Buf,
    output_len: usize,
) -> Result<(), String> {
    out.clear();

    let (hmac_alg, hash_len) = match hash_alg {
        HashAlgorithm::SHA256 => (K_CC_HMAC_ALG_SHA256, CC_SHA256_DIGEST_LENGTH),
        HashAlgorithm::SHA384 => (K_CC_HMAC_ALG_SHA384, CC_SHA384_DIGEST_LENGTH),
        _ => return Err(format!("Unsupported HMAC hash algorithm: {:?}", hash_alg)),
    };

    // A(1) = HMAC_hash(secret, A(0)) where A(0) = seed
    let mut a = vec![0u8; hash_len];
    unsafe {
        CCHmac(
            hmac_alg,
            secret.as_ptr() as *const c_void,
            secret.len(),
            full_seed.as_ptr() as *const c_void,
            full_seed.len(),
            a.as_mut_ptr() as *mut c_void,
        );
    }

    while out.len() < output_len {
        // HMAC_hash(secret, A(i) + seed)
        let mut combined = a.clone();
        combined.extend_from_slice(full_seed);

        let mut output = vec![0u8; hash_len];
        unsafe {
            CCHmac(
                hmac_alg,
                secret.as_ptr() as *const c_void,
                secret.len(),
                combined.as_ptr() as *const c_void,
                combined.len(),
                output.as_mut_ptr() as *mut c_void,
            );
        }

        let remaining = output_len - out.len();
        let to_copy = std::cmp::min(remaining, output.len());
        out.extend_from_slice(&output[..to_copy]);

        if out.len() < output_len {
            // A(i+1) = HMAC_hash(secret, A(i))
            let mut next_a = vec![0u8; hash_len];
            unsafe {
                CCHmac(
                    hmac_alg,
                    secret.as_ptr() as *const c_void,
                    secret.len(),
                    a.as_ptr() as *const c_void,
                    a.len(),
                    next_a.as_mut_ptr() as *mut c_void,
                );
            }
            a = next_a;
        }
    }

    Ok(())
}
