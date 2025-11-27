//! HMAC utilities using RustCrypto.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

use crate::buffer::Buf;
use crate::message::HashAlgorithm;

/// Compute HMAC using TLS 1.2 P_hash algorithm.
pub(super) fn p_hash(
    hash_alg: HashAlgorithm,
    secret: &[u8],
    full_seed: &[u8],
    out: &mut Buf,
    output_len: usize,
) -> Result<(), String> {
    out.clear();

    // A(1) = HMAC_hash(secret, A(0)) where A(0) = seed
    match hash_alg {
        HashAlgorithm::SHA256 => {
            let mut a_hmac = Hmac::<Sha256>::new_from_slice(secret)
                .map_err(|_| "Invalid HMAC key length".to_string())?;
            a_hmac.update(full_seed);
            let mut a = a_hmac.finalize().into_bytes();

            while out.len() < output_len {
                // HMAC_hash(secret, A(i) + seed)
                let mut ctx = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| "Invalid HMAC key length".to_string())?;
                ctx.update(&a);
                ctx.update(full_seed);
                let output = ctx.finalize().into_bytes();

                let remaining = output_len - out.len();
                let to_copy = std::cmp::min(remaining, output.len());
                out.extend_from_slice(&output[..to_copy]);

                if out.len() < output_len {
                    // A(i+1) = HMAC_hash(secret, A(i))
                    let mut next_a = Hmac::<Sha256>::new_from_slice(secret)
                        .map_err(|_| "Invalid HMAC key length".to_string())?;
                    next_a.update(&a);
                    a = next_a.finalize().into_bytes();
                }
            }
        }
        HashAlgorithm::SHA384 => {
            let mut a_hmac = Hmac::<Sha384>::new_from_slice(secret)
                .map_err(|_| "Invalid HMAC key length".to_string())?;
            a_hmac.update(full_seed);
            let mut a = a_hmac.finalize().into_bytes();

            while out.len() < output_len {
                // HMAC_hash(secret, A(i) + seed)
                let mut ctx = Hmac::<Sha384>::new_from_slice(secret)
                    .map_err(|_| "Invalid HMAC key length".to_string())?;
                ctx.update(&a);
                ctx.update(full_seed);
                let output = ctx.finalize().into_bytes();

                let remaining = output_len - out.len();
                let to_copy = std::cmp::min(remaining, output.len());
                out.extend_from_slice(&output[..to_copy]);

                if out.len() < output_len {
                    // A(i+1) = HMAC_hash(secret, A(i))
                    let mut next_a = Hmac::<Sha384>::new_from_slice(secret)
                        .map_err(|_| "Invalid HMAC key length".to_string())?;
                    next_a.update(&a);
                    a = next_a.finalize().into_bytes();
                }
            }
        }
        _ => return Err(format!("Unsupported HMAC hash algorithm: {:?}", hash_alg)),
    }

    Ok(())
}
