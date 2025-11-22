//! HMAC utilities using aws-lc-rs.

use aws_lc_rs::hmac;

use crate::message::HashAlgorithm;

/// Compute HMAC using TLS 1.2 P_hash algorithm.
pub(super) fn p_hash(
    algorithm: hmac::Algorithm,
    secret: &[u8],
    full_seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();

    let key = hmac::Key::new(algorithm, secret);

    // A(1) = HMAC_hash(secret, A(0)) where A(0) = seed
    let mut a = hmac::sign(&key, full_seed);

    while result.len() < output_len {
        // HMAC_hash(secret, A(i) + seed)
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(a.as_ref());
        ctx.update(full_seed);
        let output = ctx.sign();

        let remaining = output_len - result.len();
        let to_copy = std::cmp::min(remaining, output.as_ref().len());
        result.extend_from_slice(&output.as_ref()[..to_copy]);

        if result.len() < output_len {
            // A(i+1) = HMAC_hash(secret, A(i))
            a = hmac::sign(&key, a.as_ref());
        }
    }

    Ok(result)
}

/// Get HMAC algorithm from hash algorithm.
pub(super) fn hmac_algorithm(hash: HashAlgorithm) -> Result<hmac::Algorithm, String> {
    match hash {
        HashAlgorithm::SHA256 => Ok(hmac::HMAC_SHA256),
        HashAlgorithm::SHA384 => Ok(hmac::HMAC_SHA384),
        _ => Err(format!("Unsupported HMAC hash algorithm: {:?}", hash)),
    }
}
