use crate::message::HashAlgorithm;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use tinyvec::ArrayVec;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

/// PRF for TLS 1.2
/// as specified in RFC 5246 Section 5.
///
/// PRF(secret, label, seed) = P_<hash>(secret, label + seed)
///
/// NOTE: The seed parameter here is the actual seed data WITHOUT the label.
/// The label will be prepended to form the full seed used in the PRF calculation.
pub fn prf_tls12(
    secret: &[u8],
    label: &str,
    seed: &[u8],
    output_len: usize,
    hash: HashAlgorithm,
) -> Result<ArrayVec<[u8; 128]>, String> {
    let full_seed = compute_full_seed(label, seed);

    match hash {
        HashAlgorithm::SHA256 => p_hash::<HmacSha256>(secret, &full_seed, output_len),
        HashAlgorithm::SHA384 => p_hash::<HmacSha384>(secret, &full_seed, output_len),
        _ => Err(format!("Unsupported PRF hash for TLS1.2: {:?}", hash)),
    }
}

fn compute_full_seed(label: &str, seed: &[u8]) -> ArrayVec<[u8; 128]> {
    assert!(label.is_ascii());
    let mut full_seed = ArrayVec::default();
    full_seed.extend_from_slice(label.as_bytes());
    full_seed.extend_from_slice(seed);
    full_seed
}

fn p_hash<M: Mac + KeyInit>(
    secret: &[u8],
    full_seed: &[u8],
    output_len: usize,
) -> Result<ArrayVec<[u8; 128]>, String> {
    let mut result = ArrayVec::default();

    // A(1) = HMAC_hash(secret, A(0)) where A(0) = seed
    let mut hmac = <M as KeyInit>::new_from_slice(secret).map_err(|e| e.to_string())?;
    hmac.update(full_seed);
    let mut a = hmac.finalize().into_bytes();

    while result.len() < output_len {
        // HMAC_hash(secret, A(i) + seed)
        let mut hmac = <M as KeyInit>::new_from_slice(secret).map_err(|e| e.to_string())?;
        hmac.update(&a);
        hmac.update(full_seed);
        let output = hmac.finalize().into_bytes();

        let remaining = output_len - result.len();
        let to_copy = std::cmp::min(remaining, output.len());
        result.extend_from_slice(&output[..to_copy]);

        if result.len() < output_len {
            // A(i+1) = HMAC_hash(secret, A(i))
            let mut hmac = <M as KeyInit>::new_from_slice(secret).map_err(|e| e.to_string())?;
            hmac.update(&a);
            a = hmac.finalize().into_bytes();
        }
    }

    Ok(result)
}

/// Extended Master Secret calculation for TLS 1.2 (RFC 7627)
///
/// master_secret = PRF(pre_master_secret, "extended master secret", session_hash, 48)
pub fn calculate_extended_master_secret(
    pre_master_secret: &[u8],
    session_hash: &[u8],
    hash: HashAlgorithm,
) -> Result<ArrayVec<[u8; 128]>, String> {
    prf_tls12(
        pre_master_secret,
        "extended master secret",
        session_hash,
        48,
        hash,
    )
}

/// Key expansion for TLS 1.2
/// as specified in RFC 5246 Section 6.3
pub fn key_expansion(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    key_material_length: usize,
    hash: HashAlgorithm,
) -> Result<ArrayVec<[u8; 128]>, String> {
    // For key expansion, the seed is server_random + client_random
    let mut seed: ArrayVec<[u8; 128]> = ArrayVec::default();
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    // key_block = PRF(master_secret, "key expansion", server_random + client_random, key_material_length)
    // The label "key expansion" is passed separately and will be prepended to the seed by prf_tls12
    prf_tls12(
        master_secret,
        "key expansion",
        &seed,
        key_material_length,
        hash,
    )
}
