use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Implement TLS 1.2 PRF (Pseudorandom Function)
/// as specified in RFC 5246 Section 5
pub fn prf_tls12(
    secret: &[u8],
    label: &str,
    seed: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, String> {
    // In TLS 1.2, PRF uses HMAC-SHA256
    let mut hmac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;

    // A(1) = HMAC_hash(secret, label + seed)
    hmac.update(label.as_bytes());
    hmac.update(seed);
    let a1 = hmac.finalize().into_bytes();

    let mut result = Vec::with_capacity(output_len);
    let mut a_i = a1.clone();

    // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    //                        HMAC_hash(secret, A(2) + seed) +
    //                        HMAC_hash(secret, A(3) + seed) + ...
    while result.len() < output_len {
        let mut hmac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;

        // HMAC_hash(secret, A(i) + label + seed)
        hmac.update(&a_i);
        hmac.update(label.as_bytes());
        hmac.update(seed);

        let output = hmac.finalize().into_bytes();
        result.extend_from_slice(&output);

        // A(i+1) = HMAC_hash(secret, A(i))
        let mut hmac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;
        hmac.update(&a_i);
        a_i = hmac.finalize().into_bytes();
    }

    // Truncate to the desired length
    result.truncate(output_len);
    Ok(result)
}

/// Master secret calculation for TLS 1.2
/// as specified in RFC 5246 Section 8.1
pub fn calculate_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Result<Vec<u8>, String> {
    // Concatenate client_random and server_random for seed
    let mut seed = Vec::with_capacity(client_random.len() + server_random.len());
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);

    // master_secret = PRF(pre_master_secret, "master secret", client_random + server_random, 48)
    prf_tls12(pre_master_secret, "master secret", &seed, 48)
}

/// Key expansion for TLS 1.2
/// as specified in RFC 5246 Section 6.3
pub fn key_expansion(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    key_material_length: usize,
) -> Result<Vec<u8>, String> {
    // For key expansion, the seed is server_random + client_random
    let mut seed = Vec::with_capacity(client_random.len() + server_random.len());
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    // key_block = PRF(master_secret, "key expansion", server_random + client_random, key_material_length)
    prf_tls12(master_secret, "key expansion", &seed, key_material_length)
}
