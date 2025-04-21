use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Implement TLS 1.2 PRF (Pseudorandom Function)
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
) -> Result<Vec<u8>, String> {
    // In TLS 1.2, PRF uses HMAC-SHA256
    let mut result = Vec::with_capacity(output_len);

    // A(0) = label + seed
    // Create the full seed by prepending the label to the seed
    let mut full_seed = Vec::with_capacity(label.len() + seed.len());
    full_seed.extend_from_slice(label.as_bytes());
    full_seed.extend_from_slice(seed);

    // Compute A(1) = HMAC_hash(secret, A(0))
    let mut hmac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;
    hmac.update(&full_seed);
    let mut a = hmac.finalize().into_bytes();

    while result.len() < output_len {
        // P_hash = HMAC_hash(secret, A(i) + [label + seed])
        let mut hmac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;
        hmac.update(&a);
        hmac.update(&full_seed);
        let output = hmac.finalize().into_bytes();

        // Add as much of the output as needed
        let remaining = output_len - result.len();
        let to_copy = std::cmp::min(remaining, output.len());
        result.extend_from_slice(&output[..to_copy]);

        // If we need more, compute A(i+1) = HMAC_hash(secret, A(i))
        if result.len() < output_len {
            let mut hmac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;
            hmac.update(&a);
            a = hmac.finalize().into_bytes();
        }
    }

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
    // The label "master secret" is passed separately and will be prepended to the seed by prf_tls12
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
    // The label "key expansion" is passed separately and will be prepended to the seed by prf_tls12
    prf_tls12(master_secret, "key expansion", &seed, key_material_length)
}
