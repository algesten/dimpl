use crate::crypto::ParsedKey;

/// Sign data using the provided parsed key
pub fn sign_data(parsed_key: &ParsedKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let signature = parsed_key
        .key_pair()
        .sign(&rng, data)
        .map_err(|_| "Signing failed".to_string())?;
    Ok(signature.as_ref().to_vec())
}
