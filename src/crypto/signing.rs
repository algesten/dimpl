use crate::crypto::ParsedKey;

/// Sign data using the provided parsed key
pub fn sign_data(parsed_key: &ParsedKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    match parsed_key {
        ParsedKey::P256(key_pair) | ParsedKey::P384(key_pair) => {
            let signature = key_pair
                .sign(&rng, data)
                .map_err(|_| "Signing failed".to_string())?;
            Ok(signature.as_ref().to_vec())
        }
    }
}
