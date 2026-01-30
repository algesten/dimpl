//! TLS 1.2 PRF using aws-lc-rs.

use crate::buffer::Buf;
use crate::crypto::provider::PrfProvider;
use crate::types::HashAlgorithm;

use super::hmac;

/// PRF provider implementation for TLS 1.2.
#[derive(Debug)]
pub(super) struct AwsLcPrfProvider;

impl PrfProvider for AwsLcPrfProvider {
    fn prf_tls12(
        &self,
        secret: &[u8],
        label: &str,
        seed: &[u8],
        out: &mut Buf,
        output_len: usize,
        scratch: &mut Buf,
        hash: HashAlgorithm,
    ) -> Result<(), String> {
        assert!(label.is_ascii(), "Label must be ASCII");

        // Use scratch buffer for full_seed concatenation
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);

        let algorithm = hmac::hmac_algorithm(hash)?;
        hmac::p_hash(algorithm, secret, scratch, out, output_len)
    }
}

/// Static instance of the PRF provider.
pub(super) static PRF_PROVIDER: AwsLcPrfProvider = AwsLcPrfProvider;
