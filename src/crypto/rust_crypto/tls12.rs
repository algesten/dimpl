//! TLS 1.2 PRF using RustCrypto.

use super::super::PrfProvider;
use crate::buffer::Buf;
use crate::types::HashAlgorithm;

use super::hmac;

/// PRF provider implementation for TLS 1.2.
#[derive(Debug)]
pub(super) struct RustCryptoPrfProvider;

impl PrfProvider for RustCryptoPrfProvider {
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

        // Compute full_seed = label + seed using scratch buffer
        scratch.clear();
        scratch.extend_from_slice(label.as_bytes());
        scratch.extend_from_slice(seed);

        hmac::p_hash(hash, secret, scratch, out, output_len)
    }
}

/// Static instance of the PRF provider.
pub(super) static PRF_PROVIDER: RustCryptoPrfProvider = RustCryptoPrfProvider;
