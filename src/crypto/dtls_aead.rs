//! DTLS AEAD record formatting types and constants.
//!
//! This module contains types and constants specific to DTLS AEAD record formatting,
//! separate from the pluggable crypto provider abstraction.

use crate::dtls12::message::{ContentType, Sequence};

/// Explicit nonce length for DTLS AEAD records.
///
/// The explicit nonce is transmitted with each record.
pub(crate) const DTLS_EXPLICIT_NONCE_LEN: usize = 8;

/// GCM authentication tag length.
///
/// The tag is appended to the ciphertext.
pub(crate) const GCM_TAG_LEN: usize = 16;

/// Overhead per AEAD record (explicit nonce + tag).
///
/// This equals 24 bytes for DTLS AES-GCM.
pub(crate) const DTLS_AEAD_OVERHEAD: usize = DTLS_EXPLICIT_NONCE_LEN + GCM_TAG_LEN; // 24

/// Compute AAD length from plaintext length for AEAD records.
/// For DTLS AEAD this is the plaintext length.
#[inline]
#[cfg(test)]
pub fn aad_len_from_plaintext_len(plaintext_len: u16) -> u16 {
    plaintext_len
}

/// Compute fragment length from plaintext length for AEAD records.
/// fragment_len = explicit_nonce(8) + ciphertext(plaintext_len + 16 tag)
#[inline]
#[cfg(test)]
pub fn fragment_len_from_plaintext_len(plaintext_len: usize) -> usize {
    DTLS_EXPLICIT_NONCE_LEN + plaintext_len + GCM_TAG_LEN
}

/// Compute plaintext length from fragment length, if large enough.
/// Returns None if the fragment is smaller than the mandatory AEAD overhead.
#[inline]
#[cfg(test)]
pub fn plaintext_len_from_fragment_len(fragment_len: usize) -> Option<usize> {
    fragment_len.checked_sub(DTLS_AEAD_OVERHEAD)
}

/// Fixed IV portion for DTLS AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Iv(pub [u8; 4]);

impl Iv {
    pub(crate) fn new(iv: &[u8]) -> Self {
        // invariant: the iv is 4 bytes.
        Self(iv.try_into().unwrap())
    }
}

/// Full AEAD nonce (fixed IV + explicit nonce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    /// Create a new AEAD nonce by combining fixed IV and explicit nonce.
    pub(crate) fn new(iv: Iv, explicit_nonce: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&iv.0);
        nonce[4..].copy_from_slice(explicit_nonce);
        Self(nonce)
    }
}

/// Additional Authenticated Data for DTLS records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aad(pub [u8; 13]);

impl Aad {
    /// Create Additional Authenticated Data for a DTLS record.
    pub(crate) fn new(content_type: ContentType, sequence: Sequence, length: u16) -> Self {
        // Exactly match the format used in the working dtls implementation
        let mut aad = [0u8; 13];

        // First set the full 8-byte sequence number
        aad[..8].copy_from_slice(&sequence.sequence_number.to_be_bytes());

        // Then overwrite the first 2 bytes with epoch
        aad[..2].copy_from_slice(&sequence.epoch.to_be_bytes());

        // Content type at index 8
        aad[8] = content_type.as_u8();

        // Protocol version bytes (major:minor) at indexes 9-10
        aad[9] = 0xfe; // DTLS 1.2 major version
        aad[10] = 0xfd; // DTLS 1.2 minor version

        // Payload length (2 bytes) at indexes 11-12
        aad[11..].copy_from_slice(&length.to_be_bytes());

        Aad(aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_constants_and_length_helpers() {
        assert_eq!(DTLS_EXPLICIT_NONCE_LEN, 8);
        assert_eq!(GCM_TAG_LEN, 16);
        assert_eq!(DTLS_AEAD_OVERHEAD, 24);

        for &pt_len in &[0usize, 1, 37, 512, 1350, 16384] {
            let aad_len = aad_len_from_plaintext_len(pt_len as u16);
            assert_eq!(aad_len as usize, pt_len);

            let frag_len = fragment_len_from_plaintext_len(pt_len);
            assert_eq!(frag_len, DTLS_EXPLICIT_NONCE_LEN + pt_len + GCM_TAG_LEN);

            let roundtrip =
                plaintext_len_from_fragment_len(frag_len).expect("frag_len >= overhead");
            assert_eq!(roundtrip, pt_len);
        }

        assert!(plaintext_len_from_fragment_len(0).is_none());
        assert!(plaintext_len_from_fragment_len(3).is_none());
        assert!(plaintext_len_from_fragment_len(DTLS_AEAD_OVERHEAD - 1).is_none());
    }
}
