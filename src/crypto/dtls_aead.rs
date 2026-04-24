//! DTLS AEAD record formatting types and constants.
//!
//! This module contains types and constants specific to DTLS AEAD record formatting,
//! separate from the pluggable crypto provider abstraction.

use arrayvec::ArrayVec;

use crate::types::{ContentType, Sequence};

/// Explicit nonce length for DTLS AEAD records.
///
/// The explicit nonce is transmitted with each record.
#[cfg(test)]
pub(crate) const DTLS_EXPLICIT_NONCE_LEN: usize = 8;

/// GCM authentication tag length.
///
/// The tag is appended to the ciphertext.
#[cfg(test)]
pub(crate) const GCM_TAG_LEN: usize = 16;

/// Overhead per DTLS 1.2 AES-GCM record (explicit nonce + tag).
///
/// This equals 24 bytes for DTLS AES-GCM.
#[cfg(test)]
pub(crate) const DTLS_AEAD_OVERHEAD: usize = DTLS_EXPLICIT_NONCE_LEN + GCM_TAG_LEN; // 24

/// Compute AAD length from plaintext length for DTLS 1.2 AES-GCM records.
#[inline]
#[cfg(test)]
pub fn aad_len_from_plaintext_len(plaintext_len: u16) -> u16 {
    plaintext_len
}

/// Compute fragment length from plaintext length for DTLS 1.2 AES-GCM records.
/// fragment_len = explicit_nonce(8) + ciphertext(plaintext_len + 16 tag)
#[inline]
#[cfg(test)]
pub fn fragment_len_from_plaintext_len(plaintext_len: usize) -> usize {
    DTLS_EXPLICIT_NONCE_LEN + plaintext_len + GCM_TAG_LEN
}

/// Compute plaintext length from fragment length for DTLS 1.2 AES-GCM records.
/// Returns None if the fragment is smaller than the mandatory AEAD overhead.
#[inline]
#[cfg(test)]
pub fn plaintext_len_from_fragment_len(fragment_len: usize) -> Option<usize> {
    fragment_len.checked_sub(DTLS_AEAD_OVERHEAD)
}

/// Fixed IV portion for DTLS AEAD.
///
/// DTLS 1.2 uses:
/// - AES-GCM: 4-byte fixed IV + 8-byte explicit nonce (per record)
/// - ChaCha20-Poly1305: 12-byte fixed IV + 0-byte explicit nonce
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Iv {
    bytes: [u8; 12],
    len: u8,
}

impl Iv {
    pub(crate) fn new(iv: &[u8]) -> Self {
        assert!(
            iv.len() <= 12,
            "invalid IV length: expected <= 12, got {}",
            iv.len()
        );
        let mut bytes = [0u8; 12];
        bytes[..iv.len()].copy_from_slice(iv);
        Self {
            bytes,
            len: iv.len() as u8,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    /// Returns the full 12-byte backing array.
    ///
    /// Only valid for 12-byte IVs (ChaCha20-Poly1305). For 4-byte IVs
    /// (AES-GCM), use [`as_slice`] instead.
    pub(crate) fn as_12_bytes(&self) -> &[u8; 12] {
        assert_eq!(
            self.len(),
            12,
            "as_12_bytes called on {}-byte IV",
            self.len()
        );
        &self.bytes
    }
}

/// Full AEAD nonce (fixed IV + explicit nonce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    /// Create a new AEAD nonce by combining fixed IV and explicit nonce (DTLS 1.2).
    pub(crate) fn new(iv: Iv, explicit_nonce: &[u8]) -> Self {
        assert_eq!(
            iv.len() + explicit_nonce.len(),
            12,
            "invalid DTLS 1.2 nonce parts: iv_len={}, explicit_nonce_len={}",
            iv.len(),
            explicit_nonce.len()
        );
        let mut nonce = [0u8; 12];
        let iv_len = iv.len();
        nonce[..iv_len].copy_from_slice(iv.as_slice());
        nonce[iv_len..].copy_from_slice(explicit_nonce);
        Self(nonce)
    }

    /// Create a nonce by XORing the IV with the padded sequence number.
    ///
    /// Used by both DTLS 1.2 (ChaCha20-Poly1305) and DTLS 1.3:
    /// nonce = iv XOR pad_left(sequence_number, 12)
    /// See RFC 8446 Section 5.3 / RFC 7905.
    pub(crate) fn xor(iv: &[u8; 12], seq: u64) -> Self {
        let mut nonce = *iv;
        let seq_bytes = seq.to_be_bytes(); // 8 bytes
        // XOR the last 8 bytes of the 12-byte IV with the sequence number
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        Self(nonce)
    }
}

/// Maximum length of a DTLS 1.2 Connection ID (RFC 9146).
///
/// RFC 9146 caps CID length at a single byte. `Config::build` rejects
/// `connection_id` longer than this, and `ConnectionIdExtension::parse`
/// enforces the same ceiling via its `ArrayVec<u8, 255>` backing store.
pub const DTLS12_CID_MAX_LEN: usize = 255;

/// Maximum capacity for a DTLS AAD buffer.
///
/// 23 fixed bytes (DTLS 1.2 CID AAD header, RFC 9146 §5) + up to 255 CID bytes.
/// Sizing for the worst case keeps the `try_extend_from_slice(cid)` paths
/// panic-free for any config-validated CID without a runtime bound check.
/// Also covers DTLS 1.2 (13 bytes) and DTLS 1.3 (3-5 bytes) AAD forms.
pub const DTLS12_CID_AAD_MAX: usize = 23 + DTLS12_CID_MAX_LEN;

/// Additional Authenticated Data for DTLS records.
///
/// Variable-length to support DTLS 1.2 (13 bytes), DTLS 1.2 with CID (23+N bytes),
/// and DTLS 1.3 (3-5 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad(ArrayVec<u8, DTLS12_CID_AAD_MAX>);

impl Aad {
    /// Borrow the AAD as a byte slice for AEAD operations.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Aad {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Aad {
    /// Create Additional Authenticated Data for a DTLS 1.2 record.
    ///
    /// `version` is the 2-byte wire version field observed in the record
    /// header (e.g. `[0xFE, 0xFD]` for DTLS 1.2, `[0xFE, 0xFF]` for
    /// DTLS 1.0). RFC 6347 §4.1.2.1 names this slot `DTLSCompressed.version`
    /// — the bytes that were actually transmitted — so the sender and
    /// receiver must bind the same bytes or AEAD authentication fails.
    pub(crate) fn new_dtls12(
        content_type: ContentType,
        sequence: Sequence,
        version: [u8; 2],
        length: u16,
    ) -> Self {
        let mut aad = ArrayVec::new();

        // First set the full 8-byte sequence number
        let seq_bytes = sequence.sequence_number.to_be_bytes();
        // unwrap: total DTLS 1.2 AAD is 13 bytes, well within DTLS12_CID_AAD_MAX.
        aad.try_extend_from_slice(&seq_bytes).unwrap();

        // Overwrite the first 2 bytes with epoch
        let epoch_bytes = sequence.epoch.to_be_bytes();
        aad[0] = epoch_bytes[0];
        aad[1] = epoch_bytes[1];

        // Content type at index 8
        aad.push(content_type.as_u8());

        // Protocol version bytes (major:minor) at indexes 9-10, from the wire
        aad.push(version[0]);
        aad.push(version[1]);

        // Payload length (2 bytes) at indexes 11-12
        // unwrap: same capacity argument as the seq_bytes extend above.
        aad.try_extend_from_slice(&length.to_be_bytes()).unwrap();

        Aad(aad)
    }

    /// Create Additional Authenticated Data for a DTLS 1.2 CID record (RFC 9146 §5).
    ///
    /// `version` is the 2-byte wire `DTLSCiphertext.version` field from the
    /// record header. Per RFC 9146 §5 the AAD binds the exact bytes the
    /// sender put on the wire, so a peer that emits `0xFE 0xFF` (DTLS 1.0)
    /// requires `[0xFE, 0xFF]` here — hardcoding `0xFE 0xFD` would silently
    /// fail AEAD against such a peer.
    ///
    /// AAD layout:
    /// ```text
    /// seq_num_placeholder(8, 0xFF) | tls12_cid(1) | cid_length(1) |
    /// tls12_cid(1) | version(2) | epoch(2) | sequence_number(6) |
    /// cid(N) | length_of_DTLSInnerPlaintext(2)
    /// ```
    pub(crate) fn new_dtls12_cid(
        sequence: Sequence,
        version: [u8; 2],
        cid: &[u8],
        inner_plaintext_len: u16,
    ) -> Self {
        let mut aad = ArrayVec::new();

        // 8 bytes of 0xFF as sequence number placeholder.
        // unwrap: fixed 8 bytes, well within DTLS12_CID_AAD_MAX.
        aad.try_extend_from_slice(&[0xFF; 8]).unwrap();

        // tls12_cid content type (25)
        aad.push(ContentType::Tls12Cid.as_u8());

        // CID length (1 byte).
        // `cid.len() as u8` is lossless: `Config::build` rejects CID > 255
        // bytes, and `ConnectionIdExtension::parse` enforces the same 255
        // ceiling via its `ArrayVec<u8, 255>` backing store, so the value
        // always fits in u8.
        aad.push(cid.len() as u8);

        // tls12_cid content type again (25)
        aad.push(ContentType::Tls12Cid.as_u8());

        // Wire version bytes from the record header.
        aad.push(version[0]);
        aad.push(version[1]);

        // First set the full 8-byte sequence number.
        // unwrap: at this point 13 bytes are consumed, adding 8 stays within DTLS12_CID_AAD_MAX.
        let seq_bytes = sequence.sequence_number.to_be_bytes();
        aad.try_extend_from_slice(&seq_bytes).unwrap();

        // Overwrite the first 2 bytes with epoch
        let epoch_bytes = sequence.epoch.to_be_bytes();
        aad[13] = epoch_bytes[0];
        aad[14] = epoch_bytes[1];

        // CID (N bytes).
        // unwrap: 21 fixed bytes are consumed by now, `cid.len() <=
        // DTLS12_CID_MAX_LEN` by config validation, and remaining capacity
        // is DTLS12_CID_AAD_MAX - 21 = 257, so the extend always succeeds.
        aad.try_extend_from_slice(cid).unwrap();

        // Length of DTLSInnerPlaintext (2 bytes).
        // unwrap: worst case is 21 + DTLS12_CID_MAX_LEN + 2 =
        // DTLS12_CID_AAD_MAX which matches capacity exactly — still fits.
        aad.try_extend_from_slice(&inner_plaintext_len.to_be_bytes())
            .unwrap();

        Aad(aad)
    }

    /// Create Additional Authenticated Data for a DTLS 1.3 record.
    ///
    /// The AAD is the raw unified header bytes (3-5 bytes).
    pub(crate) fn new_dtls13(header_bytes: &[u8]) -> Self {
        let mut aad = ArrayVec::new();
        // unwrap: header_bytes is at most 5 bytes, well within capacity 13
        aad.try_extend_from_slice(header_bytes).unwrap();
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

    #[test]
    fn aad_new_dtls12_cid_layout() {
        // RFC 9146 §5 AAD layout verification
        let sequence = Sequence {
            epoch: 1,
            sequence_number: 42,
        };
        let cid = b"test-cid";
        let inner_plaintext_len: u16 = 100;

        let aad = Aad::new_dtls12_cid(sequence, [0xFE, 0xFD], cid, inner_plaintext_len);
        let bytes = aad.as_slice();

        // Total: 8 + 1 + 1 + 1 + 2 + 2 + 6 + 8 + 2 = 31 bytes
        assert_eq!(bytes.len(), 23 + cid.len());

        // seq_num_placeholder: 8 bytes of 0xFF
        assert_eq!(&bytes[0..8], &[0xFF; 8]);
        // tls12_cid content type
        assert_eq!(bytes[8], 25);
        // cid_length
        assert_eq!(bytes[9], cid.len() as u8);
        // tls12_cid content type again
        assert_eq!(bytes[10], 25);
        // version: DTLS 1.2 = {0xFE, 0xFD}
        assert_eq!(&bytes[11..13], &[0xFE, 0xFD]);
        // epoch
        assert_eq!(&bytes[13..15], &[0x00, 0x01]);
        // sequence_number (6 bytes)
        assert_eq!(&bytes[15..21], &[0x00, 0x00, 0x00, 0x00, 0x00, 42]);
        // CID
        assert_eq!(&bytes[21..21 + cid.len()], cid);
        // inner_plaintext_len
        assert_eq!(&bytes[21 + cid.len()..], &inner_plaintext_len.to_be_bytes());
    }
}
