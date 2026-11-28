//! SRTP keying material types and profiles used by DTLS-SRTP.
use std::ops::Deref;

use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Keying material used as master key for SRTP.
///
/// The bytes are zeroed when the value is dropped.
pub struct KeyingMaterial(Zeroizing<Vec<u8>>);

impl KeyingMaterial {
    /// Create a new wrapper for DTLS-SRTP keying material bytes.
    pub fn new(m: &[u8]) -> Self {
        KeyingMaterial(Zeroizing::new(m.to_vec()))
    }
}

impl Deref for KeyingMaterial {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl ZeroizeOnDrop for KeyingMaterial {}

impl std::fmt::Debug for KeyingMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyingMaterial")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
/// Supported SRTP protection profiles (RFC 5764).
pub enum SrtpProfile {
    /// SRTP_AES128_CM_HMAC_SHA1_80 (RFC 5764)
    AES128_CM_SHA1_80,
    /// AEAD_AES_128_GCM (RFC 7714)
    AEAD_AES_128_GCM,
    /// AEAD_AES_256_GCM (RFC 7714)
    AEAD_AES_256_GCM,
}

impl SrtpProfile {
    /// All supported profiles ordered by preference.
    pub const ALL: &'static [SrtpProfile] = &[
        SrtpProfile::AEAD_AES_256_GCM,
        SrtpProfile::AEAD_AES_128_GCM,
        SrtpProfile::AES128_CM_SHA1_80,
    ];

    /// The length of keying material to extract from the DTLS session in bytes.
    #[rustfmt::skip]
    pub fn keying_material_len(&self) -> usize {
        match self {
             // MASTER_KEY_LEN * 2 + MASTER_SALT * 2
             // TODO: This is a duplication of info that is held in srtp.rs, because we
             // don't want a dependency in that direction.
            SrtpProfile::AES128_CM_SHA1_80 => 16 * 2 + 14 * 2,
            SrtpProfile::AEAD_AES_128_GCM   => 16 * 2 + 12 * 2,
            SrtpProfile::AEAD_AES_256_GCM   => 32 * 2 + 12 * 2,
        }
    }
}

impl std::fmt::Display for SrtpProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SrtpProfile::AES128_CM_SHA1_80 => write!(f, "SRTP_AES128_CM_SHA1_80"),
            SrtpProfile::AEAD_AES_128_GCM => write!(f, "SRTP_AEAD_AES_128_GCM"),
            SrtpProfile::AEAD_AES_256_GCM => write!(f, "SRTP_AEAD_AES_256_GCM"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keying_material_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<KeyingMaterial>();

        let km = KeyingMaterial::new(&[1, 2, 3]);
        assert_eq!(&*km, &[1, 2, 3]);
    }
}
