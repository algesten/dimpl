//! SRTP keying material types and profiles used by DTLS-SRTP.
use std::ops::Deref;

/// Keying material used as master key for SRTP.
pub struct KeyingMaterial<'a>(&'a [u8]);

impl<'a> KeyingMaterial<'a> {
    /// Create a new wrapper for DTLS-SRTP keying material bytes.
    pub fn new(m: &'a [u8]) -> Self {
        KeyingMaterial(m)
    }
}

impl<'a> Deref for KeyingMaterial<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> std::fmt::Debug for KeyingMaterial<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyingMaterial")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Supported SRTP protection profiles (RFC 5764).
pub enum SrtpProfile {
    /// SRTP_AES128_CM_HMAC_SHA1_80 (RFC 5764)
    Aes128CmSha1_80,
    /// AEAD_AES_128_GCM (RFC 7714)
    AeadAes128Gcm,
    /// AEAD_AES_256_GCM (RFC 7714)
    AeadAes256Gcm,
}

impl SrtpProfile {
    /// All supported profiles ordered by preference.
    pub const ALL: &'static [SrtpProfile] = &[
        SrtpProfile::AeadAes256Gcm,
        SrtpProfile::AeadAes128Gcm,
        SrtpProfile::Aes128CmSha1_80,
    ];

    /// The length of keying material to extract from the DTLS session in bytes.
    #[rustfmt::skip]
    pub fn keying_material_len(&self) -> usize {
        match self {
             // MASTER_KEY_LEN * 2 + MASTER_SALT * 2
             // TODO: This is a duplication of info that is held in srtp.rs, because we
             // don't want a dependency in that direction.
            SrtpProfile::Aes128CmSha1_80 => 16 * 2 + 14 * 2,
            SrtpProfile::AeadAes128Gcm   => 16 * 2 + 12 * 2,
            SrtpProfile::AeadAes256Gcm   => 32 * 2 + 12 * 2,
        }
    }
}
