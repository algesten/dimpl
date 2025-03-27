use std::ops::Deref;

/// Keying material used as master key for SRTP.
pub struct KeyingMaterial(Vec<u8>);

impl KeyingMaterial {
    pub fn new(m: Vec<u8>) -> Self {
        KeyingMaterial(m)
    }
}

impl Deref for KeyingMaterial {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for KeyingMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyingMaterial")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    Aes128CmSha1_80,
    AeadAes128Gcm,
}

#[allow(dead_code)]
impl SrtpProfile {
    // All the profiles we support, ordered from most preferred to least.
    pub const ALL: &'static [SrtpProfile] =
        &[SrtpProfile::AeadAes128Gcm, SrtpProfile::Aes128CmSha1_80];

    /// The length of keying material to extract from the DTLS session in bytes.
    #[rustfmt::skip]
    pub fn keying_material_len(&self) -> usize {
        match self {
             // MASTER_KEY_LEN * 2 + MASTER_SALT * 2
             // TODO: This is a duplication of info that is held in srtp.rs, because we
             // don't want a dependency in that direction.
            SrtpProfile::Aes128CmSha1_80 => 16 * 2 + 14 * 2,
            SrtpProfile::AeadAes128Gcm   => 16 * 2 + 12 * 2,
        }
    }
}
