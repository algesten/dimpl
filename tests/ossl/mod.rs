#![allow(unused)]

//! OpenSSL implementation of cryptographic functions.

/// Errors that can arise in DTLS.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Some error from OpenSSL layer (used for DTLS).
    #[error("{0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// Other IO errors.
    #[error("{0}")]
    Io(#[from] io::Error),
}

mod cert;
use std::io;

pub use cert::{Fingerprint, OsslDtlsCert};

mod io_buf;
mod stream;

mod dtls;
use dimpl::KeyingMaterial;
pub use dtls::OsslDtlsImpl;

pub use io_buf::DatagramSend;
use thiserror::Error;

/// Targeted MTU
pub(crate) const DATAGRAM_MTU: usize = 1150;

/// Warn if any packet we are about to send is above this size.
pub(crate) const DATAGRAM_MTU_WARN: usize = 1280;

/// Events arising from a [`Dtls`] instance.
pub enum DtlsEvent {
    /// When the DTLS has finished handshaking.
    Connected,

    /// Keying material for SRTP encryption master key and the selected SRTP profile.
    SrtpKeyingMaterial(KeyingMaterial, SrtpProfile),

    /// The fingerprint of the remote peer.
    ///
    /// This should be checked against the fingerprint communicated in the SDP.
    RemoteFingerprint(Fingerprint),

    /// Decrypted data from incoming DTLS traffic.
    Data(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    Aes128CmSha1_80,
    AeadAes128Gcm,
}

#[allow(dead_code)]
impl SrtpProfile {
    // All the profiles we support, ordered from most preferred to least.
    pub(crate) const ALL: &'static [SrtpProfile] =
        &[SrtpProfile::AeadAes128Gcm, SrtpProfile::Aes128CmSha1_80];

    /// The length of keying material to extract from the DTLS session in bytes.
    #[rustfmt::skip]
    pub(crate) fn keying_material_len(&self) -> usize {
        match self {
             // MASTER_KEY_LEN * 2 + MASTER_SALT * 2
             // TODO: This is a duplication of info that is held in srtp.rs, because we
             // don't want a dependency in that direction.
            SrtpProfile::Aes128CmSha1_80 => 16 * 2 + 14 * 2,
            SrtpProfile::AeadAes128Gcm   => 16 * 2 + 12 * 2,
        }
    }

    /// What this profile is called in OpenSSL parlance.
    pub(crate) fn openssl_name(&self) -> &'static str {
        match self {
            SrtpProfile::Aes128CmSha1_80 => "SRTP_AES128_CM_SHA1_80",
            SrtpProfile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
        }
    }
}
