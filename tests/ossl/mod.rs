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

pub use cert::{DtlsCertOptions, DtlsPKeyType, Fingerprint, OsslDtlsCert};

mod io_buf;
mod stream;

mod dtls;
use dimpl::{KeyingMaterial, SrtpProfile};
pub use dtls::{dtls_ssl_create, OsslDtlsImpl};

pub use io_buf::DatagramSend;
use std::collections::VecDeque;
use thiserror::Error;

/// Targeted MTU
pub(crate) const DATAGRAM_MTU: usize = 1150;

/// Warn if any packet we are about to send is above this size.
pub(crate) const DATAGRAM_MTU_WARN: usize = 1280;

/// Events arising from a [`Dtls`] instance.
#[derive(Debug)]
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
