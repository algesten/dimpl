//! Local events for DTLS state machines.
//!
//! This module contains the `LocalEvent` enum used by both DTLS 1.2 and DTLS 1.3
//! client/server state machines to queue events for delivery via `poll_output`.

use arrayvec::ArrayVec;

use crate::buffer::Buf;
use crate::{KeyingMaterial, Output, SrtpProfile};

/// Events queued by the DTLS state machine for delivery to the application.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LocalEvent {
    /// Peer certificate is available for inspection.
    PeerCert,
    /// DTLS handshake completed successfully.
    Connected,
    /// Keying material exported for SRTP.
    KeyingMaterial(ArrayVec<u8, 88>, SrtpProfile),
}

impl LocalEvent {
    /// Convert this event into an `Output` for delivery to the application.
    ///
    /// * `buf` - Buffer to copy certificate or keying material into.
    /// * `peer_certs` - Peer certificates received during handshake.
    pub(crate) fn into_output<'a>(self, buf: &'a mut [u8], peer_certs: &[Buf]) -> Output<'a> {
        match self {
            LocalEvent::PeerCert => {
                if !peer_certs.is_empty() {
                    let l = peer_certs[0].len();
                    assert!(l <= buf.len(), "Buffer too small for peer certificate");
                    buf[..l].copy_from_slice(&peer_certs[0]);
                    Output::PeerCert(&buf[..l])
                } else {
                    // No certificate available, just signal connected
                    Output::Connected
                }
            }
            LocalEvent::Connected => Output::Connected,
            LocalEvent::KeyingMaterial(km, profile) => {
                Output::KeyingMaterial(KeyingMaterial::new(&km), profile)
            }
        }
    }
}
