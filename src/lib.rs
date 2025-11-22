//! dimpl — DTLS 1.2 implementation (Sans‑IO, Sync)
//!
//! dimpl is a focused DTLS 1.2 implementation aimed at WebRTC. It is a Sans‑IO
//! state machine you embed into your own UDP/RTC event loop: you feed incoming
//! datagrams, poll for outgoing records or timers, and wire up certificate
//! verification and SRTP key export yourself.
//!
//! # Goals
//! - **DTLS 1.2**: Implements the DTLS 1.2 handshake and record layer used by WebRTC.
//! - **Safety**: `forbid(unsafe_code)` throughout the crate.
//! - **Minimal Rust‑only deps**: Uses small, well‑maintained Rust crypto crates.
//! - **Low overhead**: Tight control over allocations and buffers; Sans‑IO integration.
//!
//! ## Non‑goals
//! - **DTLS 1.0**
//! - **Async** (the crate is Sans‑IO and event‑loop agnostic)
//! - **no_std** (at least not without allocation)
//! - **RSA**
//! - **DHE**
//!
//! ## Regarding DTLS 1.3 and the future of this crate
//!
//! dimpl was built as a support package for [str0m](https://github.com/algesten/str0m),
//! with WebRTC as its primary use case, which currently uses DTLS 1.2. The author
//! is not a cryptography expert; however, our understanding is that DTLS 1.2 is acceptable
//! provided we narrow the protocol's scope—for example, by supporting only specific
//! cipher suites and hash algorithms and by requiring the Extended Master Secret extension.
//!
//! If you are interested in extending this crate to support DTLS 1.3 and/or additional
//! cipher suites or hash algorithms, we welcome collaboration, but we are not planning
//! to lead such initiatives.
//!
//! # Cryptography surface
//! - **Cipher suites (TLS 1.2 over DTLS)**
//!   - `ECDHE_ECDSA_AES256_GCM_SHA384`
//!   - `ECDHE_ECDSA_AES128_GCM_SHA256`
//! - **AEAD**: AES‑GCM 128/256 only (no CBC/EtM modes).
//! - **Key exchange**: ECDHE (P‑256/P‑384)
//! - **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384
//! - **DTLS‑SRTP**: Exports keying material for `SRTP_AEAD_AES_256_GCM`,
//!   `SRTP_AEAD_AES_128_GCM`, and `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).
//! - **Extended Master Secret** ([RFC 7627]) is negotiated and enforced.
//! - Not supported: PSK cipher suites.
//!
//! ## Certificate model
//! During the handshake the engine emits [`Output::PeerCert`] with the peer's
//! leaf certificate (DER). The crate uses that certificate to verify DTLS
//! handshake messages, but it does not perform any PKI validation. Your
//! application is responsible for validating the peer certificate according to
//! your policy (fingerprint, chain building, name/EKU checks, pinning, etc.).
//!
//! ## Sans‑IO integration model
//! Drive the engine with three calls:
//! - [`Dtls::handle_packet`] — feed an entire received UDP datagram.
//! - [`Dtls::poll_output`] — drain pending output: DTLS records, timers, events.
//! - [`Dtls::handle_timeout`] — trigger retransmissions/time‑based progress.
//!
//! The output is an [`Output`] enum with borrowed references into your provided buffer:
//! - `Packet(&[u8])`: send on your UDP socket
//! - `Timeout(Instant)`: schedule a timer and call `handle_timeout` at/after it
//! - `Connected`: handshake complete
//! - `PeerCert(&[u8])`: peer leaf certificate (DER) — validate in your app
//! - `KeyingMaterial(KeyingMaterial, SrtpProfile)`: DTLS‑SRTP export
//! - `ApplicationData(&[u8])`: plaintext received from peer
//!
//! # Example (Sans‑IO loop)
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Instant;
//!
//! use dimpl::{certificate, Config, Dtls, Output};
//!
//! // Stub I/O to keep the example focused on the state machine
//! enum Event { Udp(Vec<u8>), Timer(Instant) }
//! fn wait_next_event(_next_wake: Option<Instant>) -> Event { Event::Udp(Vec::new()) }
//! fn send_udp(_bytes: &[u8]) {}
//!
//! fn example_event_loop(mut dtls: Dtls) -> Result<(), dimpl::Error> {
//!     let mut next_wake: Option<Instant> = None;
//!     loop {
//!         // Drain engine output until we have to wait for I/O or a timer
//!         let mut out_buf = vec![0u8; 2048];
//!         loop {
//!             match dtls.poll_output(&mut out_buf) {
//!                 Output::Packet(p) => send_udp(p),
//!                 Output::Timeout(t) => { next_wake = Some(t); break; }
//!                 Output::Connected => {
//!                     // DTLS established — application may start sending
//!                 }
//!                 Output::PeerCert(_der) => {
//!                     // Inspect peer leaf certificate if desired
//!                 }
//!                 Output::KeyingMaterial(_km, _profile) => {
//!                     // Provide to SRTP stack
//!                 }
//!                 Output::ApplicationData(_data) => {
//!                     // Deliver plaintext to application
//!                 }
//!             }
//!         }
//!
//!         // Block waiting for either UDP input or the scheduled timeout
//!         match wait_next_event(next_wake) {
//!             Event::Udp(pkt) => dtls.handle_packet(&pkt)?,
//!             Event::Timer(now) => dtls.handle_timeout(now)?,
//!         }
//!     }
//! }
//!
//! fn mk_dtls_client() -> Dtls {
//!     let cert = certificate::generate_self_signed_certificate().unwrap();
//!     let cfg = Arc::new(Config::default());
//!     let mut dtls = Dtls::new(
//!         cfg,
//!         cert.certificate,
//!         cert.private_key,
//!     );
//!     dtls.set_active(true); // client role
//!     dtls
//! }
//!
//! // Putting it together
//! let dtls = mk_dtls_client();
//! let _ = example_event_loop(dtls);
//! ```
//!
//! ### MSRV
//! Rust 1.81.0
//!
//! ### Status
//! - Session resumption is not implemented (WebRTC does a full handshake on ICE restart).
//! - Renegotiation is not implemented (WebRTC does full restart).
//! - Only DTLS 1.2 is accepted/advertised.
//!
//! [RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
//! [RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
//! [RFC 7627]: https://www.rfc-editor.org/rfc/rfc7627
//!
//! [`Dtls::handle_packet`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.handle_packet
//! [`Dtls::poll_output`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.poll_output
//! [`Dtls::handle_timeout`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.handle_timeout
//! [`Output`]: https://docs.rs/dimpl/0.1.0/dimpl/enum.Output.html
//! [`Output::PeerCert`]: https://docs.rs/dimpl/0.1.0/dimpl/enum.Output.html#variant.PeerCert
//!
#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
#![allow(mismatched_lifetime_syntaxes)]
#![allow(clippy::len_without_is_empty)]
#![deny(missing_docs)]

// This is the full DTLS 1.2 handshake flow
//
// Client                                               Server
//
// 1     ClientHello                  -------->
//
// 2                                  <--------   HelloVerifyRequest
//                                                 (contains cookie)
//
// 3     ClientHello                  -------->
//       (with cookie)
// 4                                                     ServerHello
//                                                      Certificate*
//                                                ServerKeyExchange*
//                                               CertificateRequest*
//                                    <--------      ServerHelloDone
// 5     Certificate*
//       ClientKeyExchange
//       CertificateVerify*
//       [ChangeCipherSpec]
//       Finished                     -------->
// 6                                              [ChangeCipherSpec]
//                                    <--------             Finished
//       Application Data             <------->     Application Data

#[macro_use]
extern crate log;

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

mod client;
use client::Client;

mod server;
use server::Server;

mod message;

mod time_tricks;

pub mod buffer;
mod engine;
mod incoming;
mod window;

mod util;

mod error;
pub use error::Error;

mod config;
pub use config::Config;

pub mod certificate;
pub mod crypto;

pub use crypto::{KeyingMaterial, SrtpProfile};

mod timer;

/// Public DTLS endpoint wrapping either a client or server state.
///
/// Use the role helpers to query or switch between client and server modes
/// and drive the handshake and record processing.
pub struct Dtls {
    inner: Option<Inner>,
}

enum Inner {
    Client(Client),
    Server(Server),
}

impl Dtls {
    /// Create a new DTLS instance.
    ///
    /// The instance is initialized with the provided `config`,
    /// certificate and private key.
    ///
    /// During the handshake, the peer's leaf certificate is surfaced via
    /// [`Output::PeerCert`]. It is up to the application to validate that
    /// certificate according to its security policy.
    pub fn new(config: Arc<Config>, certificate: Vec<u8>, private_key: Vec<u8>) -> Self {
        let inner = Inner::Server(Server::new(config, certificate, private_key));
        Dtls { inner: Some(inner) }
    }

    /// Return true if the instance is operating in the client role.
    pub fn is_active(&self) -> bool {
        matches!(self.inner, Some(Inner::Client(_)))
    }

    /// Switch between server and client roles.
    ///
    /// Set `active` to true for client role, false for server role.
    pub fn set_active(&mut self, active: bool) {
        match (self.is_active(), active) {
            (true, false) => {
                let inner = self.inner.take().unwrap();
                let Inner::Client(inner) = inner else {
                    unreachable!();
                };
                self.inner = Some(Inner::Server(inner.into_server()));
            }
            (false, true) => {
                let inner = self.inner.take().unwrap();
                let Inner::Server(inner) = inner else {
                    unreachable!();
                };
                self.inner = Some(Inner::Client(inner.into_client()));
            }
            _ => {}
        }
    }

    /// Process an incoming DTLS datagram.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.handle_packet(packet),
            Inner::Server(server) => server.handle_packet(packet),
        }
    }

    /// Poll for pending output from the DTLS engine.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.poll_output(buf),
            Inner::Server(server) => server.poll_output(buf),
        }
    }

    /// Handle time-based events such as retransmission timers.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.handle_timeout(now),
            Inner::Server(server) => server.handle_timeout(now),
        }
    }

    /// Send application data over the established DTLS session.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.send_application_data(data),
            Inner::Server(server) => server.send_application_data(data),
        }
    }
}

/// Output events produced by the DTLS engine when polled.
pub enum Output<'a> {
    /// A DTLS record to transmit on the wire.
    Packet(&'a [u8]),
    /// A timeout instant for scheduling retransmission or handshake timers.
    Timeout(Instant),
    /// The handshake completed and the connection is established.
    Connected,
    /// The peer's leaf certificate in DER encoding.
    ///
    /// Applications must validate this certificate independently (chain,
    /// name/EKU checks, pinning, etc.).
    PeerCert(&'a [u8]),
    /// Extracted DTLS-SRTP keying material and selected SRTP profile.
    KeyingMaterial(KeyingMaterial<'a>, SrtpProfile),
    /// Received application data plaintext.
    ApplicationData(&'a [u8]),
}

impl fmt::Debug for Output<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(v) => write!(f, "Packet({})", v.len()),
            Self::Timeout(v) => write!(f, "Timeout({:?})", v),
            Self::Connected => write!(f, "Connected"),
            Self::PeerCert(v) => write!(f, "PeerCert({})", v.len()),
            Self::KeyingMaterial(v, p) => write!(f, "KeyingMaterial({}, {:?})", v.len(), p),
            Self::ApplicationData(v) => write!(f, "ApplicationData({})", v.len()),
        }
    }
}

#[cfg(test)]
mod test {
    use std::panic::UnwindSafe;

    use crate::certificate::generate_self_signed_certificate;

    use super::*;

    fn new_instance() -> Dtls {
        let client_cert =
            generate_self_signed_certificate().expect("Failed to generate client cert");

        // Initialize client
        let config = Arc::new(Config::default());

        Dtls::new(config, client_cert.certificate, client_cert.private_key)
    }

    #[test]
    fn test_dtls_default() {
        let mut dtls = new_instance();
        assert!(!dtls.is_active());
        dtls.set_active(true);
        assert!(dtls.is_active());
        dtls.set_active(false);
    }

    #[test]
    fn is_send() {
        fn is_send<T: Send>(_t: T) {}
        fn is_sync<T: Sync>(_t: T) {}
        is_send(new_instance());
        is_sync(new_instance());
    }

    #[test]
    fn is_unwind_safe() {
        fn is_unwind_safe<T: UnwindSafe>(_t: T) {}
        is_unwind_safe(new_instance());
    }
}
