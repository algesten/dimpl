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
//!   - `ECDHE_RSA_AES256_GCM_SHA384`
//!   - `ECDHE_RSA_AES128_GCM_SHA256`
//!   - `DHE_RSA_AES256_GCM_SHA384`
//!   - `DHE_RSA_AES128_GCM_SHA256`
//! - **AEAD**: AES‑GCM 128/256 only (no CBC/EtM modes).
//! - **Key exchange**: ECDHE (P‑256/P‑384) and FFDHE (≥2048 bit) for DHE suites.
//! - **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384, RSA‑PKCS1v1.5 with SHA‑256/384.
//! - **DTLS‑SRTP**: Exports keying material for `SRTP_AEAD_AES_256_GCM`,
//!   `SRTP_AEAD_AES_128_GCM`, and `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).
//! - **Extended Master Secret** ([RFC 7627]) is negotiated and enforced.
//! - Not supported: PSK cipher suites.
//!
//! ## Certificate model
//! You provide a certificate verifier via [`CertVerifier`]. The crate verifies
//! handshake signatures against the peer's certificate; PKI policy (chain,
//! name, EKU, pinning) is enforced by your verifier.
//!
//! ## Sans‑IO integration model
//! Drive the engine with three calls:
//! - [`Dtls::handle_packet`] — feed an entire received UDP datagram.
//! - [`Dtls::poll_output`] — drain pending output: DTLS records, timers, events.
//! - [`Dtls::handle_timeout`] — trigger retransmissions/time‑based progress.
//!
//! The output is an [`Output`] enum with:
//! - `Packet(&[u8])`: send on your UDP socket
//! - `Timeout(Instant)`: schedule a timer and call `handle_timeout` at/after it
//! - `Connected`: handshake complete
//! - `PeerCert(Vec<u8>)`: peer leaf certificate (DER)
//! - `KeyingMaterial(KeyingMaterial, SrtpProfile)`: DTLS‑SRTP export
//! - `ApplicationData(Vec<u8>)`: plaintext received from peer
//!
//! # Example (Sans‑IO loop)
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Instant;
//!
//! use dimpl::{certificate, CertVerifier, Config, Dtls, Output};
//!
//! // Minimal certificate verifier (application policy goes here)
//! struct AcceptAll;
//! impl CertVerifier for AcceptAll {
//!     fn verify_certificate(&self, _der: &[u8]) -> Result<(), String> { Ok(()) }
//! }
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
//!         loop {
//!             match dtls.poll_output() {
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
//!     let now = Instant::now();
//!     let cert = certificate::generate_self_signed_certificate().unwrap();
//!     let cfg = Arc::new(Config::default());
//!     let mut dtls = Dtls::new(now, cfg,
//!         cert.certificate,
//!         cert.private_key,
//!         Box::new(AcceptAll)
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
//! Rust 1.71.1.
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
//       ClientHello                  -------->
//
//                                    <--------   HelloVerifyRequest
//                                                 (contains cookie)
//
//       ClientHello                  -------->
//       (with cookie)
//                                                       ServerHello
//                                                      Certificate*
//                                                ServerKeyExchange*
//                                               CertificateRequest*
//                                    <--------      ServerHelloDone
//       Certificate*
//       ClientKeyExchange
//       CertificateVerify*
//       [ChangeCipherSpec]
//       Finished                     -------->
//                                                [ChangeCipherSpec]
//                                    <--------             Finished
//       Application Data             <------->     Application Data

#[macro_use]
extern crate log;

use std::sync::Arc;
use std::time::Instant;

mod client;
use client::Client;

mod server;
use server::Server;

mod message;
pub use message::{CipherSuite, SignatureAlgorithm};

mod time_tricks;

mod buffer;
mod crypto;
pub use crypto::CertVerifier;
mod engine;
mod incoming;
mod window;

mod util;

mod error;
pub use error::Error;

mod config;
pub use config::Config;

pub mod certificate;

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
    /// The instance is initialized with the provided `now`, `config`,
    /// certificate, private key, and certificate verifier.
    pub fn new(
        now: Instant,
        config: Arc<Config>,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
    ) -> Self {
        let inner = Inner::Server(Server::new(
            now,
            config,
            certificate,
            private_key,
            cert_verifier,
        ));
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
    pub fn poll_output(&mut self) -> Output {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.poll_output(),
            Inner::Server(server) => server.poll_output(),
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
    PeerCert(Vec<u8>),
    /// Extracted DTLS-SRTP keying material and selected SRTP profile.
    KeyingMaterial(KeyingMaterial, SrtpProfile),
    /// Received application data plaintext.
    ApplicationData(Vec<u8>),
}

#[cfg(test)]
mod test {
    use crate::certificate::generate_self_signed_certificate;

    use super::*;

    #[test]
    fn test_dtls_default() {
        let client_cert =
            generate_self_signed_certificate().expect("Failed to generate client cert");

        // Initialize client
        let now = Instant::now();
        let config = Arc::new(Config::default());

        // Simple certificate verifier that accepts any certificate
        struct DummyVerifier;
        impl CertVerifier for DummyVerifier {
            fn verify_certificate(&self, _der: &[u8]) -> Result<(), String> {
                Ok(())
            }
        }

        let mut dtls = Dtls::new(
            now,
            config,
            client_cert.certificate,
            client_cert.private_key,
            Box::new(DummyVerifier),
        );

        assert!(!dtls.is_active());
        dtls.set_active(true);
        assert!(dtls.is_active());
        dtls.set_active(false);
    }
}
