//! dimpl — DTLS 1.2 and 1.3 implementation (Sans‑IO, Sync)
//!
//! dimpl is a DTLS 1.2 and 1.3 implementation aimed at WebRTC. It is a Sans‑IO
//! state machine you embed into your own UDP/RTC event loop: you feed incoming
//! datagrams, poll for outgoing records or timers, and wire up certificate
//! verification and SRTP key export yourself.
//!
//! # Goals
//! - **DTLS 1.2 and 1.3**: Implements the DTLS handshake and record layer used by WebRTC.
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
//! ## Version selection
//!
//! Three constructors control which DTLS version is used:
//! - [`Dtls::new_12`] — explicit DTLS 1.2
//! - [`Dtls::new_13`] — explicit DTLS 1.3
//! - [`Dtls::new_auto`] — auto‑sense: the first incoming ClientHello determines
//!   the version (based on the `supported_versions` extension)
//!
//! # Cryptography surface
//! - **Cipher suites (TLS 1.2 over DTLS)**
//!   - `ECDHE_ECDSA_AES256_GCM_SHA384`
//!   - `ECDHE_ECDSA_AES128_GCM_SHA256`
//! - **Cipher suites (TLS 1.3 over DTLS)**
//!   - `TLS_AES_128_GCM_SHA256`
//!   - `TLS_AES_256_GCM_SHA384`
//! - **AEAD**: AES‑GCM 128/256 only (no CBC/EtM modes).
//! - **Key exchange**: ECDHE (P‑256/P‑384)
//! - **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384
//! - **DTLS‑SRTP**: Exports keying material for `SRTP_AEAD_AES_256_GCM`,
//!   `SRTP_AEAD_AES_128_GCM`, and `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).
//! - **Extended Master Secret** ([RFC 7627]) is negotiated and enforced (DTLS 1.2).
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
//! # #[cfg(feature = "rcgen")]
//! # {
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
//!     let mut dtls = Dtls::new_12(cfg, cert, Instant::now());
//!     dtls.set_active(true); // client role
//!     dtls
//! }
//!
//! // Putting it together
//! let dtls = mk_dtls_client();
//! let _ = example_event_loop(dtls);
//! # }
//! ```
//!
//! ### MSRV
//! Rust 1.81.0
//!
//! ### Status
//! - Session resumption is not implemented (WebRTC does a full handshake on ICE restart).
//! - Renegotiation is not implemented (WebRTC does full restart).
//!
//! [RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
//! [RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
//! [RFC 7627]: https://www.rfc-editor.org/rfc/rfc7627
//!
//! [`Dtls::handle_packet`]: Dtls::handle_packet
//! [`Dtls::poll_output`]: Dtls::poll_output
//! [`Dtls::handle_timeout`]: Dtls::handle_timeout
//!
#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(unknown_lints)]
#![deny(missing_docs)]

#[macro_use]
extern crate log;

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

// Shared types used by both DTLS versions
mod types;
pub use types::{
    CompressionMethod, ContentType, HashAlgorithm, NamedGroup, ProtocolVersion, Sequence,
    SignatureAlgorithm,
};

// DTLS version-specific modules
mod dtls12;
mod dtls13;

use dtls12::{Client as Client12, Server as Server12};
use dtls13::{Client as Client13, Server as Server13};

use detect::{ClientPending, ServerPending};

mod detect;
mod time_tricks;

pub(crate) mod buffer;
mod window;

mod util;

mod error;
pub use error::Error;

mod config;
pub use config::Config;

#[cfg(feature = "rcgen")]
pub mod certificate;

pub mod crypto;

pub use crypto::{KeyingMaterial, SrtpProfile};

mod timer;

mod rng;
pub(crate) use rng::SeededRng;

/// Certificate and private key pair.
#[derive(Clone)]
pub struct DtlsCertificate {
    /// Certificate in DER format.
    pub certificate: Vec<u8>,
    /// Private key in DER format.
    pub private_key: Vec<u8>,
}

impl std::fmt::Debug for DtlsCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsCertificate")
            .field("certificate", &self.certificate.len())
            .field("private_key", &self.private_key.len())
            .finish()
    }
}

/// Sans-IO DTLS endpoint (client or server).
///
/// New instances start in the **server role**. Call
/// [`set_active(true)`](Self::set_active) to switch to client before
/// the handshake begins.
///
/// Drive the state machine with [`handle_packet`](Self::handle_packet),
/// [`poll_output`](Self::poll_output), and
/// [`handle_timeout`](Self::handle_timeout).
pub struct Dtls {
    inner: Option<Inner>,
}

enum Inner {
    Client12(Client12),
    Server12(Server12),
    Client13(Client13),
    Server13(Server13),
    ServerPending(ServerPending),
    ClientPending(ClientPending),
}

impl Dtls {
    /// Create a new DTLS 1.2 instance in the server role.
    ///
    /// Call [`set_active(true)`](Self::set_active) to switch to client
    /// before the handshake begins. The `now` parameter seeds the internal
    /// time tracking for timeouts and retransmissions.
    ///
    /// During the handshake, the peer's leaf certificate is surfaced via
    /// [`Output::PeerCert`]. It is up to the application to validate that
    /// certificate according to its security policy.
    pub fn new_12(config: Arc<Config>, certificate: DtlsCertificate, now: Instant) -> Self {
        let inner = Inner::Server12(Server12::new(config, certificate, now));
        Dtls { inner: Some(inner) }
    }

    /// Create a new DTLS 1.3 instance in the server role.
    ///
    /// Call [`set_active(true)`](Self::set_active) to switch to client
    /// before the handshake begins.
    ///
    /// During the handshake, the peer's leaf certificate is surfaced via
    /// [`Output::PeerCert`]. It is up to the application to validate that
    /// certificate according to its security policy.
    pub fn new_13(config: Arc<Config>, certificate: DtlsCertificate, now: Instant) -> Self {
        let inner = Inner::Server13(Server13::new(config, certificate, now));
        Dtls { inner: Some(inner) }
    }

    /// Create a new DTLS instance that auto‑senses the version.
    ///
    /// **Server role** (default): the instance stays in a pending state.
    /// When the first ClientHello arrives it inspects the
    /// `supported_versions` extension and creates either a DTLS 1.2 or
    /// 1.3 server.
    ///
    /// **Client role** ([`set_active(true)`](Self::set_active)): the
    /// instance sends a hybrid ClientHello compatible with both DTLS 1.2
    /// and 1.3 servers and forks into the correct handshake once the
    /// server responds.
    pub fn new_auto(config: Arc<Config>, certificate: DtlsCertificate, now: Instant) -> Self {
        let inner = Inner::ServerPending(ServerPending::new(config, certificate, now));
        Dtls { inner: Some(inner) }
    }

    /// Return true if the instance is operating in the client role.
    pub fn is_active(&self) -> bool {
        matches!(
            self.inner,
            Some(Inner::Client12(_) | Inner::Client13(_) | Inner::ClientPending(_))
        )
    }

    /// Switch between server and client roles.
    ///
    /// Set `active` to true for client role, false for server role.
    ///
    /// When called on an auto‑sense instance ([`Dtls::new_auto`]) the
    /// client sends a hybrid ClientHello compatible with both DTLS 1.2
    /// and 1.3. The version is determined from the server's first
    /// response.
    pub fn set_active(&mut self, active: bool) {
        match (self.is_active(), active) {
            (true, false) => {
                let inner = self.inner.take().unwrap();
                match inner {
                    Inner::Client12(c) => {
                        self.inner = Some(Inner::Server12(c.into_server()));
                    }
                    Inner::Client13(c) => {
                        self.inner = Some(Inner::Server13(c.into_server()));
                    }
                    Inner::ClientPending(_) => {
                        panic!("cannot switch auto-sense client back to server: version unknown");
                    }
                    _ => unreachable!(),
                }
            }
            (false, true) => {
                let inner = self.inner.take().unwrap();
                match inner {
                    Inner::Server12(s) => {
                        self.inner = Some(Inner::Client12(s.into_client()));
                    }
                    Inner::Server13(s) => {
                        self.inner = Some(Inner::Client13(s.into_client()));
                    }
                    Inner::ServerPending(sp) => {
                        let (config, certificate, now) = sp.into_parts();
                        // unwrap: ClientPending::new only fails on missing kx groups
                        let cp = ClientPending::new(config, certificate, now)
                            .expect("failed to build hybrid ClientHello");
                        self.inner = Some(Inner::ClientPending(cp));
                    }
                    _ => unreachable!(),
                }
            }
            _ => {}
        }
    }

    /// Process an incoming DTLS datagram.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        // Auto-sense server: resolve version on first ClientHello
        if matches!(self.inner, Some(Inner::ServerPending(_))) {
            let inner = self.inner.take().unwrap();
            let Inner::ServerPending(sp) = inner else {
                unreachable!()
            };
            let (config, certificate, now) = sp.into_parts();

            let is_13 = matches!(
                detect::client_hello_version(packet),
                detect::DetectedVersion::Dtls13
            );
            let resolved = if is_13 {
                let mut server = Server13::new(config, certificate, now);
                server.handle_timeout(now)?;
                Inner::Server13(server)
            } else {
                let mut server = Server12::new(config, certificate, now);
                server.handle_timeout(now)?;
                Inner::Server12(server)
            };
            self.inner = Some(resolved);
        }

        // Auto-sense client: resolve version on first server response
        if matches!(self.inner, Some(Inner::ClientPending(_))) {
            let version = detect::server_hello_version(packet);
            let inner = self.inner.take().unwrap();
            let Inner::ClientPending(cp) = inner else {
                unreachable!()
            };
            let (hybrid, config, certificate, now) = cp.into_parts();
            match version {
                detect::DetectedVersion::Dtls12 => {
                    let mut client12 = Client12::new_from_hybrid(
                        hybrid.random,
                        &hybrid.handshake_fragment,
                        config,
                        certificate,
                        now,
                    );
                    // Feed the HVR to Client12 — it enters
                    // AwaitHelloVerifyRequest and processes the cookie.
                    client12.handle_packet(packet)?;
                    self.inner = Some(Inner::Client12(client12));
                    return Ok(());
                }
                detect::DetectedVersion::Dtls13 | detect::DetectedVersion::Unknown => {
                    let mut client13 = Client13::new_from_hybrid(hybrid, config, certificate, now);
                    client13.handle_packet(packet)?;
                    self.inner = Some(Inner::Client13(client13));
                    return Ok(());
                }
            }
        }

        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.handle_packet(packet),
            Inner::Server12(server) => server.handle_packet(packet),
            Inner::Client13(client) => client.handle_packet(packet),
            Inner::Server13(server) => server.handle_packet(packet),
            Inner::ServerPending(_) | Inner::ClientPending(_) => unreachable!(),
        }
    }

    /// Poll for pending output from the DTLS engine.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.poll_output(buf),
            Inner::Server12(server) => server.poll_output(buf),
            Inner::Client13(client) => client.poll_output(buf),
            Inner::Server13(server) => server.poll_output(buf),
            Inner::ServerPending(sp) => sp.poll_output(buf),
            Inner::ClientPending(cp) => cp.poll_output(buf),
        }
    }

    /// Handle time-based events such as retransmission timers.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.handle_timeout(now),
            Inner::Server12(server) => server.handle_timeout(now),
            Inner::Client13(client) => client.handle_timeout(now),
            Inner::Server13(server) => server.handle_timeout(now),
            Inner::ServerPending(sp) => {
                sp.handle_timeout(now);
                Ok(())
            }
            Inner::ClientPending(cp) => cp.handle_timeout(now),
        }
    }

    /// Send application data over the established DTLS session.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.send_application_data(data),
            Inner::Server12(server) => server.send_application_data(data),
            Inner::Client13(client) => client.send_application_data(data),
            Inner::Server13(server) => server.send_application_data(data),
            Inner::ServerPending(_) => Err(Error::UnexpectedMessage(
                "cannot send application data: handshake not started".to_string(),
            )),
            Inner::ClientPending(_) => Err(Error::UnexpectedMessage(
                "cannot send application data: handshake not complete".to_string(),
            )),
        }
    }
}

impl fmt::Debug for Dtls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (role, state) = match &self.inner {
            Some(Inner::Client12(c)) => ("Client12", c.state_name()),
            Some(Inner::Server12(s)) => ("Server12", s.state_name()),
            Some(Inner::Client13(c)) => ("Client13", c.state_name()),
            Some(Inner::Server13(s)) => ("Server13", s.state_name()),
            Some(Inner::ServerPending(_)) => ("ServerPending", ""),
            Some(Inner::ClientPending(_)) => ("ClientPending", ""),
            None => ("None", ""),
        };
        f.debug_struct("Dtls")
            .field("role", &role)
            .field("state", &state)
            .finish()
    }
}

/// Output events produced by the DTLS engine when polled.
pub enum Output<'a> {
    /// A DTLS record to transmit on the wire.
    Packet(&'a [u8]),
    /// Schedule a timer and call [`Dtls::handle_timeout`] at this instant.
    ///
    /// This is always the last variant returned by a poll cycle.
    /// Internal state is only consistent after reaching `Timeout`.
    Timeout(Instant),
    /// The handshake completed and the connection is established.
    Connected,
    /// The peer's leaf certificate in DER encoding.
    ///
    /// Applications must validate this certificate independently (chain,
    /// name/EKU checks, pinning, etc.).
    PeerCert(&'a [u8]),
    /// Extracted DTLS-SRTP keying material and selected SRTP profile.
    KeyingMaterial(KeyingMaterial, SrtpProfile),
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
#[cfg(feature = "rcgen")]
mod test {
    use std::panic::UnwindSafe;

    use crate::certificate::generate_self_signed_certificate;

    use super::*;

    fn new_instance() -> Dtls {
        let client_cert =
            generate_self_signed_certificate().expect("Failed to generate client cert");
        let config = Arc::new(Config::default());
        Dtls::new_12(config, client_cert, Instant::now())
    }

    fn new_instance_13() -> Dtls {
        let cert = generate_self_signed_certificate().expect("Failed to generate cert");
        let config = Arc::new(Config::default());
        Dtls::new_13(config, cert, Instant::now())
    }

    fn new_instance_auto() -> Dtls {
        let cert = generate_self_signed_certificate().expect("Failed to generate cert");
        let config = Arc::new(Config::default());
        Dtls::new_auto(config, cert, Instant::now())
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
    fn test_dtls13_default() {
        let mut dtls = new_instance_13();
        assert!(!dtls.is_active());
        dtls.set_active(true);
        assert!(dtls.is_active());
        dtls.set_active(false);
    }

    #[test]
    fn test_auto_sense_set_active_creates_client_pending() {
        let mut dtls = new_instance_auto();
        assert!(!dtls.is_active());
        dtls.set_active(true);
        assert!(dtls.is_active());
        assert!(matches!(dtls.inner, Some(Inner::ClientPending(_))));
    }

    #[test]
    fn test_auto_sense_client_sends_hybrid_ch() {
        let mut dtls = new_instance_auto();
        dtls.set_active(true);
        let now = Instant::now();
        dtls.handle_timeout(now).unwrap();
        let output = &mut [0u8; 2048];
        // First poll returns the hybrid ClientHello packet
        let result = dtls.poll_output(output);
        assert!(matches!(result, Output::Packet(_)));
        // Second poll returns Timeout
        let result = dtls.poll_output(output);
        assert!(matches!(result, Output::Timeout(_)));
    }

    #[test]
    fn is_send() {
        fn is_send<T: Send>(_t: T) {}
        fn is_sync<T: Sync>(_t: T) {}
        is_send(new_instance());
        is_sync(new_instance());
        is_send(new_instance_13());
        is_sync(new_instance_13());
        is_send(new_instance_auto());
        is_sync(new_instance_auto());
    }

    #[test]
    fn is_unwind_safe() {
        fn is_unwind_safe<T: UnwindSafe>(_t: T) {}
        is_unwind_safe(new_instance());
        is_unwind_safe(new_instance_13());
        is_unwind_safe(new_instance_auto());
    }
}
