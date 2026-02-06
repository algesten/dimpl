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
//!   - `TLS_CHACHA20_POLY1305_SHA256`
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
//! [`Dtls::handle_packet`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.handle_packet
//! [`Dtls::poll_output`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.poll_output
//! [`Dtls::handle_timeout`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.handle_timeout
//! [`Output`]: https://docs.rs/dimpl/0.1.0/dimpl/enum.Output.html
//! [`Output::PeerCert`]: https://docs.rs/dimpl/0.1.0/dimpl/enum.Output.html#variant.PeerCert
//!
#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(unknown_lints)]
#![deny(missing_docs)]

#[macro_use]
extern crate log;

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Public DTLS endpoint wrapping either a client or server state.
///
/// Use the role helpers to query or switch between client and server modes
/// and drive the handshake and record processing.
pub struct Dtls {
    inner: Option<Inner>,
}

enum Inner {
    Client12(Client12),
    Server12(Server12),
    Client13(Client13),
    Server13(Server13),
    ServerPending {
        config: Arc<Config>,
        certificate: DtlsCertificate,
        last_now: Option<Instant>,
    },
}

impl Dtls {
    /// Create a new DTLS 1.2 instance.
    ///
    /// The instance is initialized with the provided `config` and `certificate`
    /// and will use DTLS 1.2 exclusively. The `now` parameter seeds the internal
    /// time tracking for timeouts and retransmissions.
    ///
    /// During the handshake, the peer's leaf certificate is surfaced via
    /// [`Output::PeerCert`]. It is up to the application to validate that
    /// certificate according to its security policy.
    pub fn new_12(config: Arc<Config>, certificate: DtlsCertificate, now: Instant) -> Self {
        let inner = Inner::Server12(Server12::new(config, certificate, now));
        Dtls { inner: Some(inner) }
    }

    /// Create a new DTLS 1.3 instance.
    ///
    /// The instance is initialized with the provided `config` and `certificate`
    /// and will use DTLS 1.3 exclusively.
    ///
    /// During the handshake, the peer's leaf certificate is surfaced via
    /// [`Output::PeerCert`]. It is up to the application to validate that
    /// certificate according to its security policy.
    pub fn new_13(config: Arc<Config>, certificate: DtlsCertificate) -> Self {
        let inner = Inner::Server13(Server13::new(config, certificate));
        Dtls { inner: Some(inner) }
    }

    /// Create a new DTLS instance that auto‑senses the version.
    ///
    /// The instance starts in a pending state. When the first ClientHello
    /// arrives, it inspects the `supported_versions` extension and creates
    /// either a DTLS 1.2 or 1.3 server accordingly.
    ///
    /// This constructor is only useful for the server role. Calling
    /// [`set_active(true)`](Self::set_active) on an auto‑sense instance will
    /// panic because the version has not been determined yet.
    pub fn new_auto(config: Arc<Config>, certificate: DtlsCertificate) -> Self {
        let inner = Inner::ServerPending {
            config,
            certificate,
            last_now: None,
        };
        Dtls { inner: Some(inner) }
    }

    /// Return true if the instance is operating in the client role.
    pub fn is_active(&self) -> bool {
        matches!(self.inner, Some(Inner::Client12(_) | Inner::Client13(_)))
    }

    /// Switch between server and client roles.
    ///
    /// Set `active` to true for client role, false for server role.
    ///
    /// # Panics
    ///
    /// Panics if called with `active = true` on an auto‑sense instance
    /// ([`Dtls::new_auto`]) that has not yet received a packet, because the
    /// DTLS version is unknown.
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
                    Inner::ServerPending { .. } => {
                        panic!("cannot switch auto-sense server to client role: version unknown");
                    }
                    _ => unreachable!(),
                }
            }
            _ => {}
        }
    }

    /// Process an incoming DTLS datagram.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        // Auto-sense: resolve version on first packet
        if matches!(self.inner, Some(Inner::ServerPending { .. })) {
            let inner = self.inner.take().unwrap();
            let Inner::ServerPending {
                config,
                certificate,
                last_now,
            } = inner
            else {
                unreachable!()
            };

            // unwrap: handle_timeout must be called before handle_packet
            let now = last_now.expect("need handle_timeout before handle_packet");

            let resolved = if detect_dtls13_client_hello(packet) {
                let mut server = Server13::new(config, certificate);
                server.handle_timeout(now)?;
                Inner::Server13(server)
            } else {
                let mut server = Server12::new(config, certificate, now);
                server.handle_timeout(now)?;
                Inner::Server12(server)
            };
            self.inner = Some(resolved);
        }

        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.handle_packet(packet),
            Inner::Server12(server) => server.handle_packet(packet),
            Inner::Client13(client) => client.handle_packet(packet),
            Inner::Server13(server) => server.handle_packet(packet),
            Inner::ServerPending { .. } => unreachable!(),
        }
    }

    /// Poll for pending output from the DTLS engine.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.poll_output(buf),
            Inner::Server12(server) => server.poll_output(buf),
            Inner::Client13(client) => client.poll_output(buf),
            Inner::Server13(server) => server.poll_output(buf),
            Inner::ServerPending { last_now, .. } => {
                // unwrap: handle_timeout must be called before poll_output
                let now = last_now.expect("need handle_timeout before poll_output");
                Output::Timeout(now + Duration::from_secs(86400))
            }
        }
    }

    /// Handle time-based events such as retransmission timers.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.handle_timeout(now),
            Inner::Server12(server) => server.handle_timeout(now),
            Inner::Client13(client) => client.handle_timeout(now),
            Inner::Server13(server) => server.handle_timeout(now),
            Inner::ServerPending { last_now, .. } => {
                *last_now = Some(now);
                Ok(())
            }
        }
    }

    /// Initiate a KeyUpdate to rotate application traffic keys.
    ///
    /// Only supported for DTLS 1.3 connections that have completed the handshake.
    /// The peer will be requested to also rotate its keys.
    pub fn initiate_key_update(&mut self) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client13(client) => client.initiate_key_update(),
            Inner::Server13(server) => server.initiate_key_update(),
            Inner::Client12(_) | Inner::Server12(_) => Err(Error::UnexpectedMessage(
                "KeyUpdate is only supported in DTLS 1.3".to_string(),
            )),
            Inner::ServerPending { .. } => Err(Error::UnexpectedMessage(
                "Cannot initiate KeyUpdate: handshake not started".to_string(),
            )),
        }
    }

    /// Send application data over the established DTLS session.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.send_application_data(data),
            Inner::Server12(server) => server.send_application_data(data),
            Inner::Client13(client) => client.send_application_data(data),
            Inner::Server13(server) => server.send_application_data(data),
            Inner::ServerPending { .. } => Err(Error::UnexpectedMessage(
                "cannot send application data: handshake not started".to_string(),
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
            Some(Inner::ServerPending { .. }) => ("ServerPending", ""),
            None => ("None", ""),
        };
        f.debug_struct("Dtls")
            .field("role", &role)
            .field("state", &state)
            .finish()
    }
}

/// Detect whether a raw packet is a DTLS 1.3 ClientHello by scanning for the
/// `supported_versions` extension containing DTLS 1.3 (0xFEFC).
///
/// Returns `false` on any parse failure, defaulting to DTLS 1.2.
fn detect_dtls13_client_hello(packet: &[u8]) -> bool {
    detect_dtls13_client_hello_inner(packet).unwrap_or(false)
}

fn detect_dtls13_client_hello_inner(packet: &[u8]) -> Option<bool> {
    // Record header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13
    if packet.len() < 13 {
        return Some(false);
    }

    // content_type must be 0x16 (Handshake)
    if packet[0] != 0x16 {
        return Some(false);
    }

    let record_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
    let record_body = packet.get(13..13 + record_len)?;

    // Handshake header: msg_type(1) + length(3) + message_seq(2) +
    //   fragment_offset(3) + fragment_length(3) = 12
    if record_body.len() < 12 {
        return Some(false);
    }

    // msg_type must be 1 (ClientHello)
    if record_body[0] != 1 {
        return Some(false);
    }

    let fragment_len = ((record_body[9] as usize) << 16)
        | ((record_body[10] as usize) << 8)
        | (record_body[11] as usize);
    let body = record_body.get(12..12 + fragment_len)?;

    // ClientHello body:
    //   client_version(2) + random(32) = 34 minimum before session_id
    if body.len() < 34 {
        return Some(false);
    }
    let mut pos = 34;

    // session_id: 1-byte length + data
    let sid_len = *body.get(pos)? as usize;
    pos += 1 + sid_len;

    // cookie: 1-byte length + data
    let cookie_len = *body.get(pos)? as usize;
    pos += 1 + cookie_len;

    // cipher_suites: 2-byte length + data
    if pos + 2 > body.len() {
        return Some(false);
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression_methods: 1-byte length + data
    let cm_len = *body.get(pos)? as usize;
    pos += 1 + cm_len;

    // extensions: 2-byte total length
    if pos + 2 > body.len() {
        return Some(false);
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > body.len() {
        return Some(false);
    }

    // Walk extensions looking for supported_versions (0x002B)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x002B {
            // supported_versions client format: 1-byte list length, then 2-byte versions
            if ext_len < 1 {
                return Some(false);
            }
            let list_len = body[pos] as usize;
            let list_start = pos + 1;
            if list_start + list_len > pos + ext_len {
                return Some(false);
            }
            let mut i = list_start;
            while i + 2 <= list_start + list_len {
                let version = u16::from_be_bytes([body[i], body[i + 1]]);
                if version == 0xFEFC {
                    return Some(true);
                }
                i += 2;
            }
            return Some(false);
        }

        pos += ext_len;
    }

    Some(false)
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
        Dtls::new_13(config, cert)
    }

    fn new_instance_auto() -> Dtls {
        let cert = generate_self_signed_certificate().expect("Failed to generate cert");
        let config = Arc::new(Config::default());
        Dtls::new_auto(config, cert)
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
    #[should_panic(expected = "cannot switch auto-sense server to client role")]
    fn test_auto_sense_panics_on_set_active() {
        let mut dtls = new_instance_auto();
        dtls.set_active(true);
    }

    #[test]
    fn test_auto_sense_poll_output_returns_timeout() {
        let mut dtls = new_instance_auto();
        let now = Instant::now();
        dtls.handle_timeout(now).unwrap();
        let output = &mut [0u8; 2048];
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
