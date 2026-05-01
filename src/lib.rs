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
//! Four constructors control which DTLS version is used:
//! - [`Dtls::new_12`][new_12] — explicit DTLS 1.2 (certificate‑based)
//! - [`Dtls::new_12_psk`][new_12_psk] — explicit DTLS 1.2 (PSK, no certificates)
//! - [`Dtls::new_13`][new_13] — explicit DTLS 1.3
//! - [`Dtls::new_auto`][new_auto] — auto‑sense: the first
//!   incoming ClientHello determines the version (based on the
//!   `supported_versions` extension)
//!
//! # Cryptography surface
//! - **Cipher suites (TLS 1.2 over DTLS)**
//!   - `ECDHE_ECDSA_AES256_GCM_SHA384`
//!   - `ECDHE_ECDSA_AES128_GCM_SHA256`
//!   - `ECDHE_ECDSA_CHACHA20_POLY1305_SHA256`
//! - **PSK cipher suites (TLS 1.2 over DTLS)**
//!   - `PSK_AES128_CCM_8`
//! - **Cipher suites (TLS 1.3 over DTLS)**
//!   - `TLS_AES_128_GCM_SHA256`
//!   - `TLS_AES_256_GCM_SHA384`
//!   - `TLS_CHACHA20_POLY1305_SHA256`
//! - **AEAD**: AES‑GCM 128/256, ChaCha20‑Poly1305 (no CBC/EtM modes).
//! - **Key exchange**: ECDHE (P‑256/P‑384), X25519
//! - **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384
//! - **DTLS‑SRTP**: Exports keying material for `SRTP_AEAD_AES_256_GCM`,
//!   `SRTP_AEAD_AES_128_GCM`, and `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).
//! - **Extended Master Secret** ([RFC 7627]) is negotiated and enforced (DTLS 1.2).
//!
//! ## Certificate model
//! During the handshake the engine emits
//! [`Output::PeerCert`][peer_cert] with the peer's leaf
//! certificate (DER). The crate uses that certificate to verify DTLS
//! handshake messages, but it does not perform any PKI validation. Your
//! application is responsible for validating the peer certificate according to
//! your policy (fingerprint, chain building, name/EKU checks, pinning, etc.).
//!
//! ## Sans‑IO integration model
//! Drive the engine with three calls:
//! - [`Dtls::handle_packet`][handle_packet] — feed an entire
//!   received UDP datagram.
//! - [`Dtls::poll_output`][poll_output] — drain pending output:
//!   DTLS records, timers, events.
//! - [`Dtls::handle_timeout`][handle_timeout] — trigger
//!   retransmissions/time‑based progress.
//!
//! The output is an [`Output`][output] enum with borrowed
//! references into your provided buffer:
//! - `Packet(&[u8])`: send on your UDP socket
//! - `Timeout(Instant)`: schedule a timer and call `handle_timeout` at/after it
//! - `Connected`: handshake complete
//! - `PeerCert(&[u8])`: peer leaf certificate (DER) — validate in your app
//! - `KeyingMaterial(KeyingMaterial, SrtpProfile)`: DTLS‑SRTP export
//! - `ApplicationData(&[u8])`: plaintext received from peer
//! - `CloseNotify`: peer sent a graceful shutdown alert
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
//!                 Output::CloseNotify => {
//!                     // Peer initiated graceful shutdown
//!                 }
//!                 _ => {}
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
//! ## Example (PSK client)
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Instant;
//!
//! use dimpl::{Config, Dtls, PskResolver};
//!
//! struct MyPsk;
//!
//! impl PskResolver for MyPsk {
//!     fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
//!         if identity == b"device-01" {
//!             Some(b"shared-secret-key".to_vec())
//!         } else {
//!             None
//!         }
//!     }
//! }
//!
//! let config = Arc::new(
//!     Config::builder()
//!         .with_psk_client(b"device-01".to_vec(), Arc::new(MyPsk))
//!         .build()
//!         .unwrap(),
//! );
//!
//! let mut dtls = Dtls::new_12_psk(config, Instant::now());
//! dtls.set_active(true); // client role
//! ```
//!
//! ### MSRV
//! Rust 1.85.0
//!
//! ### Status
//! - Session resumption is not implemented (WebRTC does a full handshake on ICE restart).
//! - Renegotiation is not implemented (WebRTC does full restart).
//!
//! [new_12]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.new_12
//! [new_12_psk]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.new_12_psk
//! [new_13]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.new_13
//! [new_auto]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.new_auto
//! [peer_cert]: https://docs.rs/dimpl/latest/dimpl/enum.Output.html#variant.PeerCert
//! [handle_packet]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.handle_packet
//! [poll_output]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.poll_output
//! [handle_timeout]: https://docs.rs/dimpl/latest/dimpl/struct.Dtls.html#method.handle_timeout
//! [output]: https://docs.rs/dimpl/latest/dimpl/enum.Output.html
//! [RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
//! [RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
//! [RFC 7627]: https://www.rfc-editor.org/rfc/rfc7627
//!
#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(unknown_lints)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

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

use auto::ClientPending;

mod auto;
mod time_tricks;

pub(crate) mod buffer;
mod window;

mod util;

mod error;
pub use error::Error;

mod config;
pub use config::{Config, ConfigBuilder, Psk, PskResolver};

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

impl fmt::Debug for DtlsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    ClientPending(ClientPending),
}

fn is_dtls12_psk_only(config: &Config) -> bool {
    if config.dtls13_cipher_suites().next().is_some() {
        return false;
    }

    let mut suites = config.dtls12_cipher_suites().map(|cs| cs.suite());
    suites
        .next()
        .is_some_and(|first| first.is_psk() && suites.all(|s| s.is_psk()))
}

/// If `packet` is a Handshake record carrying a ClientHello, return the
/// inner handshake message bytes (msg_type + length + message_seq +
/// fragment_offset + fragment_length + body). Returns `None` for any
/// other content type, message type, or malformed framing.
///
/// Shared by [`looks_like_client_hello`] (structural check only) and
/// [`client_hello_wants_psk`] (which inspects cipher suites further).
fn client_hello_handshake(packet: &[u8]) -> Option<&[u8]> {
    // DTLS record header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13
    if packet.len() < 13 || packet[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
    let record_body = packet.get(13..13 + record_len)?;

    // Handshake header: msg_type(1) + length(3) + message_seq(2) +
    //   fragment_offset(3) + fragment_length(3) = 12
    if record_body.len() < 12 || record_body[0] != 0x01 {
        return None;
    }
    Some(record_body)
}

/// Lightweight structural check: does this packet look like a ClientHello?
///
/// Used by the auto-sense server to gate the DTLS 1.2 fallback on parse
/// errors. A packet that fails to parse in the DTLS 1.3 engine should
/// only trigger a downgrade if it at least claims to be a ClientHello —
/// otherwise random/garbage traffic could force fallback.
///
/// In addition to the record/handshake header check from
/// [`client_hello_handshake`], this validates wire-format integrity of
/// the handshake header (fragment fits inside the declared total length;
/// fragment bytes actually present in the record) and, for an
/// unfragmented CH, requires the declared length to be at least the
/// minimum a real DTLS 1.2 ClientHello can carry. A header-only fake
/// or a CH whose declared length cannot fit a valid 1.2 body fails the
/// check.
fn looks_like_client_hello(packet: &[u8]) -> bool {
    let Some(record_body) = client_hello_handshake(packet) else {
        return false;
    };

    // Handshake header (12 bytes already validated to be present):
    //   msg_type(1) + length(3) + message_seq(2) + fragment_offset(3) + fragment_length(3)
    let length = ((record_body[1] as usize) << 16)
        | ((record_body[2] as usize) << 8)
        | record_body[3] as usize;
    let frag_off = ((record_body[6] as usize) << 16)
        | ((record_body[7] as usize) << 8)
        | record_body[8] as usize;
    let frag_len = ((record_body[9] as usize) << 16)
        | ((record_body[10] as usize) << 8)
        | record_body[11] as usize;

    // Only the first fragment (offset 0) is allowed to trigger fallback.
    // A non-first fragment arriving alone could be a spoofed packet
    // designed to force a downgrade; a real fragmented CH always sends
    // a fragment with offset 0 too, and the clean Dtls12Fallback path
    // (driven by supported_versions, not by this gate) handles real
    // fragmented 1.2 CHs once reassembly completes.
    if frag_off != 0 {
        return false;
    }

    // Fragment must lie within the declared total CH length, and the
    // declared fragment bytes must actually be present in the record.
    if frag_len > length {
        return false;
    }
    if 12usize.saturating_add(frag_len) > record_body.len() {
        return false;
    }

    // Minimum DTLS 1.2 ClientHello body:
    //   version(2) + random(32) + sid_len(1) + cookie_len(1) +
    //   cipher_suites_len(2) + compression_methods_len(1) +
    //   compression_method(1) = 40 bytes (with empty sid/cookie/suites).
    // Use 41 to also require a single byte for at least one cipher suite
    // half — anything below this cannot be a real CH.
    const MIN_CH_BODY: usize = 41;
    let is_unfragmented = frag_len == length;
    if is_unfragmented && length < MIN_CH_BODY {
        return false;
    }

    true
}

/// Peek at a buffered DTLS 1.2 ClientHello to decide whether the auto-sense
/// server fallback should construct a PSK-mode Server12.
///
/// Walks the client's offered cipher suites in order and returns `true` iff
/// the first one allowed by `config` is a PSK suite. This mirrors the suite
/// selection inside `Server12` itself, so the chosen auth mode matches the
/// suite that `Server12` will pick once it reprocesses the ClientHello.
///
/// Returns `false` if `packet` is not a ClientHello or if parsing fails —
/// a fragmented ClientHello (fragment_offset > 0) is skipped and the next
/// buffered packet is tried by the caller.
fn client_hello_wants_psk(packet: &[u8], config: &Config) -> bool {
    use dtls12::message::Dtls12CipherSuite;

    let Some(record_body) = client_hello_handshake(packet) else {
        return false;
    };

    let frag_off =
        ((record_body[6] as u32) << 16) | ((record_body[7] as u32) << 8) | record_body[8] as u32;
    if frag_off != 0 {
        return false;
    }

    let frag_len = ((record_body[9] as usize) << 16)
        | ((record_body[10] as usize) << 8)
        | record_body[11] as usize;
    let Some(body) = record_body.get(12..12 + frag_len) else {
        return false;
    };

    // ClientHello body: client_version(2) + random(32) + session_id(var) +
    //   cookie(var) + cipher_suites(var) + ...
    let mut pos = 2 + 32;
    let Some(&sid_len) = body.get(pos) else {
        return false;
    };
    pos += 1 + sid_len as usize;
    let Some(&cookie_len) = body.get(pos) else {
        return false;
    };
    pos += 1 + cookie_len as usize;
    if pos + 2 > body.len() {
        return false;
    }
    let suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + suites_len > body.len() || suites_len % 2 != 0 {
        return false;
    }

    let allowed: Vec<_> = config.dtls12_cipher_suites().map(|cs| cs.suite()).collect();
    for chunk in body[pos..pos + suites_len].chunks_exact(2) {
        let suite = Dtls12CipherSuite::from_u16(u16::from_be_bytes([chunk[0], chunk[1]]));
        if allowed.contains(&suite) {
            return suite.is_psk();
        }
    }
    false
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

    /// Create a new DTLS 1.2 PSK-only instance (no certificate).
    ///
    /// Call [`set_active(true)`](Self::set_active) to switch to client
    /// before the handshake begins. The `config` must have a
    /// [`PskResolver`] configured, and for clients a PSK identity
    /// via [`ConfigBuilder::with_psk_client`](ConfigBuilder).
    ///
    /// Panics if `config` has no PSK configured. Without PSK data the
    /// PSK suite filter would leave zero negotiable suites, so failing
    /// fast at construction is preferable to a late handshake error.
    pub fn new_12_psk(config: Arc<Config>, now: Instant) -> Self {
        assert!(
            config.psk().is_some(),
            "Dtls::new_12_psk requires a PSK configuration; \
             set one via ConfigBuilder::with_psk_client or with_psk_server"
        );
        let inner = Inner::Server12(Server12::new_psk(config, now));
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
    /// **Server role** (default): starts as a DTLS 1.3 server. If the
    /// peer's ClientHello does not offer DTLS 1.3 in `supported_versions`,
    /// the server automatically falls back to DTLS 1.2.  This handles
    /// fragmented ClientHellos (e.g. with post-quantum key shares)
    /// correctly because the DTLS 1.3 engine performs full reassembly
    /// before inspecting extensions.
    ///
    /// **Client role** ([`set_active(true)`](Self::set_active)): the
    /// instance sends a hybrid ClientHello compatible with both DTLS 1.2
    /// and 1.3 servers and forks into the correct handshake once the
    /// server responds. If the configuration only enables PSK DTLS 1.2
    /// suites, `new_auto` delegates to the DTLS 1.2 PSK state machine.
    pub fn new_auto(config: Arc<Config>, certificate: DtlsCertificate, now: Instant) -> Self {
        let inner = if is_dtls12_psk_only(config.as_ref()) {
            Inner::Server12(Server12::new_psk(config, now))
        } else {
            Inner::Server13(Server13::new_auto(config, certificate, now))
        };
        Dtls { inner: Some(inner) }
    }

    /// Returns the negotiated DTLS protocol version.
    ///
    /// Returns `None` for auto-sense instances that have not yet completed
    /// version negotiation (i.e. still in a `Pending` state).
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        match self.inner.as_ref()? {
            Inner::Client12(_) | Inner::Server12(_) => Some(ProtocolVersion::DTLS1_2),
            Inner::Client13(_) => Some(ProtocolVersion::DTLS1_3),
            Inner::Server13(s) => {
                // Still waiting for a complete ClientHello
                if s.is_auto_mode() {
                    None
                } else {
                    Some(ProtocolVersion::DTLS1_3)
                }
            }
            Inner::ClientPending(_) => None,
        }
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
                        if s.is_auto_mode() {
                            let (config, certificate, now, _) = s.into_parts();
                            let cp = ClientPending::new(config, certificate, now)
                                .expect("failed to build hybrid ClientHello");
                            self.inner = Some(Inner::ClientPending(cp));
                        } else {
                            // Not auto mode, or already consumed — just convert
                            self.inner = Some(Inner::Client13(s.into_client()));
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => {}
        }
    }

    /// Process an incoming DTLS datagram.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        // unwrap is ok. The inner is only Option to work around borrowing
        // issues when doing auto-sensing of DTLS version.
        let inner = self.inner.as_mut().unwrap();

        // Auto-sense pending states handle the packet themselves
        // (including replay to the newly created inner), so we
        // must not fall through to the regular dispatch below.
        if inner.is_pending() {
            return self.handle_pending_auto(packet);
        }

        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.handle_packet(packet),
            Inner::Server12(server) => server.handle_packet(packet),
            Inner::Client13(client) => client.handle_packet(packet),
            Inner::Server13(server) => server.handle_packet(packet),
            Inner::ClientPending(_) => unreachable!(),
        }
    }

    fn handle_pending_auto(&mut self, packet: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::ClientPending(_) => self.handle_pending_auto_client(packet),
            Inner::Server13(server) if server.is_auto_mode() => {
                // Run the structural check unconditionally so the time
                // spent here does not leak which error branch the parser
                // took — same cost whether handle_packet returns Ok,
                // Dtls12Fallback, ParseError, or anything else.
                let is_ch_shaped = looks_like_client_hello(packet);
                match server.handle_packet(packet) {
                    Ok(()) => Ok(()),
                    Err(Error::Dtls12Fallback) => {
                        // The 1.3 engine cleanly rejected a ClientHello
                        // that did not offer DTLS 1.3 in supported_versions.
                        self.handle_pending_auto_server()
                    }
                    Err(Error::ParseError(_) | Error::ParseIncomplete) if is_ch_shaped => {
                        // The packet is structurally a ClientHello but the
                        // 1.3 parser couldn't handle it — fall back to 1.2,
                        // which has a more permissive parser. Random/garbage
                        // traffic that happens to error is not caught here,
                        // so an off-path attacker cannot force a downgrade
                        // by spraying malformed packets.
                        self.handle_pending_auto_server()
                    }
                    Err(e) => Err(e),
                }
            }
            _ => unreachable!(),
        }
    }

    fn handle_pending_auto_client(&mut self, packet: &[u8]) -> Result<(), Error> {
        // Auto-sense client: resolve version on first server response
        let version = auto::server_hello_version(packet);

        // Check version before taking inner — returning an error
        // while inner is None would leave us unable to poll/timeout.
        if matches!(version, auto::DetectedVersion::Unknown) {
            return Err(Error::UnexpectedMessage(
                "Unrecognized response from server".to_string(),
            ));
        }

        // unwrap: guarded by the matches! check above
        let inner = self.inner.take().unwrap();
        let Inner::ClientPending(cp) = inner else {
            unreachable!()
        };
        let (hybrid, config, certificate, now) = cp.into_parts();
        match version {
            auto::DetectedVersion::Dtls12 => {
                let mut client12 = Client12::new_from_hybrid(
                    hybrid.random,
                    &hybrid.handshake_fragment,
                    config,
                    certificate,
                    now,
                )?;
                // Feed the HVR to Client12 — it enters
                // AwaitHelloVerifyRequest and processes the cookie.
                if let Err(e) = client12.handle_packet(packet) {
                    self.inner = Some(Inner::Client12(client12));
                    return Err(e);
                }
                self.inner = Some(Inner::Client12(client12));
                Ok(())
            }
            auto::DetectedVersion::Dtls13 => {
                let mut client13 = Client13::new_from_hybrid(hybrid, config, certificate, now)?;
                if let Err(e) = client13.handle_packet(packet) {
                    self.inner = Some(Inner::Client13(client13));
                    return Err(e);
                }
                self.inner = Some(Inner::Client13(client13));
                Ok(())
            }
            auto::DetectedVersion::Unknown => unreachable!(),
        }
    }

    /// Fall back from DTLS 1.3 auto-sense to a DTLS 1.2 server, replaying
    /// all buffered packets from the Server13.
    fn handle_pending_auto_server(&mut self) -> Result<(), Error> {
        // Take buffered packets and last_now from the Server13 before replacing it.

        // unwrap: is ok, because we can only be here if the inner is a Server13.
        let server = match self.inner.take().unwrap() {
            Inner::Server13(server) => server,
            _ => unreachable!(),
        };

        let (config, cert, now, buffered) = server.into_parts();

        // A Server12 instance is either cert-auth or PSK-auth — the auth
        // mode must be chosen before construction. Peek at the buffered
        // ClientHello to see which cipher suite the server would pick,
        // so PSK clients survive the fallback.
        let use_psk =
            config.psk().is_some() && buffered.iter().any(|p| client_hello_wants_psk(p, &config));

        let mut server12 = if use_psk {
            Server12::new_psk(config, now)
        } else {
            Server12::new(config, cert, now)
        };
        server12.handle_timeout(now)?;

        self.inner = Some(Inner::Server12(server12));

        for p in &buffered {
            self.handle_packet(p)?;
        }
        Ok(())
    }

    /// Poll for pending output from the DTLS engine.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        match self.inner.as_mut().unwrap() {
            Inner::Client12(client) => client.poll_output(buf),
            Inner::Server12(server) => server.poll_output(buf),
            Inner::Client13(client) => client.poll_output(buf),
            Inner::Server13(server) => server.poll_output(buf),
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
            Inner::ClientPending(cp) => cp.handle_timeout(now),
        }
    }

    /// Send application data over the established DTLS session.
    ///
    /// Returns [`Error::HandshakePending`] if the DTLS version has not
    /// yet been resolved (auto-sense pending).  Callers should buffer
    /// the data externally and retry after the handshake progresses.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        // unwrap is ok, we only have an Option to deal with pending auto.
        let inner = self.inner.as_mut().unwrap();

        if inner.is_pending() {
            return Err(Error::HandshakePending);
        }

        match inner {
            Inner::Client12(client) => client.send_application_data(data),
            Inner::Server12(server) => server.send_application_data(data),
            Inner::Client13(client) => client.send_application_data(data),
            Inner::Server13(server) => server.send_application_data(data),
            Inner::ClientPending(_) => Err(Error::HandshakePending),
        }
    }

    /// Initiate graceful shutdown by sending a `close_notify` alert.
    ///
    /// **Connected** (`AwaitApplicationData`): queues a `close_notify` alert;
    /// the next [`poll_output`](Self::poll_output) cycle yields it as
    /// [`Output::Packet`].
    ///
    /// **Handshake in progress**: aborts immediately without sending an
    /// alert (no authenticated channel exists). Subsequent calls to
    /// [`send_application_data`](Self::send_application_data) will return
    /// an error.
    ///
    /// **Pending** (version not yet resolved): returns
    /// [`Error::HandshakePending`]. Callers who want to discard a pending
    /// connection can simply drop the [`Dtls`] value.
    ///
    /// The alert is not retransmitted (per RFC 6347 §4.2.7 / RFC 9147 §5.10).
    pub fn close(&mut self) -> Result<bool, Error> {
        let inner = self.inner.as_mut().unwrap();

        if inner.is_pending() {
            return Err(Error::HandshakePending);
        }

        match inner {
            Inner::Client12(client) => client.close(),
            Inner::Server12(server) => server.close(),
            Inner::Client13(client) => client.close(),
            Inner::Server13(server) => server.close(),
            Inner::ClientPending(_) => Err(Error::HandshakePending),
        }
    }
}

impl Inner {
    fn is_pending(&self) -> bool {
        match self {
            Inner::Server13(v) => v.is_auto_mode(),
            Inner::ClientPending(_) => true,
            _ => false,
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
#[non_exhaustive]
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
    /// The peer sent a `close_notify` alert, indicating graceful connection closure.
    CloseNotify,
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
            Self::CloseNotify => write!(f, "CloseNotify"),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "rcgen")]
mod test {
    use std::panic::UnwindSafe;

    use crate::certificate::generate_self_signed_certificate;
    use crate::crypto::Dtls12CipherSuite;

    use super::*;

    struct FixedPsk;

    impl PskResolver for FixedPsk {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(b"0123456789abcdef".to_vec())
        }
    }

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
    fn test_auto_client_unknown_version_no_panic() {
        // Regression: handle_packet returning UnexpectedMessage for an
        // unrecognized server response must not leave inner as None,
        // which would panic on the next poll_output/handle_timeout.
        let mut dtls = new_instance_auto();
        dtls.set_active(true);
        let now = Instant::now();
        dtls.handle_timeout(now).unwrap();

        // Drain the hybrid ClientHello
        let mut buf = [0u8; 2048];
        loop {
            if matches!(dtls.poll_output(&mut buf), Output::Timeout(_)) {
                break;
            }
        }

        // Feed a garbage packet that won't be recognized as DTLS 1.2 or 1.3
        let garbage = [0xFF; 64];
        let err = dtls.handle_packet(&garbage).unwrap_err();
        assert!(matches!(err, Error::UnexpectedMessage(_)));

        // These must NOT panic — inner should still be intact
        dtls.handle_timeout(now).unwrap();
        let _ = dtls.poll_output(&mut buf);
    }

    #[test]
    fn test_auto_psk_only_dtls12_uses_dtls12_path() {
        let cert = generate_self_signed_certificate().expect("Failed to generate cert");
        let config = Arc::new(
            Config::builder()
                .with_psk_client(b"identity".to_vec(), Arc::new(FixedPsk))
                .dtls12_cipher_suites(&[Dtls12CipherSuite::PSK_AES128_CCM_8])
                .dtls13_cipher_suites(&[])
                .build()
                .expect("PSK-only DTLS 1.2 config should build"),
        );

        let mut dtls = Dtls::new_auto(config, cert, Instant::now());
        dtls.set_active(true);

        assert!(dtls.is_active(), "client should become active");
        assert!(
            matches!(dtls.inner, Some(Inner::Client12(_))),
            "PSK-only DTLS 1.2 auto config should reuse the DTLS 1.2 client path"
        );
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

    #[test]
    fn test_protocol_version_12() {
        let dtls = new_instance();
        assert_eq!(dtls.protocol_version(), Some(ProtocolVersion::DTLS1_2));
    }

    #[test]
    fn test_protocol_version_13() {
        let dtls = new_instance_13();
        assert_eq!(dtls.protocol_version(), Some(ProtocolVersion::DTLS1_3));
    }

    #[test]
    fn test_protocol_version_auto_pending() {
        let dtls = new_instance_auto();
        assert_eq!(dtls.protocol_version(), None);
    }

    #[test]
    #[should_panic(expected = "requires a PSK configuration")]
    fn new_12_psk_panics_without_psk_config() {
        let config = Arc::new(Config::default());
        let _ = Dtls::new_12_psk(config, Instant::now());
    }

    #[test]
    #[should_panic(expected = "Server certificate cannot be empty")]
    fn new_12_panics_on_empty_certificate() {
        let cert = generate_self_signed_certificate().expect("Failed to generate cert");
        let config = Arc::new(Config::default());
        let empty = DtlsCertificate {
            certificate: vec![],
            private_key: cert.private_key,
        };
        let _ = Dtls::new_12(config, empty, Instant::now());
    }

    #[test]
    fn test_auto_server_send_application_data_pending() {
        let mut dtls = new_instance_auto();
        let err = dtls.send_application_data(b"early data").unwrap_err();
        assert!(matches!(err, Error::HandshakePending));
    }

    #[test]
    fn test_auto_close_pending() {
        let mut dtls = new_instance_auto();
        let err = dtls.close().unwrap_err();
        assert!(matches!(err, Error::HandshakePending));
    }

    fn make_record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(13 + body.len());
        pkt.push(content_type);
        pkt.extend_from_slice(&[0xFE, 0xFD]); // version
        pkt.extend_from_slice(&[0x00, 0x00]); // epoch
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seq
        pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
        pkt.extend_from_slice(body);
        pkt
    }

    /// Build a handshake message: 12-byte header + body bytes.
    fn make_handshake(
        msg_type: u8,
        length: u32,
        frag_off: u32,
        frag_len: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut hs = Vec::with_capacity(12 + body.len());
        hs.push(msg_type);
        hs.extend_from_slice(&length.to_be_bytes()[1..]); // 3-byte length
        hs.extend_from_slice(&[0x00, 0x00]); // message_seq
        hs.extend_from_slice(&frag_off.to_be_bytes()[1..]); // 3-byte fragment_offset
        hs.extend_from_slice(&frag_len.to_be_bytes()[1..]); // 3-byte fragment_length
        hs.extend_from_slice(body);
        hs
    }

    /// Minimum-shape DTLS 1.2 ClientHello body (41 bytes):
    /// version(2) + random(32) + sid_len=0(1) + cookie_len=0(1) +
    /// suites_len=2(2) + 2 bytes of suite + comp_len=1(1) + null comp(1)
    /// = 42. We use 41 to match the gate's lower bound; an extra byte is
    /// fine. Returns a fixed valid-shape body for use in unit tests.
    fn min_ch_body() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_length = 0
        body.push(0); // cookie_length = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_length = 2
        body.extend_from_slice(&[0xC0, 0x2B]); // one suite (ECDHE_ECDSA_AES128_GCM)
        body.push(1); // compression_methods_length = 1
        body.push(0); // null compression
        body
    }

    #[test]
    fn looks_like_client_hello_accepts_minimum_shape_ch() {
        let body = min_ch_body();
        let len = body.len() as u32;
        let hs = make_handshake(0x01, len, 0, len, &body);
        let pkt = make_record(0x16, &hs);
        assert!(looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_non_handshake_record() {
        let body = min_ch_body();
        let len = body.len() as u32;
        let hs = make_handshake(0x01, len, 0, len, &body);
        let pkt = make_record(0x17, &hs); // ApplicationData
        assert!(!looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_other_handshake_msg_types() {
        // ServerHello, HelloVerifyRequest, Finished, etc.
        let body = min_ch_body();
        let len = body.len() as u32;
        for msg_type in [0x02, 0x03, 0x04, 0x0B, 0x0E, 0x14] {
            let hs = make_handshake(msg_type, len, 0, len, &body);
            let pkt = make_record(0x16, &hs);
            assert!(
                !looks_like_client_hello(&pkt),
                "msg_type {:#x} should not look like a CH",
                msg_type
            );
        }
    }

    #[test]
    fn looks_like_client_hello_rejects_truncated_packets() {
        assert!(!looks_like_client_hello(&[]));
        assert!(!looks_like_client_hello(&[0x16; 12])); // too short for record header
        // Record header claims body length 100 but no body bytes follow.
        let mut pkt = vec![0x16, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0];
        pkt.extend_from_slice(&100u16.to_be_bytes());
        assert!(!looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_short_handshake_body() {
        // Valid record header but handshake body too short (< 12 bytes).
        let pkt = make_record(0x16, &[0x01, 0x00, 0x00]);
        assert!(!looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_header_only_ch() {
        // Handshake header with msg_type=ClientHello but length=0 and no body.
        // Pre-tightening this passed; it must now be rejected.
        let hs = make_handshake(0x01, 0, 0, 0, &[]);
        let pkt = make_record(0x16, &hs);
        assert!(!looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_undersized_unfragmented_ch() {
        // Unfragmented CH (frag_off=0, frag_len=length) but length=20 — way
        // below the 41-byte minimum a real DTLS 1.2 CH can have.
        let body = vec![0xAA; 20];
        let hs = make_handshake(0x01, 20, 0, 20, &body);
        let pkt = make_record(0x16, &hs);
        assert!(!looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_inconsistent_fragment_overflow() {
        // fragment_offset + fragment_length > length — wire-format
        // contradiction; the fragment claims to extend past the total CH.
        let body = min_ch_body();
        let hs = make_handshake(0x01, 50, 0, 100, &body);
        let pkt = make_record(0x16, &hs);
        assert!(!looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_missing_fragment_bytes() {
        // fragment_length declares 200 bytes of body but only ~40 are
        // present in the record. The fragment's bytes are not actually
        // there.
        let body = min_ch_body();
        let hs = make_handshake(0x01, 200, 0, 200, &body);
        let pkt = make_record(0x16, &hs);
        assert!(!looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_accepts_first_fragment_of_fragmented_ch() {
        // frag_off=0, frag_len=20, length=200 — first fragment of a
        // larger CH. The minimum-body check only applies to unfragmented
        // CHs, so this must pass even though length<41 wouldn't apply
        // here either.
        let body = vec![0xAA; 20];
        let hs = make_handshake(0x01, 200, 0, 20, &body);
        let pkt = make_record(0x16, &hs);
        assert!(looks_like_client_hello(&pkt));
    }

    #[test]
    fn looks_like_client_hello_rejects_non_first_fragment() {
        // frag_off > 0: a non-first fragment arriving alone could be a
        // spoofed packet aimed at forcing a downgrade. Real fragmented
        // CHs always include a frag_off=0 fragment, and the clean
        // Dtls12Fallback path (gated by supported_versions, not by this
        // check) handles fully reassembled fragmented 1.2 CHs.
        let body = vec![0xBB; 20];
        let hs = make_handshake(0x01, 200, 20, 20, &body);
        let pkt = make_record(0x16, &hs);
        assert!(!looks_like_client_hello(&pkt));
    }

    /// CH-shaped body whose `cipher_suites_length` exceeds the bytes that
    /// follow it — the DTLS 1.3 body parser will error on this. Used to
    /// drive the auto-server into the gated ParseError fallback path.
    fn ch_shaped_malformed_body() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0xFE, 0xFD]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_length = 0
        body.push(0); // cookie_length = 0
        body.extend_from_slice(&[0xFF, 0xFF]); // cipher_suites_length = 65535 — bogus
        body.extend_from_slice(&[0xC0, 0x2B]); // 2 bytes that pretend to be a suite
        body.push(1); // compression_methods_length = 1
        body.push(0); // null compression
        body
    }

    #[test]
    fn auto_server_falls_back_on_ch_shaped_malformed_packet() {
        // Documents the intentional behavior of the gated fallback: a
        // packet that is structurally a ClientHello (passes
        // `looks_like_client_hello`) but whose body cannot be parsed by
        // the DTLS 1.3 engine should still flip the auto-sense server
        // into DTLS 1.2 mode. (Random non-CH garbage does not — see
        // `auto_server_drops_garbage_without_falling_back`.)
        let body = ch_shaped_malformed_body();
        let len = body.len() as u32;
        let hs = make_handshake(0x01, len, 0, len, &body);
        let pkt = make_record(0x16, &hs);
        assert!(
            looks_like_client_hello(&pkt),
            "fixture must pass the structural gate"
        );

        let mut dtls = new_instance_auto();
        // Server12 will also fail to parse this packet on replay, so
        // ignore the result of handle_packet — we only care about which
        // inner state we ended up in.
        let _ = dtls.handle_packet(&pkt);
        let fell_back = matches!(dtls.inner, Some(Inner::Server12(_)));
        assert!(
            fell_back,
            "auto-sense server must fall back to DTLS 1.2 on a CH-shaped malformed packet"
        );
    }

    #[test]
    fn auto_server_drops_garbage_without_falling_back() {
        let mut dtls = new_instance_auto();
        // Random non-handshake bytes — the 1.3 engine will error, but the
        // auto-sense path must not downgrade to 1.2.
        let garbage = [0xFF; 64];
        let _ = dtls.handle_packet(&garbage);
        // Inner must remain Server13 in auto-sense mode.
        let still_pending = match &dtls.inner {
            Some(Inner::Server13(s)) => s.is_auto_mode(),
            _ => false,
        };
        assert!(
            still_pending,
            "auto-sense server must not fall back to DTLS 1.2 on garbage input"
        );
    }
}
