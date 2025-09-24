# dimpl

dimpl — DTLS 1.2 implementation for WebRTC (Sans‑IO)

dimpl is a focused DTLS 1.2 implementation aimed at WebRTC. It is a Sans‑IO
state machine you embed into your own UDP/RTC event loop: you feed incoming
datagrams, poll for outgoing records or timers, and wire up certificate
verification and SRTP key export yourself.

#### Goals
- **DTLS 1.2**: Implements the DTLS 1.2 handshake and record layer used by WebRTC.
- **Safety**: `forbid(unsafe_code)` throughout the crate.
- **Minimal Rust‑only deps**: Uses small, well‑maintained Rust crypto crates.
- **Low overhead**: Tight control over allocations and buffers; Sans‑IO integration.

#### Non‑goals
- **DTLS 1.0**
- **Async API** (the crate is Sans‑IO and event‑loop agnostic)
- **no_std** (at least not without allocation)

#### Cryptography surface
- **Cipher suites (TLS 1.2 over DTLS)**
  - `ECDHE_ECDSA_AES256_GCM_SHA384`
  - `ECDHE_ECDSA_AES128_GCM_SHA256`
  - `ECDHE_RSA_AES256_GCM_SHA384`
  - `ECDHE_RSA_AES128_GCM_SHA256`
  - `DHE_RSA_AES256_GCM_SHA384`
  - `DHE_RSA_AES128_GCM_SHA256`
- **AEAD**: AES‑GCM 128/256 only (no CBC/EtM modes).
- **Key exchange**: ECDHE (P‑256/P‑384) and FFDHE (≥2048 bit) for DHE suites.
- **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384, RSA‑PKCS1v1.5 with SHA‑256/384.
- **DTLS‑SRTP**: Exports keying material for `SRTP_AEAD_AES_256_GCM`,
  `SRTP_AEAD_AES_128_GCM`, and `SRTP_AES128_CM_SHA1_80` (RFC 5764/7714).
- **Extended Master Secret** (RFC 7627) is negotiated and enforced.
- Not supported: PSK cipher suites.

#### Certificate model
You provide a certificate verifier via [`CertVerifier`]. The crate verifies
handshake signatures against the peer's certificate; PKI policy (chain,
name, EKU, pinning) is enforced by your verifier.

#### Sans‑IO integration model
Drive the engine with three calls:
- [`Dtls::handle_packet`] — feed an entire received UDP datagram.
- [`Dtls::poll_output`] — drain pending output: DTLS records, timers, events.
- [`Dtls::handle_timeout`] — trigger retransmissions/time‑based progress.

The output is an [`Output`] enum with:
- `Packet(&[u8])`: send on your UDP socket
- `Timeout(Instant)`: schedule a timer and call `handle_timeout` at/after it
- `Connected`: handshake complete
- `PeerCert(Vec<u8>)`: peer leaf certificate (DER)
- `KeyingMaterial(KeyingMaterial, SrtpProfile)`: DTLS‑SRTP export
- `ApplicationData(Vec<u8>)`: plaintext received from peer

#### Minimal example (Sans‑IO loop)

```rust
use std::sync::Arc;
use std::time::Instant;

use dimpl::{certificate, CertVerifier, Config, Dtls, Output};

// Minimal certificate verifier (application policy goes here)
struct AcceptAll;
impl CertVerifier for AcceptAll {
    fn verify_certificate(&self, _der: &[u8]) -> Result<(), String> { Ok(()) }
}

// Stub I/O to keep the example focused on the state machine
enum Event { Udp(Vec<u8>), Timer(Instant) }
fn wait_next_event(_next_wake: Option<Instant>) -> Event { Event::Udp(Vec::new()) }
fn send_udp(_bytes: &[u8]) {}

fn example_event_loop(mut dtls: Dtls) -> Result<(), dimpl::Error> {
    let mut next_wake: Option<Instant> = None;
    loop {
        // Drain engine output until we have to wait for I/O or a timer
        loop {
            match dtls.poll_output() {
                Output::Packet(p) => send_udp(p),
                Output::Timeout(t) => { next_wake = Some(t); break; }
                Output::Connected => {
                    // DTLS established — application may start sending
                }
                Output::PeerCert(_der) => {
                    // Inspect peer leaf certificate if desired
                }
                Output::KeyingMaterial(_km, _profile) => {
                    // Provide to SRTP stack
                }
                Output::ApplicationData(_data) => {
                    // Deliver plaintext to application
                }
            }
        }

        // Block waiting for either UDP input or the scheduled timeout
        match wait_next_event(next_wake) {
            Event::Udp(pkt) => dtls.handle_packet(&pkt)?,
            Event::Timer(now) => dtls.handle_timeout(now)?,
        }
    }
}

fn mk_dtls_client() -> Dtls {
    let now = Instant::now();
    let cert = certificate::generate_self_signed_certificate().unwrap();
    let cfg = Arc::new(Config::default());
    let mut dtls = Dtls::new(now, cfg,
        cert.certificate,
        cert.private_key,
        Box::new(AcceptAll)
    );
    dtls.set_active(true); // client role
    dtls
}

// Putting it together
let dtls = mk_dtls_client();
let _ = example_event_loop(dtls);
```

#### Configuration highlights
- See [`Config`] for MTU, buffer sizes, retry/backoff tuning, and allowed cipher suites.
- By default, servers require a client certificate (`require_client_certificate = true`).
- Use [`CipherSuite::compatible_with_certificate`] to align suites with your key type.

#### MSRV
Rust 1.71.1.

#### Status
- Session resumption is not implemented.
- Renegotiation is not implemented (the renegotiation info extension is sent empty).
- Only DTLS 1.2 is accepted/advertised.


License: MIT OR Apache-2.0
