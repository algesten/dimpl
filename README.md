# dimpl

dimpl — DTLS 1.2 and 1.3 implementation (Sans‑IO, Sync)

dimpl is a focused DTLS implementation aimed at WebRTC, supporting both DTLS 1.2
and DTLS 1.3 ([RFC 9147]). It is a Sans‑IO state machine you embed into your own
UDP/RTC event loop: you feed incoming datagrams, poll for outgoing records or
timers, and wire up certificate verification and SRTP key export yourself.

## Goals
- **DTLS 1.2 & 1.3**: Implements both DTLS 1.2 and DTLS 1.3 handshake and record layers for WebRTC.
- **Safety**: `forbid(unsafe_code)` throughout the crate.
- **Minimal Rust‑only deps**: Uses small, well‑maintained Rust crypto crates.
- **Low overhead**: Tight control over allocations and buffers; Sans‑IO integration.

### Non‑goals
- **DTLS 1.0**
- **Async** (the crate is Sans‑IO and event‑loop agnostic)
- **no_std** (at least not without allocation)
- **RSA**
- **DHE**
- **0-RTT** (DTLS 1.3 early data is not supported)

## Cryptography surface

### DTLS 1.2
- **Cipher suites**
  - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- **Extended Master Secret** ([RFC 7627]) is negotiated and enforced.

### DTLS 1.3
- **Cipher suites**
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_AES_128_GCM_SHA256`
- **Key Update**: Automatic key rotation when AEAD usage limits approach ([RFC 9147 §4.5.3]).
- **ACK-based retransmission**: Selective retransmission using ACK messages ([RFC 9147 §7]).
- **Unified record header**: Encrypted sequence numbers for anti-traffic analysis.

### DTLS 1.3 behavior

#### ACKs (selective retransmission)
- DTLS 1.3 uses `ContentType::Ack` (26) to acknowledge received records; ACKs are not handshake messages and are not included in the transcript.
- The engine tracks received DTLS 1.3 record numbers (epoch + sequence number) and sends ACKs when it detects gaps (out-of-order delivery).
- When ACKs arrive, the sender uses them to suppress unnecessary retransmits and selectively retransmit only the missing handshake records.

#### Piggybacking application data with Finished
- Application data queued during the handshake may be sent as soon as the connection is established.
- This implementation may piggyback application data with the sender's `{Finished}` flight.
    It emits both `{Finished}` (epoch 2) and application data (epoch 3) in the same outgoing flight/datagram.
- The receiver may observe application data immediately after installing epoch 3 keys.
    If application data arrives early (before epoch 3 keys are available), it is deferred and processed once keys are installed.

### Common
- **AEAD**: AES‑GCM 128/256 only (no CBC/EtM modes).
- **Key exchange**: ECDHE (P‑256/P‑384)
- **Signatures**: ECDSA P‑256/SHA‑256, ECDSA P‑384/SHA‑384
- **DTLS‑SRTP**: Exports keying material for `SRTP_AEAD_AES_256_GCM`,
  `SRTP_AEAD_AES_128_GCM`, and `SRTP_AES128_CM_SHA1_80` ([RFC 5764], [RFC 7714]).
- Not supported: PSK cipher suites, 0-RTT.

### Certificate model
During the handshake the engine emits [`Output::PeerCert`] with the peer's
leaf certificate (DER). The crate uses that certificate to verify DTLS
handshake messages, but it does not perform any PKI validation. Your
application is responsible for validating the peer certificate according to
your policy (fingerprint, chain building, name/EKU checks, pinning, etc.).

### Sans‑IO integration model
Drive the engine with three calls:
- [`Dtls::handle_packet`] — feed an entire received UDP datagram.
- [`Dtls::poll_output`] — drain pending output: DTLS records, timers, events.
- [`Dtls::handle_timeout`] — trigger retransmissions/time‑based progress.

The output is an [`Output`] enum with borrowed references into your provided buffer:
- `Packet(&[u8])`: send on your UDP socket
- `Timeout(Instant)`: schedule a timer and call `handle_timeout` at/after it
- `Connected`: handshake complete
- `PeerCert(&[u8])`: peer leaf certificate (DER) — validate in your app
- `KeyingMaterial(KeyingMaterial, SrtpProfile)`: DTLS‑SRTP export
- `ApplicationData(&[u8])`: plaintext received from peer

## Example (Sans‑IO loop)

```rust
use std::sync::Arc;
use std::time::Instant;

use dimpl::{certificate, Config, Dtls, Output};

// Stub I/O to keep the example focused on the state machine
enum Event { Udp(Vec<u8>), Timer(Instant) }
fn wait_next_event(_next_wake: Option<Instant>) -> Event { Event::Udp(Vec::new()) }
fn send_udp(_bytes: &[u8]) {}

fn example_event_loop(mut dtls: Dtls) -> Result<(), dimpl::Error> {
    let mut next_wake: Option<Instant> = None;
    loop {
        // Drain engine output until we have to wait for I/O or a timer
        let mut out_buf = vec![0u8; 2048];
        loop {
            match dtls.poll_output(&mut out_buf) {
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
    let cert = certificate::generate_self_signed_certificate().unwrap();
    let cfg = Arc::new(Config::default());
    let mut dtls = Dtls::new(cfg, cert);
    dtls.set_active(true); // client role
    dtls
}

// Putting it together
let dtls = mk_dtls_client();
let _ = example_event_loop(dtls);
```

#### MSRV
Rust 1.81.0

#### Status
- Session resumption is not implemented (WebRTC does a full handshake on ICE restart).
- Renegotiation is not implemented (WebRTC does full restart).
- DTLS 1.3 0-RTT (early data) is not supported.
- Post-quantum cryptography (PQ/hybrid key exchange, PQ signatures) is not implemented.
- DTLS 1.3 Connection IDs (CID) are not supported (records with the CID bit set are discarded).
- DTLS 1.3 cookie/DoS protection via HelloRetryRequest cookies is currently not enforced.
- DTLS 1.3 anti-amplification (3x before address validation) is not currently enforced.

[RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
[RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
[RFC 7627]: https://www.rfc-editor.org/rfc/rfc7627
[RFC 9147]: https://www.rfc-editor.org/rfc/rfc9147

[`Dtls::handle_packet`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.handle_packet
[`Dtls::poll_output`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.poll_output
[`Dtls::handle_timeout`]: https://docs.rs/dimpl/0.1.0/dimpl/struct.Dtls.html#method.handle_timeout
[`Output`]: https://docs.rs/dimpl/0.1.0/dimpl/enum.Output.html
[`Output::PeerCert`]: https://docs.rs/dimpl/0.1.0/dimpl/enum.Output.html#variant.PeerCert


License: MIT OR Apache-2.0
