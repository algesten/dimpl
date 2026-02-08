# DTLS 1.3 Implementation Design

This document describes the minimal DTLS 1.3 profile implemented in this crate.

## Scope

A minimal, compliant DTLS 1.3 server/client implementation optimized for
controlled environments where both endpoints are known.

## Profile Constraints

| Feature | Supported |
|---------|-----------|
| 1-RTT Handshake | Yes |
| 0-RTT Early Data | No |
| HelloRetryRequest | Yes |
| Connection ID | No |
| PSK / Session Resumption | No |
| Post-Handshake KeyUpdate | Yes |
| Post-Handshake Client Auth | Optional |

### Rationale

- **No 0-RTT**: Eliminates epoch 1 buffering, replay protection complexity,
  and idempotency requirements on the application.
- **No CID**: Assumes stable IP:port pairs. Removes variable-length header parsing.
- **No PSK**: Every connection is a full (EC)DHE handshake. No session cache,
  no ticket management, no binder calculation.

## Handshake Flow

### Full Handshake (1-RTT)

```
Client                                 Server
──────                                 ──────
ClientHello
 + supported_versions
 + supported_groups
 + key_share
 + signature_algorithms    ──────►
                                       ServerHello
                                        + supported_versions
                                        + key_share
                                       {EncryptedExtensions}
                                       {CertificateRequest*}
                                       {Certificate}
                                       {CertificateVerify}
                           ◄──────     {Finished}
{Certificate*}
{CertificateVerify*}
{Finished}                 ──────►
[Application Data]         ◄─────►     [Application Data]

{} = encrypted with handshake keys
[] = encrypted with application keys
*  = optional (client auth)
```

### HelloRetryRequest (2-RTT)

When client's key_share doesn't include a supported group:

```
Client                                 Server
──────                                 ──────
ClientHello
 + key_share (P-384)       ──────►
                                       HelloRetryRequest
                                        + supported_versions
                           ◄──────      + key_share (X25519)

ClientHello
 + key_share (X25519)      ──────►
                                       ServerHello
                                        + key_share
                           ◄──────     {... continues as above}
```

HelloRetryRequest is a ServerHello with a special random value:
```
CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
```

**Transcript handling**: The original ClientHello is replaced by a `message_hash` construct in the transcript:
```
Transcript = message_hash || HRR || ClientHello2 || ServerHello || ...

message_hash = handshake_type(254) || length || Hash(ClientHello1)
```

## Record Layer

### Plaintext Records (Epoch 0)

Used for ClientHello and ServerHello only.

```
struct {
    ContentType type;               // handshake (22)
    ProtocolVersion legacy_version; // {254, 253} (DTLS 1.2)
    uint16 epoch;                   // 0
    uint48 sequence_number;
    uint16 length;
    opaque fragment[length];
} DTLSPlaintext;
```

### Ciphertext Records (Epoch 2+)

```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|0|0|1|C|S|L|E E|   Flags (C=0 always, no CID)
+-+-+-+-+-+-+-+-+
| Sequence Num  |   1 or 2 bytes (S flag)
+-+-+-+-+-+-+-+-+
|    Length     |   2 bytes (if L=1)
+-+-+-+-+-+-+-+-+
|   Encrypted   |
|    Payload    |
+-+-+-+-+-+-+-+-+
```

Since CID is not supported, the C flag is always 0.

### Encrypted Payload Structure

```
struct {
    opaque content[length];
    ContentType type;           // Real content type
    uint8 zeros[padding];       // Optional padding
} DTLSInnerPlaintext;
```

Content type is recovered by scanning backwards from decrypted payload, skipping zero bytes.

## Key Schedule

Without PSK, the key schedule simplifies to:

```
      0 ──► HKDF-Extract ──► Early Secret
                                  │
                            Derive-Secret(., "derived", "")
                                  │
                                  ▼
(EC)DHE ──► HKDF-Extract ──► Handshake Secret
                                  │
                 ┌────────────────┼────────────────┐
                 │                │                │
                 ▼                ▼                ▼
    client_handshake    server_handshake    Derive-Secret
      _traffic_secret    _traffic_secret    (., "derived", "")
                                                  │
                                                  ▼
                              0 ──► HKDF-Extract ──► Master Secret
                                                          │
                                           ┌──────────────┼──────────────┐
                                           │              │              │
                                           ▼              ▼              ▼
                              client_app_traffic  server_app_traffic  (resumption
                                  _secret_0          _secret_0         unused)
```

### Traffic Key Derivation

From each traffic secret:

```
key = HKDF-Expand-Label(secret, "key", "", key_length)
iv  = HKDF-Expand-Label(secret, "iv", "", iv_length)
```

### Nonce Construction

```
nonce = iv XOR padded_sequence_number
```

Where `padded_sequence_number` is the 64-bit sequence number zero-padded to IV length.

## Epochs

| Epoch | Keys | Purpose |
|-------|------|---------|
| 0 | None (plaintext) | ClientHello, ServerHello |
| 1 | (unused) | Would be 0-RTT, not supported |
| 2 | Handshake traffic | EncryptedExtensions through Finished |
| 3 | Application traffic | Application data |
| 4+ | Updated application | After KeyUpdate |

## Reliability (ACKs)

Handshake messages use explicit ACKs:

```
struct {
    RecordNumber record_numbers<2..2^16-2>;
} ACK;

struct {
    uint64 epoch;
    uint64 sequence_number;
} RecordNumber;
```

- ACKs are sent at end of flight or on timeout
- Missing records trigger selective retransmission
- Timers remain as fallback (initial: 1s, max: 60s, exponential backoff)
- ACKs only apply to handshake, not application data

## Cipher Suites

| Suite | AEAD | Hash | Status |
|-------|------|------|--------|
| TLS_AES_128_GCM_SHA256 | AES-128-GCM | SHA-256 | Mandatory |
| TLS_AES_256_GCM_SHA384 | AES-256-GCM | SHA-384 | Optional |
| TLS_CHACHA20_POLY1305_SHA256 | ChaCha20-Poly1305 | SHA-256 | Optional |

TLS_AES_128_GCM_SHA256 is mandatory per RFC 9147 and required for interoperability.

## Key Exchange Groups

Both groups are supported for interoperability:

| Group | Status |
|-------|--------|
| X25519 | Mandatory |
| secp256r1 (P-256) | Mandatory |

If the client's key_share doesn't include a supported group, the server
sends HelloRetryRequest specifying the preferred group.

## Signature Algorithms

For certificate verification:

- ECDSA with P-256 and SHA-256
- ECDSA with P-384 and SHA-384
- Ed25519
- RSA-PSS with SHA-256

## Replay Protection

Sliding window for sequence numbers:

- Window size: 64 (minimum) to 256 (recommended)
- Records outside window or already seen are dropped
- Window advances with highest seen sequence number

## Post-Handshake Messages

### KeyUpdate

Supported for forward secrecy over long-lived connections:

```
struct {
    KeyUpdateRequest request_update;
} KeyUpdate;

enum {
    update_not_requested(0),
    update_requested(1)
} KeyUpdateRequest;
```

New application traffic secret derived as:

```
application_traffic_secret_N+1 =
    HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
```

Epoch increments with each update.

**Note**: KeyUpdate has no ACK. Implementations must retain old keys
temporarily to handle packet loss/reordering.

### Alerts

Supported for error signaling and clean shutdown:

```
struct {
    AlertLevel level;
    AlertDescription desc;
} Alert;
```

`close_notify` for graceful termination.

## State Machine (Server)

```
                    ┌─────┐
                    │IDLE │
                    └──┬──┘
                       │ recv ClientHello
                       │ (validate cipher, extensions)
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    [invalid]    [no key_share    [valid]
         │        match]             │
         ▼             │             │
 ┌───────────────┐     │             │
 │ send alert,   │     ▼             │
 │ close         │ ┌────────┐        │
 └───────────────┘ │WAIT_CH2│        │
                   └───┬────┘        │
                       │ send HRR    │
                       │             │
                       ▼             │
                   recv ClientHello2 │
                       │             │
                       └──────┬──────┘
                              │
                       ┌──────▼──────┐
                       │ NEGOTIATED  │
                       └──────┬──────┘
                              │ send ServerHello
                              │ derive handshake keys
                              │ send Encrypted*, Cert, CertVerify, Finished
                              ▼
                       ┌─────────────┐
                       │WAIT_FINISHED│
                       └──────┬──────┘
                              │ recv Finished
                              │ derive application keys
                              ▼
                       ┌─────────────┐
                       │ CONNECTED   │◄────────────────┐
                       └──────┬──────┘                 │
                              │                        │
                ┌─────────────┼─────────────┐          │
                │             │             │          │
                ▼             ▼             ▼          │
           [app data]   [KeyUpdate]   [close_notify]   │
                │             │             │          │
                │             │             ▼          │
                │             │        ┌────────┐      │
                │             └───────►│ CLOSED │      │
                │                      └────────┘      │
                └──────────────────────────────────────┘
```

## Limitations

1. **No 0-RTT**: First application data requires 1-RTT (or 2-RTT with HRR)
2. **No session resumption**: Full handshake every connection
3. **No NAT rebinding**: IP:port change breaks connection
4. **Ordered first flight**: Out-of-order ClientHello fragments may be dropped

## Implementation Plan

### Step 1: Slim Down CI

Reduce CI matrix during development:
- Single platform (ubuntu-latest)
- Single feature (aws-lc-rs)
- Disable fuzz tests
- Disable CodeQL (slow security scanner)
- Keep lint and snowflake

### Step 2: CLAUDE.md

Create `CLAUDE.md` with code style guidance extracted from the existing codebase.

### Step 3: Reorganize Repository

Single commit from main reorganizing the codebase. Separate engines and crypto contexts per version.

**Top-level (shared):**
```
src/
├── lib.rs
├── config.rs
├── error.rs
├── buffer.rs
├── queue.rs
├── window.rs
├── timer.rs
├── rng.rs
└── crypto/
    ├── provider.rs      # Traits only
    ├── aws_lc_rs/       # Provider impl
    └── rust_crypto/     # Provider impl
```

**DTLS 1.2 specific:**
```
src/dtls12/
├── mod.rs
├── client.rs
├── server.rs
├── engine.rs
├── incoming.rs
├── context.rs          # CryptoContext
└── message/            # All message types
```

**DTLS 1.3 (new):**
```
src/dtls13/
├── mod.rs
├── client.rs
├── server.rs
├── engine.rs
├── incoming.rs
├── context.rs
└── message/
```

### Step 4: Incremental Implementation

Build incrementally with clean commits:

1. Record layer (parse/serialize unified header)
2. Key schedule (HKDF, traffic secrets)
3. Handshake messages (EncryptedExtensions, Certificate, etc.)
4. Crypto context (encrypt/decrypt, certificate/signature ops, SRTP export)
5. Client state machine (1-RTT first, then HRR)
   - Enforce `legacy_cookie` MUST be zero length when constructing ClientHello
   - Transcript uses TLS 1.3-style 4-byte header (no message_seq/fragment fields)
   - ACK sending/receiving and selective retransmission
6. Server state machine
   - Reject ClientHello with non-empty `legacy_cookie` (`illegal_parameter` alert)
   - Transcript uses TLS 1.3-style 4-byte header (no message_seq/fragment fields)
   - ACK sending/receiving and selective retransmission
7. KeyUpdate
8. Integration + interop tests

### Step 5: Lift Tests from PR 38

Copy test files from `dev/dtls13vibe` branch:
- `tests/dtls13.rs` — dimpl ↔ dimpl tests
- `tests/client-wolfssl.rs` — interop
- `tests/server-wolfssl.rs` — interop
- `tests/wolfssl/mod.rs` — test harness

Adapt to our API as needed.

### Step 6: Re-enable Full CI

Restore full CI matrix:
- All platforms (ubuntu, macos, windows)
- All features (aws-lc-rs, rust-crypto, rcgen)
- Re-enable fuzz tests
- Re-enable CodeQL (rename `.github/workflows/codeql.yml.disabled`)

### Prior Art

PR 38 (`dev/dtls13vibe` branch) contains a WIP DTLS 1.3 implementation. We are redoing it cleanly with:
- Separate engines (not shared)
- Separate crypto contexts
- Separate message modules per version
- Cleaner commit history

## References

- [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.html) - DTLS 1.3
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) - TLS 1.3
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) - HKDF
