# DTLS 1.3 (RFC 9147) Compliance Audit — dimpl

All analysis performed against the actual source code,
February 2026.

---

## Section 4: Record Layer

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| Multiple records per datagram | 4.1 | **DONE** | `incoming.rs:80` |
| No record spanning datagrams | 4.1 | **DONE** | Single `&[u8]` per parse |
| MTU-based fragmentation | 4.1 | **DONE** | `engine.rs:833,981` |
| PMTU discovery | 4.1 | **MISSING** | Fixed config only |
| DTLSPlaintext header (13 bytes) | 4.2.1 | **DONE** | `record.rs:70-111` |
| legacy_record_version 1.0/1.2 | 4.2.1 | **DONE** | `record.rs:77-85` |
| Unified header fixed bits `001` | 4.2.2 | **DONE** | `record.rs:47,204` |
| C flag (CID) rejected | 4.2.2 | **DONE** | `incoming.rs:92` |
| S flag (seq length 8/16 bit) | 4.2.2 | **DONE** | `record.rs:140-146` |
| L flag (length present) | 4.2.2 | **DONE** | `record.rs:148-157` |
| EE epoch bits (2-bit) | 4.2.2 | **DONE** | `record.rs:138` |
| `sn_key` derivation | 4.2.3 | **DONE** | `engine.rs:1805-1812` |
| AES-ECB mask for seq encryption | 4.2.3 | **DONE** | `engine.rs:966-972` |
| ChaCha20 mask variant | 4.2.3 | **N/A** | Suite not offered |
| XOR mask over seq bytes | 4.2.3 | **DONE** | `engine.rs:1025-1036` |
| Epoch mapping (0/2/3+) | 4.3 | **DONE** | `engine.rs:2098-2103` |
| Epoch 1 (0-RTT) | 4.3 | **MISSING** | Optional per RFC |
| 2-bit epoch wrapping | 4.3 | **DONE** | `engine.rs:2139-2163` |
| AEAD nonce = IV XOR pad(seq) | 4.4 | **DONE** | `dtls_aead.rs:76-84` |
| AAD = unified header bytes | 4.4 | **DONE** | Unmasked seq — correct |
| DTLSInnerPlaintext | 4.4 | **DONE** | `engine.rs:910-912` |
| Send-side AEAD limit tracking | 4.5.1 | **DONE** | `engine.rs:1012-1018` |
| **Recv-side failure counting** | 4.5.1 | **MISSING** | No counter |
| Silent discard on decrypt fail | 4.5.2 | **DONE** | `incoming.rs:264-270` |
| No alert on invalid record | 4.5.2 | **DONE** | Silent discard only |
| Unknown-epoch handling | 4.5.2 | **DONE** | `Ok(None)` per record |
| Plaintext epoch restrictions | 4.5.3 | **DONE** | Only CH/SH at epoch 0 |
| **Max record size** | 4 | **MISSING** | No size validation |
| Anti-replay sliding window | 4.5.2 | **DONE** | `window.rs` per epoch |
| **Per-epoch replay windows** | 4.5.2 | **DONE** | Per `RecvEpochEntry` |

### Critical record-layer issues

1. ~~**Unknown-epoch records abort entire datagram**~~
   **FIXED**
2. ~~**Single replay window across epochs**~~ **FIXED**

---

## Section 5: Handshake Protocol

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| legacy_record_version = 0xFEFD | 5.1 | **DONE** | `record.rs:195` |
| legacy_version in CH = 0xFEFD | 5.1 | **DONE** | `client.rs:1069` |
| No ChangeCipherSpec | 5.1 | **DONE** | CCS discarded |
| Version via supported_versions | 5.1 | **DONE** | Client+server |
| 12-byte handshake header | 5.2 | **DONE** | `handshake.rs:63-131` |
| message_seq (incl. HRR) | 5.2 | **DONE** | `engine.rs:1057-1773` |
| Fragmentation (MTU-aware) | 5.2 | **DONE** | `engine.rs:1046-1147` |
| Reassembly (out-of-order) | 5.2 | **DONE** | `engine.rs:377-397` |
| Overlapping fragment detection | 5.2 | **PARTIAL** | MAY reject |
| **Transcript hash uses TLS fmt** | 5.2 | **DONE** | `handshake.rs:170-177` |
| ClientHello fields | 5.3 | **DONE** | All correct |
| **ClientHello padding** | 5.3 | **DONE** | RFC 7685, type 0x0015 |
| Required CH extensions | 5.3 | **DONE** | `client.rs:1092-1151` |
| SH legacy_session_id echo | 5.4 | **DONE** | `server.rs:410,640` |
| supported_versions in SH | 5.4 | **DONE** | `server.rs:1170-1180` |
| HRR magic random | 5.5 | **DONE** | `server.rs:69-72` |
| Cookie in HRR | 5.5 | **DONE** | HMAC-SHA256 cookie |
| key_share in HRR | 5.5 | **DONE** | `server.rs:1110-1122` |
| Transcript replacement (0xFE) | 5.5 | **DONE** | `engine.rs:1928-1946` |
| Double HRR prevention | 5.5 | **DONE** | Client + server |
| CertificateRequest | 5.6 | **DONE** | `server.rs:1248-1291` |
| oid_filters in CertReq | 5.6 | **MISSING** | Optional per RFC |
| TLS 1.3 Certificate format | 5.7 | **DONE** | `certificate.rs:24-101` |
| Empty cert context validated | 5.7 | **DONE** | `client.rs:681-685` |
| CertificateVerify signed content | 5.7 | **DONE** | `client.rs:742-792` |
| Finished verify_data (HMAC) | 5.7 | **DONE** | `engine.rs:1866-1893` |
| Constant-time Finished compare | 5.7 | **DONE** | `subtle::ConstantTimeEq` |
| **HKDF "dtls13" prefix** | 5.8 | **DONE** | 6 bytes, no space |
| All key schedule labels | 5.8 | **DONE** | Verified |
| Epoch 2/3 key installation | 5.9 | **DONE** | `client.rs:583,868` |
| **Downgrade sentinel** | 8446 | **MISSING** | 1.3-only impl OK |

---

## Section 6: Alert Protocol

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| **Send alerts** | 6 | **MISSING** | Zero alert records sent |
| **Process received alerts** | 6 | **MISSING** | Never read from queue |
| **close_notify** | 6 | **MISSING** | Not implemented |
| **Fatal alert before teardown** | 6 | **MISSING** | Errors not sent |

**The entire alert protocol is unimplemented.**

---

## Section 7: ACK Mechanism

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| ACK content type (26) | 7 | **DONE** | `engine.rs:1157-1179` |
| RTO/4 delay | 7 | **DONE** | `engine.rs:1359-1368` |
| Immediate ACK on gap | 7 | **DONE** | `engine.rs:1342-1356` |
| ACK scope = handshake only | 7 | **DONE** | `engine.rs:1383-1394` |
| Selective retransmission | 7 | **DONE** | `engine.rs:658-659` |
| ACK encrypted correctly | 7 | **DONE** | `engine.rs:1162-1167` |
| ACK anti-amplification | 7.3 | **MISSING** | No epoch check |

---

## Section 8: Key Updates

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| KeyUpdate message (type 24) | 8.1 | **DONE** | `handshake.rs:298-320` |
| Send key rotation | 8.1 | **DONE** | `engine.rs:1671-1696` |
| Prev send keys cleared on ACK | 8.1 | **DONE** | `engine.rs:1234-1242` |
| Prev send keys timeout | 8.1 | **MISSING** | No timeout |
| Receive multi-epoch (>= 2) | 8.1 | **DONE** | `ArrayVec<_, 4>` |
| Oldest recv epoch evicted | 8.1 | **DONE** | `engine.rs:1712-1713` |
| AEAD limit auto-KeyUpdate | 8.1 | **DONE** | Jittered threshold |
| 0-RTT early data | 8.2 | **MISSING** | Optional |
| NewSessionTicket | 8.3 | **MISSING** | Not in msg types |
| Post-handshake client auth | 8.3 | **MISSING** | Rejected |

---

## Section 9: Timer and Retransmission

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| Exponential backoff | 9.1 | **DONE** | `timer.rs` |
| Flight management | 9.1 | **DONE** | `engine.rs:628,647` |
| Duplicate CH triggers resend | 9.1 | **DONE** | `engine.rs:350-361` |
| Max retries (default 4) | 9.1 | **DONE** | `config.rs:36` |
| Handshake timeout (default 40s) | 9.1 | **DONE** | `config.rs:37` |

Fully compliant.

---

## Sections 10-11: CID and Connection Closure

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| CID | 10 | **MISSING** | Optional. Rejected |
| close_notify | 11 | **MISSING** | See Section 6 |
| Idle timeout | 11 | **MISSING** | 10-year timeout |
| Explicit close API | 11 | **MISSING** | Caller drops state |

---

## Cryptographic Coverage

| Algorithm | Adv. | Functional | Issue |
|---|---|---|---|
| AES-128-GCM-SHA256 | Yes | **Yes** | Mandatory |
| AES-256-GCM-SHA384 | Yes | **Yes** | Both providers |
| **CHACHA20-POLY1305** | **No** | **No** | Not in providers |
| ECDSA-P256-SHA256 | Yes | **Yes** | Both providers |
| ECDSA-P384-SHA384 | Yes | **Yes** | Both providers |
| Ed25519 | No | No | Not advertised |
| RSA_PSS_RSAE_SHA256 | No | No | Not advertised |
| RSA PKCS#1 v1.5 | No | Rejected | Correct per 1.3 |
| P-256 (kx) | Yes | **Yes** | Both providers |
| P-384 (kx) | Yes | **Yes** | Both providers |
| **X25519** | **No** | **No** | No provider impl |
| **P-521** | **No** | **No** | No provider impl |

### Crypto verdict

Only **ECDSA P-256/P-384** certs and **AES-GCM** suites work.

---

## Extensions

| Extension | CH | SH | HRR | EE | CR | Status |
|---|---|---|---|---|---|---|
| supported_versions | Y | Y | Y | — | — | **DONE** |
| supported_groups | Y | — | — | — | — | **DONE** |
| key_share | Y | Y | Y | — | — | **DONE** |
| signature_algorithms | Y | — | — | — | Y | **DONE** |
| cookie | Cond | — | Y | — | — | **DONE** |
| use_srtp | Y | — | — | Y | — | **DONE** |
| certificate_authorities | — | — | — | — | Y | **PARTIAL** |
| **server_name (SNI)** | — | — | — | — | — | **MISSING** |
| **ALPN** | — | — | — | — | — | **MISSING** |
| pre_shared_key | — | — | — | — | — | **MISSING** |
| early_data | — | — | — | — | — | **MISSING** |
| Unknown extensions | — | — | — | — | — | Ignored |

---

## Other APIs

| Feature | Status | Evidence |
|---|---|---|
| SRTP keying material export | **DONE** | `engine.rs:2020-2069` |
| **General-purpose exporter** | **MISSING** | Secret stored, no API |
| PSK / session resumption | **MISSING** | By design (WebRTC) |

---

## Priority-Ordered Gap Summary

### Bugs (violate MUST or cause incorrect behavior)

1. ~~**Ed25519 and RSA-PSS advertised but non-functional**~~
   **FIXED** — Only ECDSA P-256/P-384 advertised now.

2. ~~**Unknown-epoch records abort entire datagram**~~
   **FIXED** — Per-record silent discard via `Ok(None)`.

3. ~~**Single replay window across epochs**~~
   **FIXED** — Per-epoch `ReplayWindow` in each
   `RecvEpochEntry`.

### Missing MUST/SHOULD features

4. **Alert protocol entirely missing** — No `close_notify`,
   no fatal alerts, no alert processing.

5. **No record size validation** — Incoming records not
   checked against 2^14 / 2^14+256 limits.

6. **No connection closure mechanism** — No `close_notify`,
   no idle timeout, no explicit close API.

7. ~~**ClientHello padding**~~ **FIXED** — Padding extension
   (type 0x0015) fills ClientHello to MTU.

8. **Recv-side decryption failure counting** — SHOULD-level
   DoS protection, not implemented.

### Feature gaps (limit interop but not required)

9. **X25519 key exchange** — RFC 8446 9.1 recommends it.

10. **ChaCha20-Poly1305** — Important without AES-NI.

11. **PSK / session resumption** — Full handshake every time.

12. **General-purpose exporter API** — Secret exists, no API.

13. **SNI / ALPN** — Needed for multi-tenant scenarios.

14. **Prev send key timeout eviction** — Lost ACK = forever.

15. **Version downgrade sentinel** — Only if 1.2 fallback.

---

## Estimated Completeness

- **Core 1-RTT protocol**: ~90%
- **Full RFC 9147 compliance**: ~60-65%
- **WebRTC/SRTP production** (ECDSA, AES-GCM): ~85-90%
