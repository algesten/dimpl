# DTLS 1.3 (RFC 9147) Compliance Audit — dimpl

All analysis performed against the actual source code, February 2026.

---

## Section 4: Record Layer

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| Multiple records per datagram | 4.1 | **DONE** | `incoming.rs:80` — `ArrayVec<Record, 16>` loop |
| No record spanning datagrams | 4.1 | **DONE** | Implicit — single `&[u8]` per parse |
| MTU-based fragmentation | 4.1 | **DONE** | `engine.rs:833,981` — MTU check before every record; default 1150 |
| PMTU discovery | 4.1 | **MISSING** | Fixed config value only |
| DTLSPlaintext header (13 bytes) | 4.2.1 | **DONE** | `record.rs:70-111` parse, `193-199` serialize |
| legacy_record_version accepts 1.0/1.2 | 4.2.1 | **DONE** | `record.rs:77-85` |
| Unified header fixed bits `001` | 4.2.2 | **DONE** | `record.rs:47` detection, `204` serialization |
| C flag (CID) rejected | 4.2.2 | **DONE** | `incoming.rs:92` discards rest of datagram; `record.rs:128` hard error |
| S flag (seq length 8/16 bit) | 4.2.2 | **DONE** | `record.rs:140-146` parses both; always sends S=1 |
| L flag (length present) | 4.2.2 | **DONE** | `record.rs:148-157` parses both; always sends L=1 |
| EE epoch bits (2-bit) | 4.2.2 | **DONE** | `record.rs:138` parse, `engine.rs:942` serialize |
| `sn_key` derivation | 4.2.3 | **DONE** | `engine.rs:1805-1812` — HKDF-Expand-Label("sn") |
| AES-ECB mask for record number encryption | 4.2.3 | **DONE** | `engine.rs:966-972` encrypt, `2243-2267` decrypt |
| ChaCha20 mask variant | 4.2.3 | **N/A** | Suite not offered, so not needed yet |
| XOR mask over seq bytes | 4.2.3 | **DONE** | `engine.rs:1025-1028,1035-1036` |
| Epoch mapping (0=plain, 2=hs, 3+=app) | 4.3 | **DONE** | `engine.rs:2098-2103` |
| Epoch 1 (0-RTT) | 4.3 | **MISSING** | Not supported (optional per RFC) |
| 2-bit epoch wrapping/resolution | 4.3 | **DONE** | `engine.rs:2139-2163` prefers newest match |
| AEAD nonce = IV XOR pad(seq) | 4.4 | **DONE** | `dtls_aead.rs:76-84` |
| AAD = unified header bytes | 4.4 | **DONE** | `engine.rs:946-951` (encrypt), `incoming.rs:247-251` (decrypt). Both use unmasked seq — correct per RFC |
| DTLSInnerPlaintext (content + type + padding) | 4.4 | **DONE** | `engine.rs:910-912` serialize; `incoming.rs:435-448` recovery scans backward past zeros |
| Send-side AEAD limit tracking | 4.5.1 | **DONE** | `engine.rs:1012-1018` — counter + jittered threshold `[3/4*limit, limit]`, triggers KeyUpdate |
| **Recv-side decryption failure counting** | 4.5.1 | **MISSING** | No counter. RFC SHOULD track failures to detect attacks |
| Silent discard on decrypt failure | 4.5.2 | **DONE** | `incoming.rs:264-270` returns `Ok(None)` |
| No alert on invalid record | 4.5.2 | **DONE** | Silent discard only |
| Unknown-epoch record handling | 4.5.2 | **DONE** | All error paths in `Record::parse` return `Ok(None)` for per-record silent discard |
| Plaintext epoch restrictions | 4.5.3 | **DONE** | Only CH/SH at epoch 0 |
| **Max record size (2^14 / 2^14+256)** | 4 | **MISSING** | No incoming or outgoing size validation. MTU limits outgoing in practice, but oversized incoming records are accepted |
| Anti-replay sliding window | 4.5.2 | **DONE** | `window.rs` — 64-bit bitmap per epoch |
| **Per-epoch replay windows** | 4.5.2 | **DONE** | Each `RecvEpochEntry` has its own `ReplayWindow`; handshake epoch 2 has a separate window. Old-epoch records are accepted as long as keys are retained |

### Critical record-layer issues

1. ~~**Unknown-epoch records abort entire datagram** — a single bad record kills all subsequent records in the same UDP packet. Violates the per-record discard requirement.~~ **FIXED**
2. ~~**Single replay window across epochs** — during KeyUpdate, legitimate records on the old epoch are rejected once any new-epoch record is processed.~~ **FIXED**

---

## Section 5: Handshake Protocol

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| legacy_record_version = 0xFEFD | 5.1 | **DONE** | `record.rs:195` |
| legacy_version in CH = 0xFEFD | 5.1 | **DONE** | `client.rs:1069`; server validates at `server.rs:315-319` |
| No ChangeCipherSpec | 5.1 | **DONE** | CCS discarded in `queue.rs:55` |
| Version negotiation via supported_versions | 5.1 | **DONE** | Client sends DTLS 1.3, server validates and echoes |
| 12-byte DTLS handshake header | 5.2 | **DONE** | `handshake.rs:63-80` parse, `124-131` serialize |
| message_seq management (incl. across HRR) | 5.2 | **DONE** | `engine.rs:1057,1069` increment; `1769-1773` NOT reset after HRR per RFC |
| Fragmentation (MTU-aware) | 5.2 | **DONE** | `engine.rs:1046-1147` |
| Reassembly (out-of-order fragments) | 5.2 | **DONE** | Binary-search insertion `engine.rs:377-397`; contiguity check `684-733` |
| Overlapping fragment detection | 5.2 | **PARTIAL** | Sender never produces overlaps. Receiver does not detect them — overlaps corrupt the reassembly buffer. RFC says MAY reject, so acceptable |
| **Transcript hash uses TLS format** | 5.2 | **DONE** | `engine.rs:1062-1067` and `handshake.rs:170-177` — correctly uses msg_type(1) + length(3), strips DTLS framing |
| ClientHello fields | 5.3 | **DONE** | legacy_version, random, empty session_id, empty cookie, cipher_suites, null compression |
| **ClientHello padding (anti-amplification)** | 5.3 | **DONE** | Padding extension (RFC 7685, type 0x0015) fills ClientHello record to the configured MTU |
| Required CH extensions (supported_versions, groups, key_share, sig_algs) | 5.3 | **DONE** | `client.rs:1092-1151` |
| ServerHello legacy_session_id echo | 5.4 | **DONE** | `server.rs:410,640,1197` |
| supported_versions in SH | 5.4 | **DONE** | `server.rs:1170-1180` |
| HRR magic random | 5.5 | **DONE** | `server.rs:69-72` constant, `server_hello.rs:45-47` detection |
| Cookie in HRR | 5.5 | **DONE** | HMAC-SHA256 cookie at `server.rs:1071-1080` |
| key_share in HRR | 5.5 | **DONE** | `server.rs:1110-1122` |
| Transcript replacement (message_hash 0xFE) | 5.5 | **DONE** | `engine.rs:1928-1946` — `0xFE \|\| 00 00 hash_len \|\| Hash(CH1)` |
| Double HRR prevention | 5.5 | **DONE** | Client: `client.rs:378-385`; Server: `server.rs:500-503` |
| CertificateRequest with sig_algs | 5.6 | **DONE** | `server.rs:1248-1291` |
| oid_filters extension in CertReq | 5.6 | **MISSING** | Optional per RFC |
| TLS 1.3 Certificate format | 5.7 | **DONE** | `certificate.rs:24-101` |
| Empty server cert context validated | 5.7 | **DONE** | `client.rs:681-685` |
| CertificateVerify signed content (64 spaces + context + 0x00 + hash) | 5.7 | **DONE** | `client.rs:742-792`; correct context strings for server/client |
| Finished verify_data (HMAC) | 5.7 | **DONE** | `engine.rs:1866-1893` |
| Constant-time Finished comparison | 5.7 | **DONE** | `subtle::ConstantTimeEq` at `client.rs:849-855`, `server.rs:953-959` |
| **HKDF uses "dtls13" prefix (not "tls13 ")** | 5.8 | **DONE** | Every call uses `hkdf_expand_label_dtls13`. Prefix = `b"dtls13"` (6 bytes, no space). Verified in both providers |
| All key schedule labels correct | 5.8 | **DONE** | "derived", "c hs traffic", "s hs traffic", "c ap traffic", "s ap traffic", "exp master", "key", "iv", "sn", "finished", "traffic upd" |
| Epoch 2 keys after SH, epoch 3 after Finished | 5.9 | **DONE** | `client.rs:583-589` (hs keys), `868-874` (app keys) |
| **Version downgrade protection sentinel** | 8446 4.1.3 | **MISSING** | No check for sentinel bytes in ServerHello.random. Acceptable for 1.3-only implementation, but required if 1.2 fallback exists |

---

## Section 6: Alert Protocol

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| **Send alerts** | 6 | **MISSING** | Zero alert records sent anywhere in the codebase |
| **Process received alerts** | 6 | **MISSING** | Alert records land in `queue_rx`, never read — `poll_app_data` filters for `ApplicationData` only (`engine.rs:534`) |
| **close_notify** | 6 | **MISSING** | Not implemented |
| **Fatal alert before teardown** | 6 | **MISSING** | Errors returned to caller, never communicated to peer |

**The entire alert protocol is unimplemented.** This is the single largest compliance gap.

---

## Section 7: ACK Mechanism

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| ACK content type (26) and format | 7 | **DONE** | `engine.rs:1157-1179` — `record_numbers_length(2) + N*(epoch(8)+seq(8))` |
| RTO/4 delay for ACK scheduling | 7 | **DONE** | `engine.rs:1359-1368` |
| Immediate ACK on gap detection | 7 | **DONE** | `engine.rs:1342-1356` — delay=0 on gap |
| ACK scope = handshake only | 7 | **DONE** | `engine.rs:1383-1394` filters epoch 2 + Handshake |
| Selective retransmission | 7 | **DONE** | `engine.rs:658-659` — skips `entry.acked` on resend |
| ACK encrypted in correct epoch | 7 | **DONE** | `engine.rs:1162-1167` — uses app epoch or epoch 2 |
| ACK anti-amplification | 7.3 | **MISSING** | No check preventing ACK of records from higher epoch than current decryption capability |

---

## Section 8: Key Updates

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| KeyUpdate message (type 24, 1-byte body) | 8.1 | **DONE** | `handshake.rs:298-320` |
| Send key rotation (derive next, retain previous) | 8.1 | **DONE** | `engine.rs:1671-1696` — previous keys saved in `prev_app_send_keys` |
| Previous send keys cleared on ACK | 8.1 | **DONE** | `engine.rs:1234-1242` |
| Previous send keys timeout eviction | 8.1 | **MISSING** | No timeout — if ACK is lost, prev keys persist indefinitely |
| Receive multi-epoch (RFC MUST >= 2) | 8.1 | **DONE** | `ArrayVec<RecvEpochEntry, 4>` — supports 4 (exceeds minimum) |
| Oldest recv epoch evicted when full | 8.1 | **DONE** | `engine.rs:1712-1713` |
| AEAD limit auto-KeyUpdate | 8.1 | **DONE** | Jittered threshold, default 2^23, configurable |
| 0-RTT early data | 8.2 | **MISSING** | Not implemented (optional) |
| NewSessionTicket | 8.3 | **MISSING** | Not in DTLS 1.3 message types |
| Post-handshake client auth | 8.3 | **MISSING** | Rejected as renegotiation (`engine.rs:370-375`) |

---

## Section 9: Timer and Retransmission

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| Exponential backoff | 9.1 | **DONE** | `timer.rs` — 2x with +/-0.25s jitter |
| Flight management | 9.1 | **DONE** | `engine.rs:628` begin, `647` resend |
| Duplicate CH triggers resend | 9.1 | **DONE** | `handshake.rs:204-217`, `engine.rs:350-361` |
| Max retries (default 4) | 9.1 | **DONE** | Configurable via `config.rs:36` |
| Handshake timeout (default 40s) | 9.1 | **DONE** | Configurable via `config.rs:37` |

Fully compliant.

---

## Sections 10-11: CID and Connection Closure

| Requirement | RFC | Status | Evidence |
|---|---|---|---|
| CID | 10 | **MISSING** | Optional. Gracefully rejected |
| close_notify | 11 | **MISSING** | See Section 6 |
| Idle timeout | 11 | **MISSING** | Post-handshake returns 10-year timeout (`engine.rs:602`) |
| Explicit close API | 11 | **MISSING** | Connection dies when caller drops the state machine |

---

## Cryptographic Coverage

| Algorithm | Advertised | Functional | Issue |
|---|---|---|---|
| AES-128-GCM-SHA256 | Yes | **Yes** | Mandatory. Both providers. |
| AES-256-GCM-SHA384 | Yes | **Yes** | Both providers. |
| **CHACHA20-POLY1305-SHA256** | **No (in CH)** | **No** | Enum variant exists in `types.rs:590`, listed in `Dtls13CipherSuite::all()`, but NOT in provider lists. ClientHello correctly uses provider list only — safe. But `is_known()` returns true, which is misleading. |
| ECDSA-P256-SHA256 | Yes | **Yes** | Sign + verify in both providers |
| ECDSA-P384-SHA384 | Yes | **Yes** | Sign + verify in both providers |
| Ed25519 | No | No | Not advertised. Dispatch returns explicit error if encountered. Not implemented in either crypto provider. |
| RSA_PSS_RSAE_SHA256 | No | No | Not advertised. Both providers reject `SignatureAlgorithm::RSA`. Not implemented in either crypto provider. |
| RSA PKCS#1 v1.5 | No | Rejected | Correctly rejected per TLS 1.3 |
| P-256 (key exchange) | Yes | **Yes** | Both providers |
| P-384 (key exchange) | Yes | **Yes** | Both providers |
| **X25519** | **No (in CH)** | **No** | `NamedGroup::is_supported()` and `all_supported()` claim it's supported, but no provider implements it. ClientHello correctly uses provider list. RFC 8446 9.1 recommends X25519. |
| **P-521** | **No (in CH)** | **No** | Same as X25519 — type claims supported, no provider |

### Crypto verdict

The implementation can only interoperate with peers using **ECDSA P-256 or P-384 certificates** and **AES-GCM cipher suites**. Only functional schemes are advertised in `signature_algorithms`.

---

## Extensions

| Extension | CH | SH | HRR | EE | CertReq | Status |
|---|---|---|---|---|---|---|
| supported_versions | Yes | Yes | Yes | — | — | **DONE** |
| supported_groups | Yes | — | — | — | — | **DONE** |
| key_share | Yes | Yes | Yes | — | — | **DONE** |
| signature_algorithms | Yes | — | — | — | Yes | **DONE** |
| cookie | Conditional | — | Yes | — | — | **DONE** |
| use_srtp | Yes | — | — | Yes | — | **DONE** (MKI parsed but ignored) |
| certificate_authorities | — | — | — | — | Yes (empty) | **PARTIAL** |
| **server_name (SNI)** | — | — | — | — | — | **MISSING** |
| **ALPN** | — | — | — | — | — | **MISSING** |
| pre_shared_key | — | — | — | — | — | **MISSING** |
| early_data | — | — | — | — | — | **MISSING** |
| Unknown extensions | — | — | — | — | — | **Correctly ignored** per RFC |

---

## Other APIs

| Feature | Status | Evidence |
|---|---|---|
| SRTP keying material export | **DONE** | `engine.rs:2020-2069` — correct 2-step RFC 8446 7.5 derivation with "EXTRACTOR-dtls_srtp" |
| **General-purpose exporter** | **MISSING** | `exporter_master_secret` is derived and stored but no public API for arbitrary label/context exports |
| PSK / session resumption | **MISSING** | By design for WebRTC use case |

---

## Priority-Ordered Gap Summary

### Bugs (violate MUST or cause incorrect behavior)

1. ~~**Ed25519 and RSA-PSS advertised but non-functional** — Advertising schemes in `signature_algorithms` that you cannot verify violates RFC 8446 4.2.3. A peer (e.g., one with an RSA certificate) will select these, and the handshake will fail with a confusing crypto error instead of the peer choosing a different scheme. **Fix: remove Ed25519 and RSA_PSS_RSAE_SHA256 from `SignatureScheme::supported()`**, or implement them.~~ **FIXED** — Removed Ed25519 and RSA_PSS_RSAE_SHA256 from `SignatureScheme::supported()` and `is_supported()`. Only ECDSA-P256-SHA256 and ECDSA-P384-SHA384 are now advertised.

2. ~~**Unknown-epoch records abort entire datagram** — `engine.rs:2222-2228` returns `Err` which propagates through `incoming.rs:153` and kills all subsequent records in the datagram. RFC requires per-record silent discard.~~ **FIXED** — All error paths in `Record::parse` (`ParsedRecord::parse` failure, `decrypt_record` failure, `recover_inner_content_type` failure) now return `Ok(None)` for per-record silent discard instead of propagating `Err` to abort the datagram.

3. ~~**Single replay window across epochs** — During KeyUpdate, legitimate records on the old epoch are permanently rejected once any new-epoch record is seen, even though the old receive keys are still retained. This contradicts retaining multiple receive epochs.~~ **FIXED** — `ReplayWindow` no longer tracks epochs. Each `RecvEpochEntry` now has its own `ReplayWindow`, and handshake epoch 2 has a separate `hs_replay` window. Old-epoch records are accepted as long as the epoch's keys are still retained.

### Missing MUST/SHOULD features

4. **Alert protocol entirely missing** — No `close_notify`, no fatal alerts, no alert processing. The peer cannot distinguish clean shutdown from network failure. Every other implementation expects alerts.

5. **No record size validation** — Incoming records are not checked against 2^14 / 2^14+256 limits.

6. **No connection closure mechanism** — No `close_notify`, no idle timeout, no explicit close API.

7. ~~**ClientHello padding** — SHOULD-level anti-amplification measure, not implemented.~~ **FIXED** — Padding extension (type 0x0015) fills ClientHello to MTU.

8. **Recv-side decryption failure counting** — SHOULD-level DoS protection, not implemented.

### Feature gaps (limit interop but not strictly required)

9. **X25519 key exchange** — RFC 8446 9.1 recommends it. Many peers prefer or require X25519.

10. **ChaCha20-Poly1305** — Important on platforms without AES hardware acceleration.

11. **PSK / session resumption** — Every connection requires a full handshake.

12. **General-purpose exporter API** — Exporter master secret exists but is only exposed for SRTP.

13. **SNI / ALPN** — Needed for multi-tenant or protocol-negotiation scenarios.

14. **Previous send key timeout eviction** — If KeyUpdate ACK is lost, old keys persist forever.

15. **Version downgrade sentinel** — Only relevant if DTLS 1.2 fallback coexists.

---

## Estimated Completeness

- **Core 1-RTT protocol**: ~90% — record layer, handshake, ACK, retransmission, KeyUpdate are solid
- **Full RFC 9147 compliance**: ~60-65% — alerts, closure, PSK/0-RTT, CID, and several signature algorithms missing
- **WebRTC/SRTP production use** (ECDSA peers, AES-GCM): ~85-90% — the happy path works and has 24 real WolfSSL interop tests. All three bugs have been fixed. Main risk is encountering non-ECDSA peers
