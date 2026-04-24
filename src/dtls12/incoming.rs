use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use subtle::ConstantTimeEq;

use crate::Error;
use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};
use crate::dtls12::message::{ContentType, DTLSRecord, Dtls12CipherSuite, Handshake, Sequence};
use crate::util::recover_inner_content_type;

/// Holds both the UDP packet and the parsed result of that packet.
pub struct Incoming {
    // Box is here to reduce the size of the Incoming struct
    // to be passed in register instead of using memmove.
    records: Box<Records>,
}

impl Incoming {
    pub fn records(&self) -> &Records {
        &self.records
    }

    pub fn first(&self) -> &Record {
        // Invariant: Every Incoming must have at least one Record
        // or the parser of Incoming returns None.
        &self.records()[0]
    }

    pub fn into_records(self) -> impl Iterator<Item = Record> {
        self.records.records.into_iter()
    }
}

impl Incoming {
    /// Parse an incoming UDP packet
    ///
    /// * `packet` is the data from the UDP socket.
    /// * `decrypt` provides the decryption operations for encrypted records.
    /// * `cs` is the negotiated cipher suite, if any.
    ///
    /// Will surface parser errors.
    pub fn parse_packet(
        packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls12CipherSuite>,
    ) -> Result<Option<Self>, Error> {
        // Parse records directly from packet, copying each record ONCE into its own buffer
        let records = Records::parse(packet, decrypt, cs)?;

        // We need at least one Record to be valid. For replayed frames, we discard
        // the records, hence this might be None
        if records.records.is_empty() {
            return Ok(None);
        }

        let records = Box::new(records);

        Ok(Some(Incoming { records }))
    }
}

/// A number of records parsed from a single UDP packet.
#[derive(Debug)]
pub struct Records {
    pub records: ArrayVec<Record, 8>,
}

impl Records {
    pub fn parse(
        mut packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls12CipherSuite>,
    ) -> Result<Records, Error> {
        let mut parsed_records: ArrayVec<Record, 8> = ArrayVec::new();
        let our_cid_len = decrypt.our_cid().map_or(0, |c| c.len());

        // Find record boundaries and copy each record ONCE from the packet
        while !packet.is_empty() {
            // CID records have the CID between sequence and length fields,
            // so the header is larger: 11 + cid_len + 2 instead of 13.
            let is_cid_record = packet[0] == ContentType::Tls12Cid.as_u8();
            if is_cid_record && decrypt.our_cid().is_none() {
                // RFC 9146 §4 / RFC 6347 §4.1.2.7: a tls12_cid record for a
                // direction where we did not negotiate CID MUST be discarded,
                // and plan §4 says coalesced records in the same datagram
                // MUST still be processed *when framing permits*. Without a
                // negotiated inbound CID we don't know how many CID bytes
                // follow the sequence-number, so the length field at
                // `packet[11..13]` is only trustworthy if the sender used a
                // zero-length CID.
                //
                // Two-step recovery: (1) best-effort skip assuming
                // zero-length CID; (2) sanity-check that the bytes landed on
                // a plausible DTLS record header — a known ContentType plus a
                // length field that fits inside the datagram. If validation
                // fails we break rather than blindly advance into whatever an
                // attacker-controlled CID payload looked like. This caps the
                // damage of a crafted non-zero-CID stray to the remainder of
                // *this* datagram: we drop coalesced records we can't
                // re-synchronize on, but we never feed desynchronized bytes
                // into AEAD verification on a legitimate record.
                //
                // Security envelope: DoS-only. A crafted stray tls12_cid
                // record from a peer that never negotiated CID can waste the
                // rest of the datagram's parseable records, but it cannot
                // forge or alter any authenticated record — every real
                // record still runs through AEAD verification with its own
                // sequence-number-bound AAD.
                if packet.len() < DTLSRecord::HEADER_LEN {
                    // RFC 6347 §4.1.2.7 / RFC 9146 §6: silently discard.
                    trace!("Discarding CID record: datagram shorter than header");
                    break;
                }
                let stray_length = u16::from_be_bytes([packet[11], packet[12]]) as usize;
                let stray_end = DTLSRecord::HEADER_LEN + stray_length;
                if stray_end > packet.len() {
                    trace!(
                        "Discarding CID record: CID not negotiated, claimed length \
                         runs past datagram"
                    );
                    break;
                }
                if stray_end == packet.len() {
                    // Skip lands exactly at end-of-datagram — nothing more to
                    // frame, drop cleanly.
                    trace!("Discarding CID record: CID not negotiated (datagram end)");
                    break;
                }
                // Validate the post-skip bytes look like a plausible DTLS
                // record header before we commit to advancing. If not, we've
                // almost certainly desynchronized off of a non-zero-CID stray
                // and the safe move is to drop the datagram remainder.
                if packet.len() - stray_end < DTLSRecord::HEADER_LEN {
                    trace!("Discarding CID record: post-skip remainder below header size");
                    break;
                }
                let next_ct = packet[stray_end];
                let plausible_next_ct = matches!(
                    next_ct,
                    20 // ChangeCipherSpec
                    | 21 // Alert
                    | 22 // Handshake
                    | 23 // ApplicationData
                    | 25 // Tls12Cid
                );
                if !plausible_next_ct {
                    trace!(
                        "Discarding CID record: post-skip ContentType {} implausible, \
                         dropping datagram remainder",
                        next_ct
                    );
                    break;
                }
                // Any subsequent record's length field must also fit the
                // remaining datagram. If not, we desynchronized.
                let next_length =
                    u16::from_be_bytes([packet[stray_end + 11], packet[stray_end + 12]]) as usize;
                let next_end = stray_end + DTLSRecord::HEADER_LEN + next_length;
                // For a CID-typed follow-on we can't know its length field
                // position without the CID length either; the outer loop will
                // re-check and handle it via this same branch. For all other
                // ContentTypes the length field is at the standard offset, so
                // we validate here.
                if next_ct != 25 && next_end > packet.len() {
                    trace!(
                        "Discarding CID record: post-skip length field implies \
                         overshoot, dropping datagram remainder"
                    );
                    break;
                }
                trace!("Discarding CID record: CID not negotiated");
                packet = &packet[stray_end..];
                continue;
            }
            let header_len = if is_cid_record {
                DTLSRecord::HEADER_LEN + our_cid_len
            } else {
                DTLSRecord::HEADER_LEN
            };

            if packet.len() < header_len {
                if is_cid_record {
                    // RFC 9146 §6: malformed CID-framed records are silently
                    // discarded so a stray/forged tls12_cid cannot tear down
                    // the association.
                    trace!(
                        "Discarding CID record: datagram remainder ({}) shorter than header ({})",
                        packet.len(),
                        header_len
                    );
                    break;
                }
                return Err(Error::ParseIncomplete);
            }

            // Length field is at the end of the header (last 2 bytes)
            let length_offset = header_len - 2;
            // unwrap: length_offset + 2 = header_len and the `packet.len() <
            // header_len` check above guarantees at least header_len bytes
            // remain, so the 2-byte slice always converts into [u8; 2].
            let length_bytes: [u8; 2] =
                packet[length_offset..length_offset + 2].try_into().unwrap();
            let length = u16::from_be_bytes(length_bytes) as usize;
            let record_end = header_len + length;

            if packet.len() < record_end {
                if is_cid_record {
                    // RFC 9146 §6: silent-discard a CID record whose length
                    // field overshoots the datagram remainder.
                    trace!(
                        "Discarding CID record: claimed length {} overshoots datagram remainder {}",
                        record_end,
                        packet.len()
                    );
                    break;
                }
                return Err(Error::ParseIncomplete);
            }

            // This is the ONLY copy: packet -> record buffer
            let record_slice = &packet[..record_end];
            match Record::parse(record_slice, decrypt, cs) {
                Ok(record) => {
                    if let Some(record) = record {
                        if parsed_records.try_push(record).is_err() {
                            return Err(Error::TooManyRecords);
                        }
                    }
                    // `Ok(None)` is a silent discard per RFC 6347 §4.1.2.7.
                    // Each drop site inside `Record::parse` /
                    // `Record::decrypt_record` emits its own `trace!` with
                    // the specific reason (replay, parse failure,
                    // legacy-framed-when-CID-expected, wire CID mismatch,
                    // AEAD failure, bogus inner type), so no generic
                    // message here — it would mis-diagnose every drop as
                    // replay.
                }
                Err(e) => return Err(e),
            }

            packet = &packet[record_end..];
        }

        let mut records = ArrayVec::new();
        for record in parsed_records {
            if let Some(record) = decrypt.classify_record(record)? {
                records
                    .try_push(record)
                    .expect("filtered records cannot exceed parsed records");
            }
        }

        Ok(Records { records })
    }
}

impl Deref for Records {
    type Target = [Record];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

pub struct Record {
    buffer: Buf,
    // Box is here to reduce the size of the Record struct
    // to be passed in register instead of using memmove.
    parsed: Box<ParsedRecord>,
}

impl Record {
    /// The first parse pass only parses the DTLSRecord header which is unencrypted.
    /// Copies record data from UDP packet ONCE into a pooled buffer.
    pub fn parse(
        record_slice: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls12CipherSuite>,
    ) -> Result<Option<Record>, Error> {
        let is_cid_record = record_slice[0] == ContentType::Tls12Cid.as_u8();
        let our_cid_len = if is_cid_record {
            decrypt.our_cid().map_or(0, |c| c.len())
        } else {
            0
        };

        // ONLY COPY: UDP packet slice -> pooled buffer.
        // For CID records, keep the original wire format (with CID bytes) so that
        // enable_peer_encryption() can re-parse from the same buffer later.
        let mut buffer = Buf::new();
        buffer.extend_from_slice(record_slice);

        // For CID records, create a temporary stripped buffer for DTLSRecord::parse.
        // The real buffer retains the original CID format.
        let parsed = if is_cid_record {
            let mut tmp = Buf::new();
            tmp.extend_from_slice(&record_slice[..11]);
            tmp.extend_from_slice(&record_slice[11 + our_cid_len..]);
            match ParsedRecord::parse(&tmp, cs, 0) {
                Ok(p) => p,
                Err(e) => {
                    trace!("Discarding CID record: parse failed: {}", e);
                    return Ok(None);
                }
            }
        } else {
            match ParsedRecord::parse(&buffer, cs, 0) {
                Ok(p) => p,
                Err(e) => {
                    // RFC 6347 §4.1.2.7: Invalid records SHOULD be silently discarded.
                    trace!("Discarding record: parse failed: {}", e);
                    return Ok(None);
                }
            }
        };

        let parsed = Box::new(parsed);
        let record = Record { buffer, parsed };

        // It is not enough to only look at the epoch, since to be able to decrypt the entire
        // preceeding set of flights sets up the cryptographic context. In a situation with
        // packet loss, we can end up seeing epoch 1 records before we can decrypt them.
        //
        // Epoch-0 `tls12_cid` records cannot reach this point: `DTLSRecord::parse`
        // (`src/dtls12/message/record.rs:68-78`) only lets epoch-0 content
        // types in `{ChangeCipherSpec, Alert, Handshake}`, so a `tls12_cid`
        // content type at epoch 0 fails parse and is silently dropped by
        // the `Ok(None)` branch above. RFC 9146 §3 "once encryption is
        // enabled" is therefore enforced at the parse layer, not here.
        let is_epoch_0 = record.record().sequence.epoch == 0;

        if is_epoch_0 || !decrypt.is_peer_encryption_enabled() {
            // Pre-CCS CID records get queued for post-CCS decryption
            // (handshake loss can deliver an epoch-1 Finished before the
            // CCS). Round-5 review #2: cheap cleartext filter — require
            // the wire CID to match the negotiated inbound CID before
            // consuming a `queue_rx` slot. A spray attacker can otherwise
            // fill `queue_rx` with forged CID-framed records at near-zero
            // cost (all CID bytes are attacker-controlled in cleartext).
            // Legitimate peers always emit the negotiated CID, so this
            // does not affect the normal queue-and-decrypt flow. The
            // authenticating check at AEAD time is unchanged.
            if is_cid_record && !is_epoch_0 {
                // Wire CID sits at record.buffer[11..11+our_cid_len].
                // `our_cid_len > 0` implies framing with CID bytes
                // (zero-length CID routes through legacy framing per
                // RFC 9146 §3 and never hits this branch).
                if our_cid_len > 0 {
                    if let Some(expected) = decrypt.our_cid() {
                        let wire = &record.buffer[11..11 + our_cid_len];
                        if wire.ct_eq(expected).unwrap_u8() == 0 {
                            trace!(
                                "Discarding pre-CCS CID record: wire CID does not \
                                 match negotiated inbound CID"
                            );
                            return Ok(None);
                        }
                    }
                }
            }
            return Ok(Some(record));
        }

        Self::decrypt_record(record, decrypt, cs)
    }

    /// Decrypt a record (CID or standard) and re-parse the result.
    fn decrypt_record(
        record: Record,
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls12CipherSuite>,
    ) -> Result<Option<Record>, Error> {
        let is_cid_record = record.buffer[0] == ContentType::Tls12Cid.as_u8();
        let our_cid_len = if is_cid_record {
            decrypt.our_cid().map_or(0, |c| c.len())
        } else {
            0
        };

        // RFC 9146 §3: "When receiving a datagram without `tls12_cid`, the
        // receiver ... if a non-zero-length CID is expected, the datagram
        // MUST be treated as invalid." We reach this branch only for epoch-1+
        // records (epoch-0 plaintext is short-circuited upstream). If the
        // association expects a non-zero inbound CID (`our_cid().is_some()`
        // reports framing-live inbound), a legacy-framed epoch-1 record is
        // invalid and must be silently discarded per RFC 6347 §4.1.2.7 —
        // without advancing the replay window.
        if !is_cid_record && decrypt.our_cid().is_some() {
            trace!(
                "Discarding legacy-framed epoch-{} record: inbound CID expected",
                record.record().sequence.epoch
            );
            return Ok(None);
        }

        let sequence = record.record().sequence;

        // Anti-replay check (read-only, does not update window)
        if !decrypt.replay_check(sequence) {
            trace!(
                "Discarding record: replay check failed (epoch={}, seq={})",
                sequence.epoch, sequence.sequence_number
            );
            return Ok(None);
        }

        // A CID record can reach the decrypt path only if inbound CID is active.
        // `Records::parse` accepts CID-framed records as soon as `our_cid` is
        // negotiated — that lets records reordered ahead of the peer's
        // ChangeCipherSpec be queued for later decryption. By the time decryption
        // runs (either here after CCS, or via `enable_peer_encryption`'s re-parse
        // of the queue) `inbound_cid_active()` must be `Some`. Any other
        // arrangement is a state-machine error; drop silently rather than
        // feeding an unauthenticated CID length into AAD construction.
        //
        // RFC 9146 §5.3 binds the CID into the AAD so tampering is detectable
        // at the AEAD layer. We capture the wire CID bytes before stripping
        // and require them (constant-time) to match the negotiated inbound
        // CID. A mismatch is a silent drop per RFC 6347 §4.1.2.7 — no error
        // surfaced to the state machine, and the replay window is NOT
        // advanced on the tampered sequence, so a legitimate retransmit at
        // the same sequence still decrypts.
        //
        // Note: only the CID *value* is authenticated here. The CID *length*
        // used for framing (via `our_cid_len`) comes from local config and is
        // authenticated implicitly via AEAD-tag failure on any mis-framed
        // record — not by this check.
        let mut wire_cid: ArrayVec<u8, 255> = ArrayVec::new();
        if is_cid_record {
            let Some(expected_cid) = decrypt.inbound_cid_active() else {
                trace!("Discarding CID record: inbound CID not active");
                return Ok(None);
            };
            if our_cid_len > 0 {
                // Bounds: Records::parse validated record_slice.len() >= 13 +
                // our_cid_len before copying into record.buffer, so
                // [11..11+our_cid_len] is safe.
                wire_cid
                    .try_extend_from_slice(&record.buffer[11..11 + our_cid_len])
                    .expect("our_cid_len <= 255 by config validation");

                if wire_cid.as_slice().ct_eq(expected_cid).unwrap_u8() == 0 {
                    trace!("Discarding CID record: wire CID does not match negotiated CID");
                    return Ok(None);
                }
            }
        }

        // For CID records, strip CID bytes from buffer now that we're
        // decrypting. This gives us the standard 13-byte header layout
        // needed for decryption. The strip is done **in place** on the
        // record's own `Buf` — shift `[11+cid_len..]` left by `cid_len`
        // and truncate — avoiding a second pooled allocation per CID
        // record. Safe because `record.buffer` is owned here and is
        // about to be further mutated (inner content-type rewrite at
        // the post-decrypt header patch below).
        let mut buffer = record.buffer;
        if is_cid_record && our_cid_len > 0 {
            let new_len = buffer.len() - our_cid_len;
            buffer.copy_within(11 + our_cid_len.., 11);
            buffer.truncate(new_len);
        }

        // Re-parse the (possibly stripped) buffer to get a DTLSRecord for AAD/nonce
        let (_, dtls) = DTLSRecord::parse(&buffer, 0, 0)
            .map_err(|_| Error::ParseError(nom::error::ErrorKind::Fail))?;

        let explicit_nonce_len = decrypt.explicit_nonce_len();
        let aead_overhead = decrypt.aead_overhead();

        // RFC 6347 §4.1.2.7: invalid records SHOULD be silently discarded.
        // A peer-controlled `dtls.length` below the minimum AEAD overhead
        // (explicit_nonce_len + tag_len) cannot contain a valid ciphertext
        // + tag, and would underflow the `[ciph..]` slice below. Reject it
        // without advancing the replay window, so a legitimate retransmit
        // at the same sequence still decrypts.
        if (dtls.length as usize) < aead_overhead {
            trace!(
                "Discarding record: length {} below AEAD overhead {}",
                dtls.length, aead_overhead
            );
            return Ok(None);
        }

        // RFC 9146 §5.3 / RFC 6347 §4.1.1: `length_of_DTLSInnerPlaintext`
        // (CID) and `DTLSPlaintext.length` (legacy) MUST NOT exceed 2^14.
        // The send path enforces this before encryption; mirror the check
        // on receive so a mis-behaving peer (with the session key) cannot
        // assert an inner length > 2^14 in the AAD. Silent-drop per
        // §4.1.2.7; replay window stays put because we have not yet
        // attempted decryption.
        let inner_plaintext_len_usize = (dtls.length as usize) - aead_overhead;
        if inner_plaintext_len_usize > super::engine::DTLS12_MAX_PLAINTEXT_LEN {
            trace!(
                "Discarding record: inner plaintext length {} exceeds RFC 2^14 ceiling",
                inner_plaintext_len_usize
            );
            return Ok(None);
        }

        let (aad, nonce) = if is_cid_record {
            let inner_plaintext_len = inner_plaintext_len_usize as u16;
            // Feed the wire-observed CID (not the locally cached copy) into AAD
            // construction. After the ct_eq check above they are equal, but the
            // defensive posture matters for future refactors.
            decrypt.decryption_aad_and_nonce_cid(&dtls, &buffer, &wire_cid, inner_plaintext_len)
        } else {
            decrypt.decryption_aad_and_nonce(&dtls, &buffer)
        };

        // Local shorthand for where the encrypted ciphertext starts
        let ciph = DTLSRecord::HEADER_LEN + explicit_nonce_len;

        // The encrypted part is after the DTLS header and optional explicit nonce.
        let ciphertext = &mut buffer[ciph..];

        let new_len = {
            let mut buffer = TmpBuf::new(ciphertext);

            // This decrypts in place. RFC 6347 §4.1.2.7: a forged ciphertext
            // (AEAD tag mismatch) is an invalid record — silently discarded,
            // preserving the association. The replay window is intentionally
            // NOT advanced on failure (RFC 6347 §4.1.2.6), so a legitimate
            // retransmit at the same sequence still decrypts.
            match decrypt.decrypt_data(&mut buffer, aad, nonce) {
                Ok(()) => buffer.len(),
                Err(Error::CryptoError(_)) => {
                    trace!("Discarding record: AEAD decryption failed");
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        };

        // AEAD succeeded. For CID records the `DTLSInnerPlaintext` unwrap
        // and its sanity checks are themselves AEAD-covered (they live
        // inside the ciphertext), so we run them *before* the replay
        // window update — a peer bug that ships a nested `tls12_cid` or
        // unknown inner type then no longer consumes a sequence number
        // from the window. RFC 6347 §4.1.2.6 only requires "updates
        // after MAC success"; this is a tighter local invariant that
        // reserves the sequence space for semantically valid records.
        let cid_inner_rewrite: Option<(u8, usize)> = if is_cid_record {
            let decrypted = &buffer[ciph..ciph + new_len];
            let (real_content_type, content_len) = match recover_inner_content_type(decrypted) {
                Ok(v) => v,
                Err(_) => {
                    trace!("Discarding CID record: invalid inner content type");
                    return Ok(None);
                }
            };
            if matches!(real_content_type, ContentType::Tls12Cid | ContentType::Ack) {
                trace!(
                    "Discarding CID record: disallowed inner content type {:?}",
                    real_content_type
                );
                return Ok(None);
            }
            Some((real_content_type.as_u8(), content_len))
        } else {
            None
        };

        // RFC 6347 §4.1.2.6: "The receive window is updated only if the
        // MAC verification succeeds." We additionally require the CID
        // inner-type unwrap above to succeed, so malformed post-auth
        // plaintext does not poison the sequence space.
        decrypt.replay_update(sequence);

        if let Some((content_type_byte, content_len)) = cid_inner_rewrite {
            // Rewrite the buffer header with the real content type and content length
            buffer[0] = content_type_byte;
            buffer[11] = (content_len >> 8) as u8;
            buffer[12] = content_len as u8;
        } else {
            // Update the length of the record.
            buffer[11] = (new_len >> 8) as u8;
            buffer[12] = new_len as u8;
        }

        let parsed = ParsedRecord::parse(&buffer, cs, explicit_nonce_len)?;
        let parsed = Box::new(parsed);

        Ok(Some(Record { buffer, parsed }))
    }

    pub fn record(&self) -> &DTLSRecord {
        &self.parsed.record
    }

    pub fn handshakes(&self) -> &[Handshake] {
        &self.parsed.handshakes
    }

    pub fn first_handshake(&self) -> Option<&Handshake> {
        self.parsed.handshakes.first()
    }

    pub fn is_handled(&self) -> bool {
        if self.parsed.handshakes.is_empty() {
            self.parsed.handled.load(Ordering::Relaxed)
        } else {
            self.parsed.handshakes.iter().all(|h| h.is_handled())
        }
    }

    pub fn set_handled(&self) {
        // Handshakes should be empty because we set_handled() on them individually
        // during defragmentation. set_handled() on the record is only for non-handshakes.
        assert!(self.parsed.handshakes.is_empty());
        self.parsed.handled.store(true, Ordering::Relaxed);
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub(crate) fn into_buffer(self) -> Buf {
        self.buffer
    }
}

pub struct ParsedRecord {
    record: DTLSRecord,
    handshakes: ArrayVec<Handshake, 8>,
    handled: AtomicBool,
}

impl ParsedRecord {
    pub fn parse(
        input: &[u8],
        cipher_suite: Option<Dtls12CipherSuite>,
        offset: usize,
    ) -> Result<ParsedRecord, Error> {
        let (_, record) = DTLSRecord::parse(input, 0, offset)?;

        let handshakes = if record.content_type == ContentType::Handshake {
            // This will also return None on the encrypted Finished after ChangeCipherSpec.
            // However we will then decrypt and try again.
            let fragment_offset = record.fragment_range.start;
            parse_handshakes(record.fragment(input), fragment_offset, cipher_suite)
        } else {
            ArrayVec::new()
        };

        Ok(ParsedRecord {
            record,
            handshakes,
            handled: AtomicBool::new(false),
        })
    }
}

/// Trait abstracting record parsing-time handling for incoming records.
///
/// This decouples the record parser from the full `Engine`, allowing the parse loop
/// to decrypt records, classify control records, and queue only the records that
/// should survive into `Incoming`.
pub trait RecordHandler {
    fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error>;
    fn is_peer_encryption_enabled(&self) -> bool;
    fn replay_check(&self, seq: Sequence) -> bool;
    fn replay_update(&mut self, seq: Sequence);
    fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord, buf: &[u8]) -> (Aad, Nonce);
    /// Build AAD and nonce for a CID record (RFC 9146).
    fn decryption_aad_and_nonce_cid(
        &self,
        dtls: &DTLSRecord,
        buf: &[u8],
        cid: &[u8],
        inner_plaintext_len: u16,
    ) -> (Aad, Nonce);
    fn explicit_nonce_len(&self) -> usize;
    fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error>;
    /// Returns the CID value to expect in incoming `tls12_cid` framing, if
    /// any. Per RFC 9146 §3:
    ///
    /// - `None` — CID was not negotiated for this direction, OR the
    ///   negotiated inbound length was zero (legacy RFC 6347 framing). In
    ///   either case, `tls12_cid` records arriving on this engine are
    ///   unsolicited and must be dropped via the two-step recovery.
    /// - `Some(cid)` — CID was negotiated with non-zero inbound length;
    ///   incoming records use `tls12_cid` framing with `cid.len()` bytes
    ///   between the sequence-number and length fields. `cid` is the
    ///   expected value and is authenticated at the AEAD layer.
    ///
    /// A `None` return with a negotiated-but-zero-length inbound CID is
    /// distinct from "CID not negotiated at all" at the reporting layer
    /// (`Engine::inbound_cid()`), but at the framing layer both cases mean
    /// the same thing: legacy RFC 6347 record format.
    fn our_cid(&self) -> Option<&[u8]>;
    /// Returns `Some(expected_cid_bytes)` once inbound CID is armed — i.e. the
    /// peer's ChangeCipherSpec has been processed and we are prepared to
    /// authenticate CID-framed records at the AEAD layer; `None` otherwise.
    ///
    /// Fusing activation and value here removes a cross-type invariant the
    /// decrypt path would otherwise rely on (`inbound_cid_active` → `our_cid`
    /// is `Some`). Distinct from `our_cid()`, which reports the negotiated
    /// value regardless of activation so pre-CCS CID records can still be
    /// framed and queued for later decryption.
    fn inbound_cid_active(&self) -> Option<&[u8]>;
    /// Returns the total AEAD overhead (explicit nonce + tag) for this cipher suite.
    fn aead_overhead(&self) -> usize;
}

fn parse_handshakes(
    mut input: &[u8],
    mut base_offset: usize,
    cipher_suite: Option<Dtls12CipherSuite>,
) -> ArrayVec<Handshake, 8> {
    let mut handshakes = ArrayVec::new();
    while !input.is_empty() {
        if let Ok((remaining, handshake)) = Handshake::parse(input, base_offset, cipher_suite, true)
        {
            let len = input.len() - remaining.len();
            base_offset += len;
            input = remaining;
            if handshakes.try_push(handshake).is_err() {
                break;
            }
        } else {
            break;
        }
    }
    handshakes
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("records", &self.records())
            .finish()
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("record", &self.parsed.record)
            .field("handshakes", &self.parsed.handshakes)
            .finish()
    }
}

/*
Why it is sound to assert UnwindSafe for Incoming

- No internal unwind boundaries: this crate does not use catch_unwind. We do not
  cross panic boundaries internally while mutating state. This marker exists to
  document that external callers can wrap our APIs in catch_unwind without
  observing broken invariants from this type.

- Read-only builders: our dependent builders (e.g., ParsedRecord::parse) take
  only a &[u8] to the buffer and do not mutate the buffer during construction.
  An unwind during builder execution therefore cannot leave the buffer partially
  mutated across a boundary.

- Decrypt-and-reparse is publish-after-complete: when decrypting we first extract
  the buffer, mutate it (length update, in-place decrypt), and only then construct
  a fresh Record from the fully transformed bytes. If a panic occurs mid-transformation,
  the new Record is not built and the previously-built Record is dropped; no
  consumer can observe a half-transformed record across an unwind boundary.

- Interior mutability is benign across unwind: the only interior mutability is
  AtomicBool "handled" flags. They are monotonic (false -> true). If an external
  caller catches a panic and continues, the worst effect is conservatively
  skipping work already done. This does not introduce memory unsafety or aliasing
  violations, and no invariants rely on "handled implies delivery".

Given the above, an unwind cannot leave Incoming in a state where broken
invariants are later observed across a catch_unwind boundary. Marking Incoming
as UnwindSafe is a sound assertion and clarifies behavior for callers.
*/
impl std::panic::UnwindSafe for Incoming {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestHandler {
        classify_calls: usize,
        dropped_alerts: usize,
    }

    impl RecordHandler for TestHandler {
        fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
            self.classify_calls += 1;
            if record.record().content_type == ContentType::Alert {
                self.dropped_alerts += 1;
                return Ok(None);
            }
            Ok(Some(record))
        }

        fn is_peer_encryption_enabled(&self) -> bool {
            false
        }

        fn replay_check(&self, _seq: Sequence) -> bool {
            panic!("replay_check should not be called for plaintext tests");
        }

        fn replay_update(&mut self, _seq: Sequence) {
            panic!("replay_update should not be called for plaintext tests");
        }

        fn decryption_aad_and_nonce(&self, _dtls: &DTLSRecord, _buf: &[u8]) -> (Aad, Nonce) {
            panic!("decryption_aad_and_nonce should not be called for plaintext tests");
        }

        fn decryption_aad_and_nonce_cid(
            &self,
            _dtls: &DTLSRecord,
            _buf: &[u8],
            _cid: &[u8],
            _inner_plaintext_len: u16,
        ) -> (Aad, Nonce) {
            panic!("decryption_aad_and_nonce_cid should not be called for plaintext tests");
        }

        fn explicit_nonce_len(&self) -> usize {
            panic!("explicit_nonce_len should not be called for plaintext tests");
        }

        fn decrypt_data(
            &mut self,
            _ciphertext: &mut TmpBuf,
            _aad: Aad,
            _nonce: Nonce,
        ) -> Result<(), Error> {
            panic!("decrypt_data should not be called for plaintext tests");
        }

        fn our_cid(&self) -> Option<&[u8]> {
            None
        }

        fn inbound_cid_active(&self) -> Option<&[u8]> {
            None
        }

        fn aead_overhead(&self) -> usize {
            0
        }
    }

    fn build_record(content_type: ContentType, epoch: u16, seq: u64, fragment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(content_type.as_u8());
        out.extend_from_slice(&[0xFE, 0xFD]);
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..]);
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    #[test]
    fn parse_packet_filters_control_records_after_packet_validation() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&build_record(ContentType::Alert, 0, 1, &[0x01, 0x00]));
        packet.extend_from_slice(&build_record(
            ContentType::ApplicationData,
            1,
            2,
            &[0xAA, 0xBB],
        ));

        let mut handler = TestHandler::default();
        let incoming = Incoming::parse_packet(&packet, &mut handler, None)
            .unwrap()
            .expect("application data record should remain");

        assert_eq!(handler.classify_calls, 2);
        assert_eq!(handler.dropped_alerts, 1);
        assert_eq!(incoming.records().len(), 1);
        assert_eq!(
            incoming.first().record().content_type,
            ContentType::ApplicationData
        );
        assert_eq!(incoming.first().record().sequence.epoch, 1);
    }

    /// Minimal RecordHandler stub for exercising decrypt-path gating without
    /// standing up a full Engine/handshake. The AAD, nonce, and decrypt hooks
    /// all panic on invocation — the regression test asserts the CID gate
    /// drops the record *before* any of them are touched.
    struct GateStub {
        our_cid: Option<Vec<u8>>,
        inbound_cid_active: bool,
    }

    impl RecordHandler for GateStub {
        fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
            Ok(Some(record))
        }
        fn is_peer_encryption_enabled(&self) -> bool {
            true
        }
        fn replay_check(&self, _: Sequence) -> bool {
            true
        }
        fn replay_update(&mut self, _: Sequence) {}
        fn decryption_aad_and_nonce(&self, _: &DTLSRecord, _: &[u8]) -> (Aad, Nonce) {
            panic!("AAD builder reached — gate must drop CID record first")
        }
        fn decryption_aad_and_nonce_cid(
            &self,
            _: &DTLSRecord,
            _: &[u8],
            _: &[u8],
            _: u16,
        ) -> (Aad, Nonce) {
            panic!("CID AAD builder reached — gate must drop CID record first")
        }
        fn explicit_nonce_len(&self) -> usize {
            0
        }
        fn decrypt_data(&mut self, _: &mut TmpBuf, _: Aad, _: Nonce) -> Result<(), Error> {
            panic!("decrypt_data reached — gate must drop CID record first")
        }
        fn our_cid(&self) -> Option<&[u8]> {
            self.our_cid.as_deref()
        }
        fn inbound_cid_active(&self) -> Option<&[u8]> {
            if self.inbound_cid_active {
                self.our_cid.as_deref()
            } else {
                None
            }
        }
        fn aead_overhead(&self) -> usize {
            0
        }
    }

    /// Build a minimal zero-payload tls12_cid record:
    ///   [0]      content type = 25 (Tls12Cid)
    ///   [1..3]   version = 0xfefd (DTLS 1.2)
    ///   [3..5]   epoch = 1
    ///   [5..11]  sequence = 0
    ///   [11..]   CID bytes
    ///   [..+2]   length = 0
    fn make_cid_record(cid: &[u8]) -> Record {
        let mut buffer = Buf::new();
        buffer.extend_from_slice(&[25, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 0]);
        buffer.extend_from_slice(cid);
        buffer.extend_from_slice(&[0, 0]);

        // `Record::parse` builds `ParsedRecord` from a CID-stripped view so the
        // standard 13-byte DTLS header parser applies; mirror that here.
        let mut stripped = Buf::new();
        stripped.extend_from_slice(&buffer[..11]);
        stripped.extend_from_slice(&buffer[11 + cid.len()..]);
        let parsed =
            Box::new(ParsedRecord::parse(&stripped, None, 0).expect("parse stripped CID record"));

        Record { buffer, parsed }
    }

    /// When `inbound_cid_active` is false, a CID-framed record must be
    /// silently dropped at the decrypt path — before AAD construction, before
    /// the wire CID is consumed, and before any decrypt work happens. Protects
    /// against future refactors that treat `our_cid.is_some()` alone as
    /// sufficient to authenticate CID
    /// framing.
    #[test]
    fn cid_record_dropped_when_inbound_not_active() {
        let cid: &[u8] = b"abcd";
        let record = make_cid_record(cid);

        let mut decrypt = GateStub {
            our_cid: Some(cid.to_vec()),
            inbound_cid_active: false,
        };

        let result = Record::decrypt_record(record, &mut decrypt, None)
            .expect("decrypt path must not surface an error for stray CID");
        assert!(
            result.is_none(),
            "CID record must be dropped when inbound_cid_active is false"
        );
    }

    /// Build a minimal legacy (non-CID) epoch-1 ApplicationData record:
    ///   [0]      content type = 23 (ApplicationData)
    ///   [1..3]   version = 0xfefd (DTLS 1.2)
    ///   [3..5]   epoch = 1
    ///   [5..11]  sequence = 0
    ///   [11..13] length = 0
    fn make_legacy_epoch1_record() -> Record {
        let mut buffer = Buf::new();
        buffer.extend_from_slice(&[23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);

        let parsed =
            Box::new(ParsedRecord::parse(&buffer, None, 0).expect("parse legacy epoch-1 record"));
        Record { buffer, parsed }
    }

    /// RFC 9146 §3: on an association that expects a non-zero inbound CID,
    /// a legacy-framed (non-`tls12_cid`) encrypted record is invalid and MUST
    /// be silently discarded. The gate fires at `decrypt_record` before AAD
    /// construction, before replay update, and before any AEAD work — the
    /// decrypt stubs in `GateStub` panic if
    /// reached, so reaching this test without a drop is a loud failure.
    #[test]
    fn legacy_framed_record_dropped_when_inbound_cid_expected() {
        let cid: &[u8] = b"abcd";
        let record = make_legacy_epoch1_record();

        // CID is negotiated and inbound is live, so this association expects
        // incoming `tls12_cid` framing for all epoch-1 records. A legacy
        // content-type-23 record is RFC-invalid and must be dropped.
        let mut decrypt = GateStub {
            our_cid: Some(cid.to_vec()),
            inbound_cid_active: true,
        };

        let result = Record::decrypt_record(record, &mut decrypt, None)
            .expect("decrypt path must not surface an error for legacy-framed drop");
        assert!(
            result.is_none(),
            "legacy-framed epoch-1 record must be dropped when CID framing expected"
        );
    }

    /// Stub that models an authenticated decryption which "succeeds" against
    /// caller-provided plaintext. Feeds a decrypted DTLSInnerPlaintext with a
    /// bogus inner content type past AEAD and into the silent-discard gate.
    struct DecryptStub {
        cid: Vec<u8>,
        inner_plaintext: Vec<u8>,
    }

    impl RecordHandler for DecryptStub {
        fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
            Ok(Some(record))
        }
        fn is_peer_encryption_enabled(&self) -> bool {
            true
        }
        fn replay_check(&self, _: Sequence) -> bool {
            true
        }
        fn replay_update(&mut self, _: Sequence) {}
        fn decryption_aad_and_nonce(&self, _: &DTLSRecord, _: &[u8]) -> (Aad, Nonce) {
            unreachable!("non-CID path not exercised")
        }
        fn decryption_aad_and_nonce_cid(
            &self,
            _: &DTLSRecord,
            _: &[u8],
            _: &[u8],
            _: u16,
        ) -> (Aad, Nonce) {
            (
                Aad::new_dtls12(ContentType::Tls12Cid, Sequence::new(0), [0xFE, 0xFD], 0),
                Nonce([0u8; 12]),
            )
        }
        fn explicit_nonce_len(&self) -> usize {
            0
        }
        fn decrypt_data(&mut self, ciphertext: &mut TmpBuf, _: Aad, _: Nonce) -> Result<(), Error> {
            // Overwrite the ciphertext with our chosen DTLSInnerPlaintext and
            // truncate to its length. The buffer always has at least
            // `inner_plaintext.len()` bytes because `make_cid_record_with_payload`
            // sized it that way.
            let dst = ciphertext.as_mut();
            dst[..self.inner_plaintext.len()].copy_from_slice(&self.inner_plaintext);
            ciphertext.truncate(self.inner_plaintext.len());
            Ok(())
        }
        fn our_cid(&self) -> Option<&[u8]> {
            Some(&self.cid)
        }
        fn inbound_cid_active(&self) -> Option<&[u8]> {
            Some(&self.cid)
        }
        fn aead_overhead(&self) -> usize {
            0
        }
    }

    /// Build a CID record whose ciphertext region has length `inner_len`
    /// so the decrypt path slices cleanly. Actual content is replaced by the
    /// stub inside `decrypt_data`.
    fn make_cid_record_with_payload(cid: &[u8], inner_len: usize) -> Record {
        let mut buffer = Buf::new();
        buffer.extend_from_slice(&[25, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 0]);
        buffer.extend_from_slice(cid);
        // length field (covers the ciphertext region)
        buffer.extend_from_slice(&(inner_len as u16).to_be_bytes());
        for _ in 0..inner_len {
            buffer.push(0);
        }

        let mut stripped = Buf::new();
        stripped.extend_from_slice(&buffer[..11]);
        stripped.extend_from_slice(&buffer[11 + cid.len()..]);
        let parsed =
            Box::new(ParsedRecord::parse(&stripped, None, 0).expect("parse stripped CID record"));

        Record { buffer, parsed }
    }

    /// An authenticated CID record whose inner content type is `tls12_cid`
    /// (nested), `Ack`, or `Unknown(_)` must be silently dropped. RFC 6347
    /// §4.1.2.7 — invalid records SHOULD be silently discarded — and this
    /// must NOT surface as an `Err(..)` that tears down the association.
    #[test]
    fn cid_record_with_bogus_inner_type_is_silently_dropped() {
        let cid: &[u8] = b"cidX";
        // Inner: single type byte with no content, no padding. Each bad type
        // value below must silently drop.
        for bad in [
            ContentType::Tls12Cid.as_u8(),
            99,
            0,
            ContentType::Ack.as_u8(),
        ] {
            let record = make_cid_record_with_payload(cid, 1);
            let mut decrypt = DecryptStub {
                cid: cid.to_vec(),
                inner_plaintext: vec![bad],
            };
            let result = Record::decrypt_record(record, &mut decrypt, None).unwrap_or_else(|e| {
                panic!("bad inner type {} must silent-drop, got Err({:?})", bad, e)
            });
            assert!(
                result.is_none(),
                "bad inner type {} must be dropped (returned Some)",
                bad
            );
        }
    }

    /// Stub that counts replay updates so we can check "AEAD success causes
    /// the window to advance even when the inner content type is bogus".
    /// Per RFC 6347 §4.1.2.6 the window updates on MAC success, regardless
    /// of whether the decrypted plaintext is semantically valid.
    struct CountingDecryptStub {
        cid: Vec<u8>,
        inner_plaintext: Vec<u8>,
        replay_updates: usize,
    }

    impl RecordHandler for CountingDecryptStub {
        fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
            Ok(Some(record))
        }
        fn is_peer_encryption_enabled(&self) -> bool {
            true
        }
        fn replay_check(&self, _: Sequence) -> bool {
            true
        }
        fn replay_update(&mut self, _: Sequence) {
            self.replay_updates += 1;
        }
        fn decryption_aad_and_nonce(&self, _: &DTLSRecord, _: &[u8]) -> (Aad, Nonce) {
            unreachable!("non-CID path not exercised")
        }
        fn decryption_aad_and_nonce_cid(
            &self,
            _: &DTLSRecord,
            _: &[u8],
            _: &[u8],
            _: u16,
        ) -> (Aad, Nonce) {
            (
                Aad::new_dtls12(ContentType::Tls12Cid, Sequence::new(0), [0xFE, 0xFD], 0),
                Nonce([0u8; 12]),
            )
        }
        fn explicit_nonce_len(&self) -> usize {
            0
        }
        fn decrypt_data(&mut self, ciphertext: &mut TmpBuf, _: Aad, _: Nonce) -> Result<(), Error> {
            let dst = ciphertext.as_mut();
            dst[..self.inner_plaintext.len()].copy_from_slice(&self.inner_plaintext);
            ciphertext.truncate(self.inner_plaintext.len());
            Ok(())
        }
        fn our_cid(&self) -> Option<&[u8]> {
            Some(&self.cid)
        }
        fn inbound_cid_active(&self) -> Option<&[u8]> {
            Some(&self.cid)
        }
        fn aead_overhead(&self) -> usize {
            0
        }
    }

    /// Coverage gap #8: RFC 9146 §6 permits a `DTLSInnerPlaintext` whose
    /// `content` is zero bytes — the unwrap should return the lone
    /// `real_type` byte as the content type and `content_len = 0`. Verify
    /// the decrypt path surfaces the correct content type (e.g. Alert, or
    /// ApplicationData with an empty payload) without mis-classifying the
    /// single byte as padding.
    #[test]
    fn cid_record_with_empty_inner_content() {
        let cid: &[u8] = b"empty";
        for content_type in [
            ContentType::Alert.as_u8(),
            ContentType::ApplicationData.as_u8(),
            ContentType::Handshake.as_u8(),
            ContentType::ChangeCipherSpec.as_u8(),
        ] {
            let record = make_cid_record_with_payload(cid, 1);
            let mut decrypt = DecryptStub {
                cid: cid.to_vec(),
                inner_plaintext: vec![content_type],
            };
            let result = Record::decrypt_record(record, &mut decrypt, None)
                .expect("valid empty-content inner plaintext must not error")
                .expect("zero-length content with a valid real_type must surface a Record");
            // Post-decrypt the buffer's outer content type byte carries the
            // recovered inner type and the record length is zero.
            let buf = result.buffer();
            assert_eq!(
                buf[0], content_type,
                "recovered outer content type must match inner real_type"
            );
            let rec_len = u16::from_be_bytes([buf[11], buf[12]]);
            assert_eq!(
                rec_len, 0,
                "zero-length content must surface as length-0, not mis-counted padding"
            );
        }
    }

    /// Round-4 review #2 tightening: a bogus-inner-type drop must NOT
    /// advance the replay window. RFC 6347 §4.1.2.6 only requires that
    /// the window update *after* MAC success; dimpl additionally
    /// requires the CID inner-type unwrap to succeed, so a peer-bug
    /// record that AEAD-authenticates but carries a forbidden inner
    /// content type does not poison the sequence space for legitimate
    /// retransmits. The silent-drop is still there — the association
    /// survives — only the replay slot is preserved.
    #[test]
    fn cid_record_bogus_inner_type_preserves_replay_window() {
        let cid: &[u8] = b"abcd";
        let record = make_cid_record_with_payload(cid, 1);
        let mut decrypt = CountingDecryptStub {
            cid: cid.to_vec(),
            inner_plaintext: vec![ContentType::Tls12Cid.as_u8()],
            replay_updates: 0,
        };
        let result = Record::decrypt_record(record, &mut decrypt, None)
            .expect("silent-drop must not surface an error");
        assert!(result.is_none(), "record must be dropped");
        assert_eq!(
            decrypt.replay_updates, 0,
            "bogus inner type must not consume the sequence number from the window"
        );
    }

    /// Receive-side 2^14 ceiling: a CID record whose `dtls.length`
    /// implies an inner plaintext > `DTLS12_MAX_PLAINTEXT_LEN` (RFC 9146
    /// §5.3 / RFC 6347 §4.1.1) must silently drop *before* AAD
    /// construction, and the replay window must not advance.
    #[test]
    fn cid_record_inner_plaintext_over_2_14_silently_dropped() {
        let cid: &[u8] = b"big";
        // Stub aead_overhead == 0, so dtls.length == inner_plaintext_len.
        // 16385 > DTLS12_MAX_PLAINTEXT_LEN (16384) → must drop.
        let record =
            make_cid_record_with_payload(cid, super::super::engine::DTLS12_MAX_PLAINTEXT_LEN + 1);
        let mut decrypt = CountingDecryptStub {
            cid: cid.to_vec(),
            inner_plaintext: vec![ContentType::ApplicationData.as_u8()],
            replay_updates: 0,
        };
        let result = Record::decrypt_record(record, &mut decrypt, None)
            .expect("over-length record must silent-drop, not error");
        assert!(result.is_none());
        assert_eq!(
            decrypt.replay_updates, 0,
            "drop happens before AEAD; replay window must not advance"
        );
    }

    /// Build a minimal epoch-0 `tls12_cid` record (no encryption).
    fn make_epoch0_cid_record(cid: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::new();
        // type=25, version=DTLS1.2, epoch=0, seq=0
        buffer.extend_from_slice(&[25, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0]);
        buffer.extend_from_slice(cid);
        buffer.extend_from_slice(&[0, 0]); // length = 0
        buffer
    }

    /// RFC 9146 §3 / RFC 6347 §4.1.1: `tls12_cid` framing only applies
    /// once encryption is enabled, so an epoch-0 CID record is invalid
    /// and MUST be silently discarded — and must NOT consume a `queue_rx`
    /// slot, which would otherwise be a DoS amplifier.
    #[test]
    fn epoch0_cid_record_dropped_at_parse() {
        let cid: &[u8] = b"abcd";
        let raw = make_epoch0_cid_record(cid);

        let mut decrypt = GateStub {
            our_cid: Some(cid.to_vec()),
            inbound_cid_active: false,
        };

        let result =
            Record::parse(&raw, &mut decrypt, None).expect("epoch-0 CID parse must not error");
        assert!(
            result.is_none(),
            "epoch-0 tls12_cid record must drop at parse, not enter the queue"
        );
    }
}
