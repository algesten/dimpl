use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use std::fmt;

use crate::Error;
use crate::buffer::{Buf, TmpBuf};
use crate::dtls13::message::Sequence;
use crate::dtls13::message::{ContentType, Dtls13CipherSuite};
use crate::dtls13::message::{Dtls13Record, Handshake, MessageType};
use crate::window::ReplayWindow;

/// Holds both the UDP packet and the parsed result of that packet.
pub struct Incoming {
    // Box is here to reduce the size of the Incoming struct
    // to be passed in register instead of using memmove.
    records: Box<Records>,
}

pub(crate) struct IncomingParse {
    pub incoming: Option<Incoming>,
    pub deferred_tail: Option<Buf>,
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
    pub(crate) fn parse_packet_defer_after_key_update(
        packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
    ) -> Result<IncomingParse, Error> {
        Self::parse_packet_inner(packet, decrypt, cs, true)
    }

    fn parse_packet_inner(
        packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
        defer_after_key_update: bool,
    ) -> Result<IncomingParse, Error> {
        // Parse records directly from packet, copying each record ONCE into its own buffer
        let parse = Records::parse_inner(packet, decrypt, cs, defer_after_key_update)?;

        // We need at least one Record to be valid. For replayed frames, we discard
        // the records, hence this might be None
        if parse.records.records.is_empty() {
            return Ok(IncomingParse {
                incoming: None,
                deferred_tail: parse.deferred_tail,
            });
        }

        let records = Box::new(parse.records);

        Ok(IncomingParse {
            incoming: Some(Incoming { records }),
            deferred_tail: parse.deferred_tail,
        })
    }
}

/// A number of records parsed from a single UDP packet.
#[derive(Debug)]
pub struct Records {
    pub records: ArrayVec<Record, 16>,
}

struct RecordsParse {
    records: Records,
    deferred_tail: Option<Buf>,
}

impl Records {
    fn parse_inner(
        mut packet: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
        defer_after_key_update: bool,
    ) -> Result<RecordsParse, Error> {
        let mut parsed_records: ArrayVec<Record, 16> = ArrayVec::new();
        let mut replay_updates: ArrayVec<Sequence, 16> = ArrayVec::new();
        let mut pending_replay: ArrayVec<(u16, ReplayWindow), 16> = ArrayVec::new();
        let mut pending_expected: ArrayVec<(u16, u64), 16> = ArrayVec::new();
        let mut deferred_tail = None;

        // Find record boundaries and copy each record ONCE from the packet
        while !packet.is_empty() {
            let Some(record_end) = record_end(packet)? else {
                break;
            };

            if packet.len() < record_end {
                return Err(Error::ParseIncomplete);
            }

            // This is the ONLY copy: packet -> record buffer
            let record_slice = &packet[..record_end];
            let tail = &packet[record_end..];
            match Record::parse(record_slice, decrypt, cs, &pending_expected) {
                Ok(parsed) => {
                    let mut should_break_after_replay_update = false;

                    if let Some(sequence) = parsed.replay_sequence {
                        if !pending_replay_check(&pending_replay, sequence) {
                            trace!("Discarding duplicate rec in same datagram");
                            packet = &packet[record_end..];
                            continue;
                        }
                    }

                    if let Some(record) = parsed.record {
                        let should_defer_tail = defer_after_key_update
                            && !tail.is_empty()
                            && record.contains_complete_key_update();

                        if parsed_records.try_push(record).is_err() {
                            return Err(Error::TooManyRecords);
                        }

                        should_break_after_replay_update = should_defer_tail;
                        if should_defer_tail {
                            validate_record_boundaries(tail, parsed_records.len())?;
                            let mut tail_buffer = Buf::new();
                            tail_buffer.extend_from_slice(tail);
                            deferred_tail = Some(tail_buffer);
                        }
                    } else if parsed.replay_sequence.is_none() {
                        trace!("Discarding replayed rec");
                    }

                    if let Some(sequence) = parsed.replay_sequence {
                        pending_replay_update(&mut pending_replay, sequence)?;
                        pending_expected_update(&mut pending_expected, sequence)?;
                        if replay_updates.try_push(sequence).is_err() {
                            return Err(Error::TooManyRecords);
                        }
                    }

                    if should_break_after_replay_update {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }

            packet = &packet[record_end..];
        }

        // Commit replay state only after the whole UDP datagram has parsed
        // successfully. A malformed trailing record must not consume
        // replay state for an earlier authenticated record in the same datagram.
        for sequence in replay_updates {
            decrypt.replay_update(sequence);
        }

        let mut records = ArrayVec::new();
        for record in parsed_records {
            if let Some(record) = decrypt.classify_record(record)? {
                records
                    .try_push(record)
                    .expect("filtered records cannot exceed parsed records");
            }
        }

        Ok(RecordsParse {
            records: Records { records },
            deferred_tail,
        })
    }
}

fn record_end(packet: &[u8]) -> Result<Option<usize>, Error> {
    if Dtls13Record::is_ciphertext_header(packet[0]) {
        // CID bit set means we can't determine record boundaries (unsupported).
        // Discard the rest of the datagram.
        if packet[0] & 0x10 != 0 {
            return Ok(None);
        }

        // Unified header: variable length
        if packet.len() < 2 {
            return Err(Error::ParseIncomplete);
        }

        let flags = packet[0];
        let s_flag = flags & 0b0000_1000 != 0;
        let l_flag = flags & 0b0000_0100 != 0;
        let seq_len = if s_flag { 2 } else { 1 };
        let len_len = if l_flag { 2 } else { 0 };
        let header_len = 1 + seq_len + len_len;

        if packet.len() < header_len {
            return Err(Error::ParseIncomplete);
        }

        if l_flag {
            let len_offset = 1 + seq_len;
            // unwrap: header_len check above ensures 2 bytes at len_offset.
            let length_bytes: [u8; 2] = packet[len_offset..len_offset + 2].try_into().unwrap();
            let length = u16::from_be_bytes(length_bytes) as usize;
            Ok(Some(header_len + length))
        } else {
            Ok(Some(packet.len()))
        }
    } else {
        if packet.len() < Dtls13Record::PLAINTEXT_HEADER_LEN {
            return Err(Error::ParseIncomplete);
        }

        // unwrap: PLAINTEXT_HEADER_LEN check above ensures 2 bytes at offset.
        let length_bytes: [u8; 2] = packet[Dtls13Record::PLAINTEXT_LENGTH_OFFSET]
            .try_into()
            .unwrap();
        let length = u16::from_be_bytes(length_bytes) as usize;
        Ok(Some(Dtls13Record::PLAINTEXT_HEADER_LEN + length))
    }
}

fn validate_record_boundaries(
    mut packet: &[u8],
    mut parsed_record_count: usize,
) -> Result<(), Error> {
    while !packet.is_empty() {
        let Some(end) = record_end(packet)? else {
            return Ok(());
        };

        if parsed_record_count >= 16 {
            return Err(Error::TooManyRecords);
        }
        parsed_record_count += 1;

        if packet.len() < end {
            return Err(Error::ParseIncomplete);
        }

        packet = &packet[end..];
    }

    Ok(())
}

fn pending_replay_check(pending_replay: &ArrayVec<(u16, ReplayWindow), 16>, seq: Sequence) -> bool {
    match pending_replay.iter().find(|(epoch, _)| *epoch == seq.epoch) {
        Some((_, window)) => window.check(seq.sequence_number),
        None => true,
    }
}

fn pending_replay_update(
    pending_replay: &mut ArrayVec<(u16, ReplayWindow), 16>,
    seq: Sequence,
) -> Result<(), Error> {
    if let Some((_, window)) = pending_replay
        .iter_mut()
        .find(|(epoch, _)| *epoch == seq.epoch)
    {
        window.update(seq.sequence_number);
        return Ok(());
    }

    let mut window = ReplayWindow::new();
    window.update(seq.sequence_number);
    pending_replay
        .try_push((seq.epoch, window))
        .map_err(|_| Error::TooManyRecords)
}

fn pending_expected_override(
    pending_expected: &ArrayVec<(u16, u64), 16>,
    epoch: u16,
) -> Option<u64> {
    pending_expected
        .iter()
        .find(|(candidate_epoch, _)| *candidate_epoch == epoch)
        .map(|(_, expected)| *expected)
}

fn pending_expected_update(
    pending_expected: &mut ArrayVec<(u16, u64), 16>,
    seq: Sequence,
) -> Result<(), Error> {
    let next = seq.sequence_number + 1;
    if let Some((_, expected)) = pending_expected
        .iter_mut()
        .find(|(epoch, _)| *epoch == seq.epoch)
    {
        if next > *expected {
            *expected = next;
        }
        return Ok(());
    }

    pending_expected
        .try_push((seq.epoch, next))
        .map_err(|_| Error::TooManyRecords)
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

struct RecordParse {
    record: Option<Record>,
    replay_sequence: Option<Sequence>,
}

impl Record {
    /// The first parse pass only parses the record header which is unencrypted.
    /// Copies record data from UDP packet ONCE into a pooled buffer.
    fn parse(
        record_slice: &[u8],
        decrypt: &mut dyn RecordHandler,
        cs: Option<Dtls13CipherSuite>,
        pending_expected: &ArrayVec<(u16, u64), 16>,
    ) -> Result<RecordParse, Error> {
        // ONLY COPY: UDP packet slice -> pooled buffer
        let mut buffer = Buf::new();
        buffer.extend_from_slice(record_slice);

        let is_ciphertext = Dtls13Record::is_ciphertext_header(buffer[0]);

        // Decrypt record number in-place before parsing (RFC 9147 Section 4.2.3)
        if is_ciphertext && decrypt.is_peer_encryption_enabled() {
            let flags = buffer[0];
            let s_flag = flags & 0b0000_1000 != 0;
            let l_flag = flags & 0b0000_0100 != 0;
            let seq_len: usize = if s_flag { 2 } else { 1 };
            let len_len: usize = if l_flag { 2 } else { 0 };
            let header_len = 1 + seq_len + len_len;

            if buffer.len() >= header_len + 16 {
                // unwrap: bounds checked above
                let ciphertext_sample: [u8; 16] =
                    buffer[header_len..header_len + 16].try_into().unwrap();

                // Resolve epoch from 2-bit field (doesn't depend on seq bytes)
                let epoch_bits = flags & 0x03;
                let full_epoch = decrypt.resolve_epoch(epoch_bits);

                // Decrypt sequence bytes in place
                decrypt.decrypt_sequence_number(
                    full_epoch,
                    &mut buffer[1..1 + seq_len],
                    &ciphertext_sample,
                );
            }
        }

        let parsed = match ParsedRecord::parse(&buffer, cs) {
            Ok(p) => p,
            Err(e) => {
                trace!("Discarding record: parse failed: {}", e);
                return Ok(RecordParse {
                    record: None,
                    replay_sequence: None,
                });
            }
        };
        let parsed = Box::new(parsed);
        let record = Record { buffer, parsed };

        // Plaintext records (epoch 0) are not encrypted
        if !is_ciphertext || !decrypt.is_peer_encryption_enabled() {
            return Ok(RecordParse {
                record: Some(record),
                replay_sequence: None,
            });
        }

        // Resolve the full epoch from the 2-bit value in the unified header
        let epoch_bits = record.record().sequence.epoch as u8;
        let full_epoch = decrypt.resolve_epoch(epoch_bits);

        // Resolve the full sequence number from the (now decrypted) partial value
        let seq_bits = record.record().sequence.sequence_number;
        let s_flag = record_slice[0] & 0b0000_1000 != 0;
        let full_seq = decrypt.resolve_sequence(
            full_epoch,
            seq_bits,
            s_flag,
            pending_expected_override(pending_expected, full_epoch),
        );

        let full_sequence = Sequence {
            epoch: full_epoch,
            sequence_number: full_seq,
        };

        // Anti-replay check (read-only, does not update window)
        if !decrypt.replay_check(full_sequence) {
            return Ok(RecordParse {
                record: None,
                replay_sequence: None,
            });
        }

        // Save the raw header bytes for AAD before mutating the buffer.
        // Max unified header without CID: flags(1) + seq(2) + length(2) = 5 bytes.
        let header_end = record.record().fragment_range.start;

        // Reject protected records whose encrypted fragment is shorter than
        // the per-suite minimum — they cannot hold a valid ciphertext + tag,
        // so decryption would necessarily fail. Catching it here keeps the
        // cipher impls' bounds-checking from being the only line of defence.
        if record.buffer.len() - header_end < decrypt.min_protected_fragment_len() {
            return Ok(RecordParse {
                record: None,
                replay_sequence: None,
            });
        }
        let mut header_buf = [0u8; 5];
        header_buf[..header_end].copy_from_slice(&record.buffer[..header_end]);

        // Extract the buffer for decryption
        let mut buffer = record.buffer;

        // The encrypted part starts right after the unified header.
        let ciphertext = &mut buffer[header_end..];

        let new_len = {
            let mut buffer = TmpBuf::new(ciphertext);

            // This decrypts in place.
            // RFC 9147 §4.5.2: failed-to-decrypt ciphertext records MUST be silently discarded.
            match decrypt.decrypt_record(&header_buf[..header_end], full_sequence, &mut buffer) {
                Ok(()) => {}
                Err(e) => {
                    trace!("Discarding ciphertext record: decryption failed: {}", e);
                    return Ok(RecordParse {
                        record: None,
                        replay_sequence: None,
                    });
                }
            }

            buffer.len()
        };

        // Recover inner content type from DTLSInnerPlaintext
        let decrypted = &buffer[header_end..header_end + new_len];
        let (inner_content_type, content_len) = match recover_inner_content_type(decrypted) {
            Ok(v) => v,
            Err(e) => {
                trace!("Discarding record: invalid inner content type: {}", e);
                return Ok(RecordParse {
                    record: None,
                    replay_sequence: Some(full_sequence),
                });
            }
        };

        let parsed = ParsedRecord::parse_decrypted(
            Dtls13Record {
                content_type: inner_content_type,
                sequence: full_sequence,
                length: content_len as u16,
                fragment_range: header_end..(header_end + content_len),
            },
            &buffer,
            cs,
        );
        let parsed = Box::new(parsed);

        Ok(RecordParse {
            record: Some(Record { buffer, parsed }),
            replay_sequence: Some(full_sequence),
        })
    }

    pub fn record(&self) -> &Dtls13Record {
        &self.parsed.record
    }

    pub fn handshakes(&self) -> &[Handshake] {
        &self.parsed.handshakes
    }

    pub fn first_handshake(&self) -> Option<&Handshake> {
        self.parsed.handshakes.first()
    }

    fn contains_complete_key_update(&self) -> bool {
        self.record().content_type == ContentType::Handshake
            && self.handshakes().iter().any(|handshake| {
                handshake.header.msg_type == MessageType::KeyUpdate
                    && handshake.header.fragment_offset == 0
                    && handshake.header.fragment_length == handshake.header.length
            })
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
    record: Dtls13Record,
    handshakes: ArrayVec<Handshake, 8>,
    handled: AtomicBool,
}

impl ParsedRecord {
    pub fn parse(
        input: &[u8],
        cipher_suite: Option<Dtls13CipherSuite>,
    ) -> Result<ParsedRecord, Error> {
        let (_, record) = Dtls13Record::parse(input, 0)?;

        let handshakes = if record.content_type == ContentType::Handshake {
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

    /// Build a ParsedRecord from an already-constructed record (after decryption).
    pub fn parse_decrypted(
        record: Dtls13Record,
        input: &[u8],
        cipher_suite: Option<Dtls13CipherSuite>,
    ) -> ParsedRecord {
        let handshakes = if record.content_type == ContentType::Handshake {
            let fragment_offset = record.fragment_range.start;
            parse_handshakes(record.fragment(input), fragment_offset, cipher_suite)
        } else {
            ArrayVec::new()
        };

        ParsedRecord {
            record,
            handshakes,
            handled: AtomicBool::new(false),
        }
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
    fn resolve_epoch(&self, epoch_bits: u8) -> u16;
    fn resolve_sequence(
        &self,
        epoch: u16,
        seq_bits: u64,
        s_flag: bool,
        expected_override: Option<u64>,
    ) -> u64;
    fn replay_check(&self, seq: Sequence) -> bool;
    fn replay_update(&mut self, seq: Sequence);

    /// Minimum length of a protected record's encrypted fragment for the
    /// negotiated suite (tag length in DTLS 1.3). Used to reject records that
    /// cannot possibly contain a valid ciphertext + tag.
    fn min_protected_fragment_len(&self) -> usize;

    fn decrypt_record(
        &mut self,
        header: &[u8],
        seq: Sequence,
        ciphertext: &mut TmpBuf,
    ) -> Result<(), Error>;

    /// Decrypt the sequence number bytes in a unified header (RFC 9147 Section 4.2.3).
    ///
    /// `epoch` is the resolved full epoch, `seq_bytes` are the encrypted sequence
    /// bytes from the header (1 or 2 bytes), and `ciphertext_sample` is the first
    /// 16 bytes of the ciphertext following the header.
    ///
    /// Returns the decrypted sequence bytes in-place.
    fn decrypt_sequence_number(
        &self,
        epoch: u16,
        seq_bytes: &mut [u8],
        ciphertext_sample: &[u8; 16],
    );
}

fn parse_handshakes(
    mut input: &[u8],
    mut base_offset: usize,
    cipher_suite: Option<Dtls13CipherSuite>,
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

/// Recover the inner content type from a decrypted DTLSInnerPlaintext.
///
/// The format is: `content || ContentType || zeros*`
/// Scan backward past zero padding to find the content type byte.
fn recover_inner_content_type(decrypted: &[u8]) -> Result<(ContentType, usize), Error> {
    let mut i = decrypted.len();
    // Skip zero padding
    while i > 0 && decrypted[i - 1] == 0 {
        i -= 1;
    }
    if i == 0 {
        return Err(Error::ParseError(nom::error::ErrorKind::Fail));
    }
    // The byte before padding is the content type
    i -= 1;
    let content_type = ContentType::from_u8(decrypted[i]);
    // Content length is everything before the content type byte
    Ok((content_type, i))
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
  the buffer, mutate it (in-place decrypt), and only then construct a fresh Record
  from the fully transformed bytes. If a panic occurs mid-transformation, the new
  Record is not built and the previously-built Record is dropped; no consumer can
  observe a half-transformed record across an unwind boundary.

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
        dropped_acks: usize,
    }

    impl RecordHandler for TestHandler {
        fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
            self.classify_calls += 1;
            if record.record().content_type == ContentType::Ack {
                self.dropped_acks += 1;
                return Ok(None);
            }
            Ok(Some(record))
        }

        fn is_peer_encryption_enabled(&self) -> bool {
            false
        }

        fn resolve_epoch(&self, _epoch_bits: u8) -> u16 {
            panic!("resolve_epoch should not be called when peer encryption is disabled");
        }

        fn resolve_sequence(
            &self,
            _epoch: u16,
            _seq_bits: u64,
            _s_flag: bool,
            _expected_override: Option<u64>,
        ) -> u64 {
            panic!("resolve_sequence should not be called when peer encryption is disabled");
        }

        fn replay_check(&self, _seq: Sequence) -> bool {
            panic!("replay_check should not be called when peer encryption is disabled");
        }

        fn replay_update(&mut self, _seq: Sequence) {
            panic!("replay_update should not be called when peer encryption is disabled");
        }

        fn min_protected_fragment_len(&self) -> usize {
            panic!(
                "min_protected_fragment_len should not be called when peer encryption is disabled"
            );
        }

        fn decrypt_record(
            &mut self,
            _header: &[u8],
            _seq: Sequence,
            _ciphertext: &mut TmpBuf,
        ) -> Result<(), Error> {
            panic!("decrypt_record should not be called when peer encryption is disabled");
        }

        fn decrypt_sequence_number(
            &self,
            _epoch: u16,
            _seq_bytes: &mut [u8],
            _ciphertext_sample: &[u8; 16],
        ) {
            panic!("decrypt_sequence_number should not be called when peer encryption is disabled");
        }
    }

    fn build_plaintext_record(content_type: ContentType, seq: u64, fragment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(content_type.as_u8());
        out.extend_from_slice(&[0xFE, 0xFD]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..]);
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    fn build_ciphertext_record(epoch: u16, seq: u16, fragment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let flags = 0b0010_0000 | 0b0000_1000 | 0b0000_0100 | (epoch as u8 & 0x03);
        out.push(flags);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    #[test]
    fn parse_packet_filters_control_records_after_packet_validation() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&build_plaintext_record(ContentType::Ack, 1, &[0xAA, 0xBB]));
        packet.extend_from_slice(&build_ciphertext_record(2, 2, &[0x11, 0x22, 0x33]));

        let mut handler = TestHandler::default();
        let incoming = Incoming::parse_packet_defer_after_key_update(&packet, &mut handler, None)
            .unwrap()
            .incoming
            .expect("ciphertext application data record should remain");

        assert_eq!(handler.classify_calls, 2);
        assert_eq!(handler.dropped_acks, 1);
        assert_eq!(incoming.records().len(), 1);
        assert_eq!(
            incoming.first().record().content_type,
            ContentType::ApplicationData
        );
        assert_eq!(incoming.first().record().sequence.epoch, 2);
    }
}
