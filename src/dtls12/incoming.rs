use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use std::fmt;

use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce};
use crate::dtls12::message::{ContentType, DTLSRecord, Dtls12CipherSuite, Handshake, Sequence};
use crate::{Error, InternalError};

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
    ) -> Result<Option<Self>, InternalError> {
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
    ) -> Result<Records, InternalError> {
        let mut parsed_records: ArrayVec<Record, 8> = ArrayVec::new();

        // Find record boundaries and copy each record ONCE from the packet
        while !packet.is_empty() {
            if packet.len() < DTLSRecord::HEADER_LEN {
                return Err(InternalError::parse_incomplete());
            }

            let length_bytes: [u8; 2] = packet[DTLSRecord::LENGTH_OFFSET].try_into().unwrap();
            let length = u16::from_be_bytes(length_bytes) as usize;
            let record_end = DTLSRecord::HEADER_LEN + length;

            if packet.len() < record_end {
                return Err(InternalError::parse_incomplete());
            }

            // This is the ONLY copy: packet -> record buffer
            let record_slice = &packet[..record_end];
            match Record::parse(record_slice, decrypt, cs) {
                Ok(record) => {
                    if let Some(record) = record {
                        if parsed_records.try_push(record).is_err() {
                            return Err(InternalError::too_many_records());
                        }
                    } else {
                        trace!("Discarding replayed rec");
                    }
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
    ) -> Result<Option<Record>, InternalError> {
        // ONLY COPY: UDP packet slice -> pooled buffer
        let mut buffer = Buf::new();
        buffer.extend_from_slice(record_slice);
        let parsed = match ParsedRecord::parse(&buffer, cs, 0) {
            Ok(p) => p,
            Err(e) => {
                // RFC 6347 §4.1.2.7: Invalid records SHOULD be silently discarded.
                // This includes epoch 0 records with invalid ContentType.
                trace!("Discarding record: parse failed: {}", e);
                return Ok(None);
            }
        };
        let parsed = Box::new(parsed);
        let record = Record { buffer, parsed };

        // It is not enough to only look at the epoch, since to be able to decrypt the entire
        // preceeding set of flights sets up the cryptographic context. In a situation with
        // packet loss, we can end up seeing epoch 1 records before we can decrypt them.
        let is_epoch_0 = record.record().sequence.epoch == 0;
        if is_epoch_0 || !decrypt.is_peer_encryption_enabled() {
            return Ok(Some(record));
        }

        // We need to decrypt the record and redo the parsing.
        let dtls = record.record();
        let sequence = dtls.sequence;
        let content_type = dtls.content_type;

        // Anti-replay check (read-only, does not update window)
        if !decrypt.replay_check(sequence) {
            return Ok(None);
        }

        let explicit_nonce_len = decrypt.explicit_nonce_len();
        if (dtls.length as usize) < decrypt.min_protected_fragment_len() {
            return Ok(None);
        }

        // Get a reference to the buffer
        let (aad, nonce) = decrypt.decryption_aad_and_nonce(dtls, &record.buffer);

        // Extract the buffer for decryption
        let mut buffer = record.buffer;

        // Local shorthand for where the encrypted ciphertext starts
        let ciph = DTLSRecord::HEADER_LEN + explicit_nonce_len;

        // The encrypted part is after the DTLS header and optional explicit nonce.
        // The entire buffer is only the single record, since we chunk
        // records up in Records::parse()
        let ciphertext = &mut buffer[ciph..];

        let new_len = {
            let mut buffer = TmpBuf::new(ciphertext);

            // This decrypts in place.
            if let Err(e) = decrypt.decrypt_data(&mut buffer, aad, nonce) {
                if !decrypt.can_discard_bad_protected_record() {
                    return Err(e.into());
                }

                trace!("Discarding record: decrypt failed: {}", e);
                return Ok(None);
            }

            buffer.len()
        };

        // Decryption succeeded — now commit the replay window update.
        // RFC 6347 §4.1.2.6: "The receive window is updated only if the
        // MAC verification succeeds."
        decrypt.replay_update(sequence);

        // The record is now authenticated. Tell the handler so it can act on a
        // confirmed-genuine record (e.g. mark the peer past its handshake).
        decrypt.note_decrypted_record(content_type);

        // Update the length of the record.
        buffer[11] = (new_len >> 8) as u8;
        buffer[12] = new_len as u8;

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
    ) -> Result<ParsedRecord, InternalError> {
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
    fn explicit_nonce_len(&self) -> usize;
    fn min_protected_fragment_len(&self) -> usize;
    fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error>;

    fn can_discard_bad_protected_record(&self) -> bool {
        false
    }

    /// Called once a record has been successfully decrypted, i.e. authenticated.
    /// Lets the handler react to a confirmed-genuine record (e.g. note that the
    /// peer is past its handshake). The default does nothing.
    fn note_decrypted_record(&mut self, _content_type: ContentType) {}
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

        fn explicit_nonce_len(&self) -> usize {
            panic!("explicit_nonce_len should not be called for plaintext tests");
        }

        fn min_protected_fragment_len(&self) -> usize {
            panic!("min_protected_fragment_len should not be called for plaintext tests");
        }

        fn decrypt_data(
            &mut self,
            _ciphertext: &mut TmpBuf,
            _aad: Aad,
            _nonce: Nonce,
        ) -> Result<(), Error> {
            panic!("decrypt_data should not be called for plaintext tests");
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
}
