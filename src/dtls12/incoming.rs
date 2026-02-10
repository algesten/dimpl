use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use std::fmt;

use crate::buffer::{Buf, TmpBuf};
use crate::crypto::{Aad, Nonce, DTLS_EXPLICIT_NONCE_LEN};
use crate::dtls12::message::{ContentType, DTLSRecord, Dtls12CipherSuite, Handshake, Sequence};
use crate::Error;

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
        decrypt: &mut dyn RecordDecrypt,
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
        decrypt: &mut dyn RecordDecrypt,
        cs: Option<Dtls12CipherSuite>,
    ) -> Result<Records, Error> {
        let mut records = ArrayVec::new();

        // Find record boundaries and copy each record ONCE from the packet
        while !packet.is_empty() {
            if packet.len() < DTLSRecord::HEADER_LEN {
                return Err(Error::ParseIncomplete);
            }

            let length_bytes: [u8; 2] = packet[DTLSRecord::LENGTH_OFFSET].try_into().unwrap();
            let length = u16::from_be_bytes(length_bytes) as usize;
            let record_end = DTLSRecord::HEADER_LEN + length;

            if packet.len() < record_end {
                return Err(Error::ParseIncomplete);
            }

            // This is the ONLY copy: packet -> record buffer
            let record_slice = &packet[..record_end];
            match Record::parse(record_slice, decrypt, cs) {
                Ok(record) => {
                    if let Some(record) = record {
                        if records.try_push(record).is_err() {
                            return Err(Error::TooManyRecords);
                        }
                    } else {
                        trace!("Discarding replayed rec");
                    }
                }
                Err(e) => return Err(e),
            }

            packet = &packet[record_end..];
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
        decrypt: &mut dyn RecordDecrypt,
        cs: Option<Dtls12CipherSuite>,
    ) -> Result<Option<Record>, Error> {
        // ONLY COPY: UDP packet slice -> pooled buffer
        let mut buffer = Buf::new();
        buffer.extend_from_slice(record_slice);
        let parsed = ParsedRecord::parse(&buffer, cs, 0)?;
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

        // Anti-replay check
        if !decrypt.replay_check_and_update(dtls.sequence) {
            return Ok(None);
        }

        // Get a reference to the buffer
        let (aad, nonce) = decrypt.decryption_aad_and_nonce(dtls, &record.buffer);

        // Extract the buffer for decryption
        let mut buffer = record.buffer;

        // Local shorthand for where the encrypted ciphertext starts
        const CIPH: usize = DTLSRecord::HEADER_LEN + DTLS_EXPLICIT_NONCE_LEN;

        // The encrypted part is after the DTLS header and explicit nonce.
        // The entire buffer is only the single record, since we chunk
        // records up in Records::parse()
        let ciphertext = &mut buffer[CIPH..];

        let new_len = {
            let mut buffer = TmpBuf::new(ciphertext);

            // This decrypts in place.
            decrypt.decrypt_data(&mut buffer, aad, nonce)?;

            buffer.len()
        };

        // Update the length of the record.
        buffer[11] = (new_len >> 8) as u8;
        buffer[12] = new_len as u8;

        let parsed = ParsedRecord::parse(&buffer, cs, DTLS_EXPLICIT_NONCE_LEN)?;
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

/// Trait abstracting the decryption operations needed for parsing incoming records.
///
/// This decouples the record parser from the full `Engine`, allowing incoming record
/// parsing to depend only on the cryptographic operations it actually uses.
pub trait RecordDecrypt {
    fn is_peer_encryption_enabled(&self) -> bool;
    fn replay_check_and_update(&mut self, seq: Sequence) -> bool;
    fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord, buf: &[u8]) -> (Aad, Nonce);
    fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error>;
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
