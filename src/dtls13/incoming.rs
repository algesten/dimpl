use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use std::fmt;

use crate::buffer::{Buf, TmpBuf};
use crate::dtls13::message::{ContentType, Dtls13CipherSuite, Dtls13Record, Handshake, Sequence};
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
        cs: Option<Dtls13CipherSuite>,
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
        cs: Option<Dtls13CipherSuite>,
    ) -> Result<Records, Error> {
        let mut records = ArrayVec::new();

        // Find record boundaries and copy each record ONCE from the packet
        while !packet.is_empty() {
            let record_end = if Dtls13Record::is_ciphertext_header(packet[0]) {
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
                    // unwrap: header_len check above ensures 2 bytes at len_offset
                    let length_bytes: [u8; 2] =
                        packet[len_offset..len_offset + 2].try_into().unwrap();
                    let length = u16::from_be_bytes(length_bytes) as usize;
                    header_len + length
                } else {
                    // No length field: record consumes the rest of the datagram
                    packet.len()
                }
            } else {
                // Plaintext: fixed 13-byte header
                if packet.len() < Dtls13Record::PLAINTEXT_HEADER_LEN {
                    return Err(Error::ParseIncomplete);
                }

                // unwrap: PLAINTEXT_HEADER_LEN check above ensures 2 bytes at offset
                let length_bytes: [u8; 2] = packet[Dtls13Record::PLAINTEXT_LENGTH_OFFSET]
                    .try_into()
                    .unwrap();
                let length = u16::from_be_bytes(length_bytes) as usize;
                Dtls13Record::PLAINTEXT_HEADER_LEN + length
            };

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
    /// The first parse pass only parses the record header which is unencrypted.
    /// Copies record data from UDP packet ONCE into a pooled buffer.
    pub fn parse(
        record_slice: &[u8],
        decrypt: &mut dyn RecordDecrypt,
        cs: Option<Dtls13CipherSuite>,
    ) -> Result<Option<Record>, Error> {
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

        let parsed = ParsedRecord::parse(&buffer, cs)?;
        let parsed = Box::new(parsed);
        let record = Record { buffer, parsed };

        // Plaintext records (epoch 0) are not encrypted
        if !is_ciphertext || !decrypt.is_peer_encryption_enabled() {
            return Ok(Some(record));
        }

        // Resolve the full epoch from the 2-bit value in the unified header
        let epoch_bits = record.record().sequence.epoch as u8;
        let full_epoch = decrypt.resolve_epoch(epoch_bits);

        // Resolve the full sequence number from the (now decrypted) partial value
        let seq_bits = record.record().sequence.sequence_number;
        let s_flag = record_slice[0] & 0b0000_1000 != 0;
        let full_seq = decrypt.resolve_sequence(full_epoch, seq_bits, s_flag);

        let full_sequence = Sequence {
            epoch: full_epoch,
            sequence_number: full_seq,
        };

        // Anti-replay check
        if !decrypt.replay_check_and_update(full_sequence) {
            return Ok(None);
        }

        // Save the raw header bytes for AAD before mutating the buffer.
        // Max unified header without CID: flags(1) + seq(2) + length(2) = 5 bytes.
        let header_end = record.record().fragment_range.start;
        let mut header_buf = [0u8; 5];
        header_buf[..header_end].copy_from_slice(&record.buffer[..header_end]);

        // Extract the buffer for decryption
        let mut buffer = record.buffer;

        // The encrypted part starts right after the unified header.
        let ciphertext = &mut buffer[header_end..];

        let new_len = {
            let mut buffer = TmpBuf::new(ciphertext);

            // This decrypts in place.
            decrypt.decrypt_record(&header_buf[..header_end], full_sequence, &mut buffer)?;

            buffer.len()
        };

        // Recover inner content type from DTLSInnerPlaintext
        let decrypted = &buffer[header_end..header_end + new_len];
        let (inner_content_type, content_len) = recover_inner_content_type(decrypted)?;

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

        Ok(Some(Record { buffer, parsed }))
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

/// Trait abstracting the decryption operations needed for parsing incoming records.
///
/// This decouples the record parser from the full `Engine`, allowing incoming record
/// parsing to depend only on the cryptographic operations it actually uses.
pub trait RecordDecrypt {
    fn is_peer_encryption_enabled(&self) -> bool;
    fn resolve_epoch(&self, epoch_bits: u8) -> u16;
    fn resolve_sequence(&self, epoch: u16, seq_bits: u64, s_flag: bool) -> u64;
    fn replay_check_and_update(&mut self, seq: Sequence) -> bool;
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
