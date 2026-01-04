use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use arrayvec::ArrayVec;
use std::fmt;

use super::engine::Engine;
use crate::buffer::Buf;
use crate::message::record13::{flags, CiphertextRecord};
use crate::message::{ContentType, DTLSRecord, Handshake, Sequence};
use crate::Error;

/// Maximum unified header length: 1 (header byte) + 2 (16-bit seq) + 2 (length) = 5
const MAX_UNIFIED_HEADER_LEN: usize = 5;

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
    /// * `engine` is a reference to the Engine for crypto context.
    /// * `into` the buffer to return to pool (not used for storage).
    ///
    /// Will surface parser errors.
    pub fn parse_packet(packet: &[u8], engine: &mut Engine) -> Result<Option<Self>, Error> {
        // Parse records directly from packet, copying each record ONCE into its own buffer
        let records = Records::parse(packet, engine)?;

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
    pub fn parse(mut packet: &[u8], engine: &mut Engine) -> Result<Records, Error> {
        let mut records = ArrayVec::new();

        // Find record boundaries and copy each record ONCE from the packet
        while !packet.is_empty() {
            // Check if this is a DTLS 1.3 unified header (ciphertext record)
            // Unified header starts with 0b001xxxxx (fixed bits pattern)
            let first_byte = packet[0];
            let is_dtls13_ciphertext = (first_byte & flags::FIXED_MASK) == flags::FIXED_BITS;

            let record_end = if is_dtls13_ciphertext {
                // DTLS 1.3 unified header format
                // If the CID bit is set but we don't support CID, silently discard the rest
                // of the UDP packet rather than surfacing a hard error.
                if (packet[0] & flags::CID_BIT) != 0 {
                    trace!("Discarding DTLS 1.3 record with CID bit set (CID not supported)");
                    return Ok(Records { records });
                }

                Self::compute_dtls13_record_end(packet)?
            } else {
                // DTLS 1.2 record format
                if packet.len() < DTLSRecord::HEADER_LEN {
                    return Err(Error::ParseIncomplete);
                }

                let length_bytes: [u8; 2] = packet[DTLSRecord::LENGTH_OFFSET].try_into().unwrap();
                let length = u16::from_be_bytes(length_bytes) as usize;
                let end = DTLSRecord::HEADER_LEN + length;

                if packet.len() < end {
                    return Err(Error::ParseIncomplete);
                }
                end
            };

            // This is the ONLY copy: packet -> record buffer
            let record_slice = &packet[..record_end];
            // For DTLS 1.3 ciphertext, check if keys are available before parsing
            // If keys aren't ready, defer the packet for later
            if is_dtls13_ciphertext {
                let epoch = Self::extract_dtls13_epoch(record_slice);
                let has_keys = match epoch {
                    2 => engine.has_dtls13_hs_recv_keys(),
                    3 => engine.has_dtls13_recv_keys(),
                    _ => true, // Let parse_dtls13 handle invalid epochs
                };
                if !has_keys {
                    trace!(
                        "Deferring {} bytes of packet data (keys not ready for epoch {})",
                        packet.len(),
                        epoch
                    );
                    engine.set_deferred_packet(packet);
                    break;
                }
            }

            let parse_result = if is_dtls13_ciphertext {
                Record::parse_dtls13(record_slice, engine)
            } else {
                Record::parse(record_slice, engine)
            };

            match parse_result {
                Ok(record) => {
                    if let Some(record) = record {
                        if records.try_push(record).is_err() {
                            return Err(Error::TooManyRecords);
                        }
                    }
                    // If None, it was a replay - just ignore and continue
                }
                Err(e) => return Err(e),
            }

            packet = &packet[record_end..];
        }

        Ok(Records { records })
    }

    /// Compute the end offset for a DTLS 1.3 ciphertext record (unified header).
    fn compute_dtls13_record_end(packet: &[u8]) -> Result<usize, Error> {
        if packet.is_empty() {
            return Err(Error::ParseIncomplete);
        }

        let header_byte = packet[0];

        // We don't support Connection IDs
        if (header_byte & flags::CID_BIT) != 0 {
            return Err(Error::CryptoError("DTLS 1.3 CID not supported".to_string()));
        }

        let seq_16bit = (header_byte & flags::SEQ_16BIT) != 0;
        let has_length = (header_byte & flags::LENGTH_BIT) != 0;

        // Compute header length
        let mut header_len = 1; // header byte
        header_len += if seq_16bit { 2 } else { 1 }; // sequence number
        if has_length {
            header_len += 2; // length field
        }

        if packet.len() < header_len {
            return Err(Error::ParseIncomplete);
        }

        let content_len = if has_length {
            // Length is last 2 bytes of header
            let len_offset = header_len - 2;
            let len_bytes: [u8; 2] = packet[len_offset..len_offset + 2].try_into().unwrap();
            u16::from_be_bytes(len_bytes) as usize
        } else {
            // No length field: rest of packet is this record
            packet.len() - header_len
        };

        let record_end = header_len + content_len;
        if packet.len() < record_end {
            return Err(Error::ParseIncomplete);
        }

        Ok(record_end)
    }

    /// Extract the epoch from a DTLS 1.3 ciphertext record header.
    fn extract_dtls13_epoch(packet: &[u8]) -> u8 {
        if packet.is_empty() {
            return 0;
        }
        // The epoch is encoded in the low 2 bits of the first byte
        packet[0] & flags::EPOCH_MASK
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
    /// Parse a DTLS record in DTLS 1.2 format (used for epoch 0 plaintext records in DTLS 1.3).
    /// In DTLS 1.3, only epoch 0 records use this format - they are always unencrypted.
    /// Encrypted records in DTLS 1.3 use the unified header format (parse_dtls13).
    pub fn parse(record_slice: &[u8], engine: &mut Engine) -> Result<Option<Record>, Error> {
        // ONLY COPY: UDP packet slice -> pooled buffer
        let mut buffer = engine.pop_buffer();
        buffer.extend_from_slice(record_slice);
        let parsed = ParsedRecord::parse(&buffer, engine, 0)?;
        let parsed = Box::new(parsed);
        let record = Record { buffer, parsed };

        // In DTLS 1.3, epoch 0 records are always plaintext (ClientHello, ServerHello, HRR)
        // Encrypted records use the unified header format and are parsed by parse_dtls13
        Ok(Some(record))
    }

    /// Parse a DTLS 1.3 ciphertext record (unified header format).
    /// This handles encrypted records in epoch > 0.
    pub fn parse_dtls13(record_slice: &[u8], engine: &mut Engine) -> Result<Option<Record>, Error> {
        // ONLY COPY: UDP packet slice -> pooled buffer
        let mut buffer = engine.pop_buffer();
        buffer.extend_from_slice(record_slice);
        let buffer_len = buffer.len();

        // Compute the remaining encrypted length if the unified header omits the length field.
        // We need this because CiphertextRecord::parse requires the ciphertext length when L=0.
        if buffer_len == 0 {
            engine.push_buffer(buffer);
            return Err(Error::ParseIncomplete);
        }
        let header_byte = buffer[0];
        let seq_16bit = (header_byte & flags::SEQ_16BIT) != 0;
        let has_length = (header_byte & flags::LENGTH_BIT) != 0;
        let header_len = 1 + if seq_16bit { 2 } else { 1 } + if has_length { 2 } else { 0 };
        if buffer_len < header_len {
            engine.push_buffer(buffer);
            return Err(Error::ParseIncomplete);
        }
        let remaining_encrypted_len = buffer_len - header_len;

        // Parse the ciphertext header - handle error without closure to avoid move issues
        let ciphertext_record =
            match CiphertextRecord::parse(&buffer, 0, Some(remaining_encrypted_len)) {
                Ok((_, record)) => record,
                Err(e) => {
                    let err = Error::from(e);
                    engine.push_buffer(buffer);
                    return Err(err);
                }
            };

        let epoch = (ciphertext_record.epoch_bits & flags::EPOCH_MASK) as u16;

        // Check if we have receive keys installed for the appropriate epoch
        let has_keys = match epoch {
            2 => engine.has_dtls13_hs_recv_keys(), // Handshake keys
            3 => engine.has_dtls13_recv_keys(),    // Application keys
            _ => {
                trace!("Received DTLS 1.3 record with unexpected epoch {}", epoch);
                engine.push_buffer(buffer);
                return Err(Error::CryptoError(format!(
                    "DTLS 1.3 record with unsupported epoch {}",
                    epoch
                )));
            }
        };

        if !has_keys {
            // Keys not installed yet - this can happen when ServerHello is followed
            // by encrypted records in the same packet. We'll process these records
            // after the state machine installs keys.
            trace!(
                "Received DTLS 1.3 record for epoch {} but no recv keys installed (will retry)",
                epoch
            );
            engine.push_buffer(buffer);
            return Ok(None);
        }

        // The header bytes for AAD is everything before the encrypted content
        let header_len = ciphertext_record.header_len();

        // Decrypt sequence number using sn_key (RFC 9147 Section 4.2.3)
        // The mask is computed from the first 16 bytes of ciphertext.
        // RFC 9147 requires a minimum ciphertext length of 16 bytes.
        let ciphertext = &buffer[header_len..];
        if ciphertext.len() < 16 {
            trace!(
                "Discarding DTLS 1.3 record with too-short ciphertext ({} bytes)",
                ciphertext.len()
            );
            engine.push_buffer(buffer);
            return Ok(None);
        }
        let encrypted_seq = ciphertext_record.sequence_bits;
        let sequence_number = engine.decrypt_dtls13_sequence(encrypted_seq, epoch, ciphertext);

        trace!(
            "DTLS 1.3 sequence number: encrypted=0x{:04x}, decrypted={}",
            encrypted_seq,
            sequence_number
        );

        // Anti-replay check for DTLS 1.3
        let sequence = Sequence {
            epoch,
            sequence_number,
        };
        if !engine.replay_check_and_update(sequence) {
            engine.push_buffer(buffer);
            return Ok(None);
        }

        // Use stack-allocated array for header bytes (max 5 bytes for unified header)
        // RFC 9147 Section 4.2.3: "The header (with the decrypted sequence number bytes)
        // is used as the additional data for the AEAD function."
        let mut header_bytes: [u8; MAX_UNIFIED_HEADER_LEN] = [0; MAX_UNIFIED_HEADER_LEN];
        header_bytes[..header_len].copy_from_slice(&buffer[..header_len]);

        // Update header with decrypted sequence number for AAD
        // The sequence number bits follow the header byte at position 1
        let decrypted_seq_bits = (sequence_number & 0xFFFF) as u16;
        if ciphertext_record.seq_16bit {
            header_bytes[1] = (decrypted_seq_bits >> 8) as u8;
            header_bytes[2] = (decrypted_seq_bits & 0xFF) as u8;
        } else {
            header_bytes[1] = (decrypted_seq_bits & 0xFF) as u8;
        }

        // Decrypt in place - returns (content_type, plaintext_len)
        let decrypt_result = engine.decrypt_data_dtls13(
            &mut buffer[header_len..],
            &header_bytes[..header_len],
            sequence_number,
            epoch,
        );

        let (inner_content_type, plaintext_len) = match decrypt_result {
            Ok(result) => result,
            Err(Error::SecurityError(msg)) => {
                engine.push_buffer(buffer);
                return Err(Error::SecurityError(msg));
            }
            Err(e) => {
                // Per RFC behavior, unauthenticated records are commonly silently discarded.
                // The failure counter/limit is handled inside decrypt_data_dtls13.
                trace!("Discarding DTLS 1.3 record due to decryption failure: {e}");
                engine.push_buffer(buffer);
                return Ok(None);
            }
        };

        // Build DTLS 1.2-style header in-place at the start of buffer.
        // The decrypted plaintext is at buffer[header_len..header_len+plaintext_len].
        // We need to shift it to make room for the 13-byte DTLS 1.2 header.
        //
        // DTLS 1.2 header format (13 bytes):
        //   content_type (1) + version (2) + epoch (2) + seq_num (6) + length (2)
        const DTLS12_HEADER_LEN: usize = 13;

        // Calculate how much we need to shift the plaintext
        let plaintext_start = header_len;
        let new_plaintext_start = DTLS12_HEADER_LEN;

        if new_plaintext_start > plaintext_start {
            // Need to shift plaintext forward - ensure buffer has capacity
            let shift = new_plaintext_start - plaintext_start;
            let old_len = buffer.len();
            buffer.resize(old_len + shift, 0);
            // Move plaintext forward
            buffer.copy_within(
                plaintext_start..plaintext_start + plaintext_len,
                new_plaintext_start,
            );
        } else if new_plaintext_start < plaintext_start {
            // Shift plaintext backward
            buffer.copy_within(
                plaintext_start..plaintext_start + plaintext_len,
                new_plaintext_start,
            );
        }
        // If equal, no shift needed

        // Write DTLS 1.2 header in place
        buffer[0] = inner_content_type.as_u8();
        // Version: DTLS 1.2 = 0xFEFD
        buffer[1] = 0xFE;
        buffer[2] = 0xFD;
        // Epoch (2 bytes)
        buffer[3] = (epoch >> 8) as u8;
        buffer[4] = (epoch & 0xFF) as u8;
        // Sequence number (6 bytes, from 8-byte u64)
        let seq_bytes = sequence_number.to_be_bytes();
        buffer[5..11].copy_from_slice(&seq_bytes[2..8]);
        // Length (2 bytes)
        buffer[11] = (plaintext_len >> 8) as u8;
        buffer[12] = (plaintext_len & 0xFF) as u8;

        // Truncate buffer to header + plaintext
        buffer.truncate(DTLS12_HEADER_LEN + plaintext_len);

        let parsed = ParsedRecord::parse(&buffer, engine, 0)?;
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
    pub fn parse(input: &[u8], engine: &Engine, offset: usize) -> Result<ParsedRecord, Error> {
        let (_, record) = DTLSRecord::parse(input, 0, offset)?;

        let handshakes = if record.content_type == ContentType::Handshake {
            // This will also return None on the encrypted Finished after ChangeCipherSpec.
            // However we will then decrypt and try again.
            let fragment_offset = record.fragment_range.start;
            parse_handshakes(record.fragment(input), fragment_offset, engine)
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

fn parse_handshakes(
    mut input: &[u8],
    mut base_offset: usize,
    engine: &Engine,
) -> ArrayVec<Handshake, 8> {
    let mut handshakes = ArrayVec::new();
    while !input.is_empty() {
        if let Ok((remaining, handshake)) =
            Handshake::parse(input, base_offset, engine.cipher_suite(), true)
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
