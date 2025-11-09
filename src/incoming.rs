use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};

use self_cell::{self_cell, MutBorrow};
use std::fmt;
use tinyvec::ArrayVec;

use crate::buffer::{Buf, TmpBuf};
use crate::crypto::DTLS_EXPLICIT_NONCE_LEN;
use crate::engine::Engine;
use crate::message::{ContentType, DTLSRecord, DTLSRecordSlice, Handshake};
use crate::Error;

/// Holds both the UDP packet and the parsed result of that packet.
///
/// A self-referential struct.
pub struct Incoming(Inner);

impl Incoming {
    pub fn records(&self) -> &Records {
        self.0.borrow_dependent()
    }

    pub fn first(&self) -> &Record {
        // Invariant: Every Incoming must have at least one Record
        // or the parser of Incoming returns None.
        &self.records()[0]
    }

    pub fn into_owner(self) -> Buf {
        self.0.into_owner().into_inner()
    }
}

self_cell!(
    struct Inner {
        owner: MutBorrow<Buf>, // Buffer with UDP packet data
        #[covariant]
        dependent: Records, // Parsed records from that UDP packet
    }
);

impl Incoming {
    /// Parse an incoming UDP packet
    ///
    /// * `packet` is the data from the UDP socket.
    /// * `c` is a reference to the `CipherSuite` that's been selected. Some of
    ///   the parsing requires to know this to parse correctly. For Client code,
    ///   this value is only known after we receive ServerHello, which means it
    ///   can start empty and be filled in as soon as we know the value.
    /// * `into` the buffer in which we want to store the UDP data.
    ///
    /// Will surface parser errors.
    pub fn parse_packet(
        packet: &[u8],
        engine: &mut Engine,
        mut into: Buf,
    ) -> Result<Option<Self>, Error> {
        // The Buffer is where we store the raw packet data.
        into.resize(packet.len(), 0);
        into.copy_from_slice(packet);

        let into = MutBorrow::new(into);

        // håll i hatten
        let inner = Inner::try_new(into, |data| Records::parse(data.borrow_mut(), engine))?;

        // We need at least one Record to be valid. For replayed frames, we discard
        // the records, hence this might be None
        let incoming = Incoming(inner);
        if incoming.records().is_empty() {
            return Ok(None);
        }

        Ok(Some(incoming))
    }
}

/// A number of records parsed from a single UDP packet.
#[derive(Debug)]
pub struct Records<'a> {
    pub records: ArrayVec<[Record<'a>; 32]>,
}

impl<'a> Records<'a> {
    pub fn parse(input: &'a mut [u8], engine: &mut Engine) -> Result<Records<'a>, Error> {
        let mut records = ArrayVec::default();
        let mut current = input;

        // DTLSRecordSlice::try_read will end with None when cleanly chunking ends.
        // Any extra bytes will cause an Error.
        while let Some(dtls_rec) = DTLSRecordSlice::try_read(current)? {
            match Record::parse(dtls_rec.slice, engine) {
                Ok(record) => {
                    if let Some(record) = record {
                        records.push(record);
                    } else {
                        trace!("Discarding replayed rec");
                    }
                }
                Err(e) => return Err(e),
            }
            current = dtls_rec.rest;
        }

        Ok(Records { records })
    }
}

impl<'a> Deref for Records<'a> {
    type Target = [Record<'a>];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

pub struct Record<'a>(RecordInner<'a>);

impl<'a> Record<'a> {
    /// The first parse pass only parses the DTLSRecord header which is unencrypted.
    pub fn parse(input: &'a mut [u8], engine: &mut Engine) -> Result<Option<Record<'a>>, Error> {
        let inner = RecordInner::try_new(input, |borrowed| ParsedRecord::parse(borrowed, engine))?;

        let record = Record(inner);

        // It is not enough to only look at the epoch, since to be able to decrypt the entire
        // preceeding set of flights sets up the cryptographic context. In a situation with
        // packet loss, we can end up seeing epoch 1 records before we can decrypt them.
        let is_epoch_0 = record.record().sequence.epoch == 0;
        if is_epoch_0 || !engine.is_peer_encryption_enabled() {
            return Ok(Some(record));
        }

        // We need to decrypt the record and redo the parsing.
        let dtls = record.record();

        // Anti-replay check
        if !engine.replay_check_and_update(dtls.sequence) {
            return Ok(None);
        }

        let (aad, nonce) = engine.decryption_aad_and_nonce(dtls);

        // Bring back the unparsed bytes.
        let input = record.0.into_owner();

        // Local shorthand for where the encrypted ciphertext starts
        const CIPH: usize = DTLSRecord::HEADER_LEN + DTLS_EXPLICIT_NONCE_LEN;

        // The encrypted part is after the DTLS header and explicit nonce.
        // The entire buffer is only the single record, since we chunk
        // records up in Records::parse()
        let ciphertext = &mut input[CIPH..];

        let new_len = {
            let mut buffer = TmpBuf::new(ciphertext);

            // This decrypts in place.
            engine.decrypt_data(&mut buffer, aad, nonce)?;

            buffer.len()
        };

        // Update the length of the record.
        input[DTLSRecord::LENGTH_OFFSET].copy_from_slice(&(new_len as u16).to_be_bytes());

        // Shift the decrypted buffer to the start of the record.
        input.copy_within(CIPH..(CIPH + new_len), DTLSRecord::HEADER_LEN);

        let inner = RecordInner::try_new(input, |borrowed| ParsedRecord::parse(borrowed, engine))?;

        Ok(Some(Record(inner)))
    }

    pub fn record(&self) -> &DTLSRecord {
        &self.0.borrow_dependent().record
    }

    pub fn handshake(&self) -> Option<&Handshake> {
        self.0.borrow_dependent().handshake.as_ref()
    }

    pub fn is_handled(&self) -> bool {
        let rec = self.0.borrow_dependent();
        rec.handshake
            .as_ref()
            .map(|h| h.handled.load(Ordering::Relaxed))
            .unwrap_or(rec.handled.load(Ordering::Relaxed))
    }

    pub fn set_handled(&self) {
        self.0
            .borrow_dependent()
            .handled
            .store(true, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.0.borrow_owner().len()
    }
}

self_cell!(
    pub struct RecordInner<'a> {
        owner: &'a mut [u8],

        #[covariant]
        dependent: ParsedRecord,
    }
);

pub struct ParsedRecord<'a> {
    record: DTLSRecord<'a>,
    handshake: Option<Handshake<'a>>,
    handled: AtomicBool,
}

impl<'a> ParsedRecord<'a> {
    pub fn parse(input: &'a [u8], engine: &Engine) -> Result<ParsedRecord<'a>, Error> {
        let (_, record) = DTLSRecord::parse(input)?;

        let handshake = if record.content_type == ContentType::Handshake {
            // This will also return None on the encrypted Finished after ChangeCipherSpec.
            // However we will then decrypt and try again.
            maybe_handshake(record.fragment, engine)
        } else {
            None
        };

        Ok(ParsedRecord {
            record,
            handshake,
            handled: AtomicBool::new(false),
        })
    }
}

fn maybe_handshake<'a>(input: &'a [u8], engine: &Engine) -> Option<Handshake<'a>> {
    let (_, handshake) = Handshake::parse(input, engine.cipher_suite(), true).ok()?;
    Some(handshake)
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("records", &self.records())
            .finish()
    }
}

impl<'a> fmt::Debug for Record<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("record", &self.0.borrow_dependent().record)
            .field("handshake", &self.0.borrow_dependent().handshake)
            .finish()
    }
}

impl<'a> Default for Record<'a> {
    fn default() -> Self {
        Record(RecordInner::new(&mut [], |_| ParsedRecord {
            record: DTLSRecord::default(),
            handshake: None,
            handled: AtomicBool::new(false),
        }))
    }
}

/*
Why it is sound to assert UnwindSafe for Incoming

- No internal unwind boundaries: this crate does not use catch_unwind. We do not
  cross panic boundaries internally while mutating state. This marker exists to
  document that external callers can wrap our APIs in catch_unwind without
  observing broken invariants from this type.

- self_cell construction is panic-safe without catch_unwind: Incoming/Record are
  built via self_cell::new/try_new. The crate uses a drop guard to clean up a
  partially-initialized allocation if the dependent builder panics. No value
  escapes on panic, so a half-built object cannot be observed across unwinding.

- Read-only builders: our dependent builders (e.g., ParsedRecord::parse) take
  only a &[u8] to the owner and do not mutate the owner during construction. An
  unwind during builder execution therefore cannot leave the owner partially
  mutated across a boundary.

- Decrypt-and-reparse is publish-after-complete: when decrypting we first call
  into_owner() to regain the raw bytes, mutate a local &mut [u8] (length update,
  in-place decrypt, copy_within), and only then construct a fresh RecordInner
  from the fully transformed bytes. If a panic occurs mid-transformation, the
  new RecordInner is not built and the previously-built Record is dropped; no
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
