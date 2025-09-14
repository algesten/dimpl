use std::ops::Deref;

use self_cell::{self_cell, MutBorrow};
use std::fmt;
use tinyvec::ArrayVec;

use crate::buffer::Buf;
use crate::crypto::DTLS_EXPLICIT_NONCE_LEN;
use crate::engine::Engine;
use crate::message::{ContentType, DTLSRecord, DTLSRecordSlice, Handshake};
use crate::Error;

/// Holds both the UDP packet and the parsed result of that packet.
///
/// A self-referential struct.
pub struct Incoming(Inner);

impl Incoming {
    // pub fn into_inner(self) -> Buffer {
    //     self.0.into_owner()
    // }

    pub fn records(&self) -> &Records {
        self.0.borrow_dependent()
    }

    pub fn first(&self) -> &Record {
        // Invariant: Every Incoming must have at least one Record
        // or the parser would have failed. See use of many1 below.
        &self.records()[0]
    }

    pub fn last(&self) -> &Record {
        // Invariant: See above.
        self.records().last().unwrap()
    }
}

self_cell!(
    struct Inner {
        owner: MutBorrow<Buf<'static>>, // Buffer with UDP packet data
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
        mut into: Buf<'static>,
    ) -> Result<Self, Error> {
        // The Buffer is where we store the raw packet data.
        into.resize(packet.len(), 0);
        into.copy_from_slice(packet);

        let into = MutBorrow::new(into);

        // håll i hatten
        let inner = Inner::try_new(into, |data| {
            Ok::<_, Error>(Records::parse(data.borrow_mut(), engine)?)
        })?;

        Ok(Incoming(inner))
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
            match Record::parse(dtls_rec.slice, engine, true) {
                Ok(record) => {
                    if let Some(record) = record {
                        records.push(record);
                    } else {
                        // Silently drop duplicate/too-old records per RFC 6347
                        trace!("Drop replayed record");
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
    pub fn parse(
        input: &'a mut [u8],
        engine: &mut Engine,
        decrypt: bool,
    ) -> Result<Option<Record<'a>>, Error> {
        let inner = RecordInner::try_new(input, |borrowed| {
            Ok::<_, Error>(ParsedRecord::parse(&borrowed, engine)?)
        })?;

        let record = Record(inner);

        if record.record().content_type == ContentType::ChangeCipherSpec {
            // Validate CCS payload value (single byte 0x01)
            let dtls = record.record();
            if dtls.fragment.len() != 1 || dtls.fragment[0] != 0x01 {
                return Err(Error::SecurityError(
                    "Invalid ChangeCipherSpec payload".to_string(),
                ));
            }
            engine.enable_peer_encryption();
        } else if decrypt && engine.is_peer_encryption_enabled() {
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
                let mut buffer = Buf::wrap(ciphertext).keep_on_drop();

                // This decrypts in place.
                engine.decrypt_data(&mut buffer, aad, nonce)?;

                buffer.len()
            };

            // Update the length of the record.
            input[DTLSRecord::LENGTH_OFFSET].copy_from_slice(&(new_len as u16).to_be_bytes());

            // Shift the decrypted buffer to the start of the record.
            input.copy_within(CIPH..(CIPH + new_len), DTLSRecord::HEADER_LEN);

            return Record::parse(input, engine, false);
        }

        Ok(Some(record))
    }

    pub fn record(&self) -> &DTLSRecord {
        &self.0.borrow_dependent().record
    }

    pub fn handshake(&self) -> Option<&Handshake> {
        self.0.borrow_dependent().handshake.as_ref()
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
    pub record: DTLSRecord<'a>,
    pub handshake: Option<Handshake<'a>>,
}

impl<'a> ParsedRecord<'a> {
    pub fn parse(input: &'a [u8], engine: &mut Engine) -> Result<ParsedRecord<'a>, Error> {
        let (_, record) = DTLSRecord::parse(input)?;

        let handshake = if record.content_type == ContentType::Handshake {
            // This will also return None on the encrypted Finished after ChangeCipherSpec.
            // However we will then decrypt and try again.
            maybe_handshake(record.fragment, engine)
        } else {
            None
        };

        Ok(ParsedRecord { record, handshake })
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
        }))
    }
}
