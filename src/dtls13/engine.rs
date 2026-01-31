use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;

use super::queue::{QueueRx, QueueTx};
use crate::buffer::{Buf, BufferPool, TmpBuf};
use crate::crypto::{
    Aad, Cipher, HkdfProvider, Nonce, SigningKey, SupportedDtls13CipherSuite, SupportedKxGroup,
};
use crate::dtls13::incoming::{Incoming, Record, RecordDecrypt};
use crate::dtls13::message::{
    Body, ContentType, Dtls13CipherSuite, Dtls13Record, Handshake, Header, MessageType, Sequence,
};
use crate::timer::ExponentialBackoff;
use crate::types::HashAlgorithm;
use crate::window::ReplayWindow;
use crate::{Config, Error, Output, SeededRng};

const MAX_DEFRAGMENT_PACKETS: usize = 50;

pub struct Engine {
    config: Arc<Config>,

    /// Seedable random number generator for deterministic testing
    pub(crate) rng: SeededRng,

    /// Pool of buffers
    buffers_free: BufferPool,

    /// Counters for sending DTLSPlaintext during epoch 0.
    sequence_epoch_0: Sequence,

    /// Queue of incoming packets.
    queue_rx: QueueRx,

    /// Queue of outgoing packets.
    queue_tx: QueueTx,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<Dtls13CipherSuite>,

    /// Handshake send keys (epoch 2)
    hs_send_keys: Option<EpochKeys>,

    /// Handshake receive keys (epoch 2)
    hs_recv_keys: Option<EpochKeys>,

    /// Expected next receive sequence number for epoch 2 (handshake)
    hs_expected_recv_seq: u64,

    /// Application send epoch (3 initially, increments on KeyUpdate)
    app_send_epoch: u16,

    /// Sequence number for handshake epoch (epoch 2) sending
    hs_send_seq: u64,

    /// Sequence number within current send epoch
    app_send_seq: u64,

    /// Application send keys (only latest epoch; replaced on KeyUpdate)
    app_send_keys: Option<EpochKeys>,

    /// Application receive keys. Multiple epochs may coexist due to KeyUpdate.
    app_recv_keys: ArrayVec<RecvEpochEntry, 4>,

    /// Whether the remote peer has enabled encryption
    peer_encryption_enabled: bool,

    /// Certificate in DER format
    certificate_der: Vec<u8>,

    /// Signing key for CertificateVerify
    signing_key: Box<dyn SigningKey>,

    /// Whether this engine is for a client (true) or server (false)
    is_client: bool,

    /// Expected peer handshake sequence number
    peer_handshake_seq_no: u16,

    /// Next handshake message sequence number for sending
    next_handshake_seq_no: u16,

    /// Handshakes collected for hash computation.
    /// TLS 1.3 transcript: msg_type(1) + length(3), no DTLS framing.
    pub(crate) transcript: Buf,

    /// Anti-replay window state
    replay: ReplayWindow,

    /// Record numbers of received handshake records, for ACK generation.
    /// Each entry is (epoch, sequence_number).
    received_record_numbers: Vec<(u64, u64)>,

    /// The records that have been sent in the current flight.
    flight_saved_records: Vec<Entry>,

    /// Flight backoff
    flight_backoff: ExponentialBackoff,

    /// Timeout for the current flight
    flight_timeout: Timeout,

    /// Global timeout for the entire connect operation.
    connect_timeout: Timeout,

    /// Whether we are ready to release application data from poll_output.
    release_app_data: bool,

    /// Exporter master secret for TLS 1.3 exporters (RFC 8446 Section 7.5).
    exporter_master_secret: Option<Buf>,
}

struct EpochKeys {
    cipher: Box<dyn Cipher>,
    iv: [u8; 12],
    traffic_secret: Buf,
    sn_key: Buf,
}

struct RecvEpochEntry {
    epoch: u16,
    keys: EpochKeys,
    expected_recv_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Timeout {
    Disabled,
    Unarmed,
    Armed(Instant),
}

#[derive(Debug)]
struct Entry {
    content_type: ContentType,
    epoch: u16,
    send_seq: u64,
    fragment: Buf,
    acked: bool,
}

impl Engine {
    pub fn new(config: Arc<Config>, certificate: crate::DtlsCertificate) -> Self {
        let mut rng = SeededRng::new(config.rng_seed());

        let flight_backoff =
            ExponentialBackoff::new(config.flight_start_rto(), config.flight_retries(), &mut rng);

        let signing_key = config
            .crypto_provider()
            .key_provider
            .load_private_key(&certificate.private_key)
            .expect("Failed to load private key");

        Self {
            config,
            rng,
            buffers_free: BufferPool::default(),
            sequence_epoch_0: Sequence::new(0),
            queue_rx: QueueRx::new(),
            queue_tx: QueueTx::new(),
            cipher_suite: None,
            hs_send_keys: None,
            hs_recv_keys: None,
            hs_expected_recv_seq: 0,
            app_send_epoch: 3,
            hs_send_seq: 0,
            app_send_seq: 0,
            app_send_keys: None,
            app_recv_keys: ArrayVec::new(),
            peer_encryption_enabled: false,
            certificate_der: certificate.certificate,
            signing_key,
            is_client: false,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            transcript: Buf::new(),
            replay: ReplayWindow::new(),
            received_record_numbers: Vec::new(),
            flight_saved_records: Vec::new(),
            flight_backoff,
            flight_timeout: Timeout::Unarmed,
            connect_timeout: Timeout::Unarmed,
            release_app_data: false,
            exporter_master_secret: None,
        }
    }

    pub fn set_client(&mut self, is_client: bool) {
        self.is_client = is_client;
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn cipher_suite(&self) -> Option<Dtls13CipherSuite> {
        self.cipher_suite
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: Dtls13CipherSuite) {
        self.cipher_suite = Some(cipher_suite);
    }

    pub fn is_cipher_suite_allowed(&self, suite: Dtls13CipherSuite) -> bool {
        self.config
            .crypto_provider()
            .dtls13_cipher_suites
            .iter()
            .any(|cs| cs.suite() == suite)
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn signing_key(&mut self) -> &mut dyn SigningKey {
        &mut *self.signing_key
    }

    pub fn parse_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let cs = self.cipher_suite;
        let incoming = Incoming::parse_packet(packet, self, cs)?;
        if let Some(incoming) = incoming {
            self.insert_incoming(incoming)?;
        }

        Ok(())
    }

    fn insert_incoming(&mut self, incoming: Incoming) -> Result<(), Error> {
        if self.queue_rx.len() >= self.config.max_queue_rx() {
            warn!(
                "Receive queue full (max {}): {:?}",
                self.config.max_queue_rx(),
                self.queue_rx
            );
            return Err(Error::ReceiveQueueFull);
        }

        // Handle ACK records immediately (don't queue them)
        let first = incoming.first();
        if first.record().content_type == ContentType::Ack {
            let fragment = first.record().fragment(first.buffer());
            self.process_ack(fragment);
            return Ok(());
        }

        if incoming.first().first_handshake().is_some() {
            self.insert_incoming_handshake(incoming)
        } else {
            self.insert_incoming_non_handshake(incoming)
        }
    }

    fn insert_incoming_handshake(&mut self, incoming: Incoming) -> Result<(), Error> {
        let first_record = incoming.first();
        let handshake = first_record
            .first_handshake()
            .expect("caller ensures handshake");

        let key_current = (
            handshake.header.message_seq,
            handshake.header.fragment_offset,
        );

        let maybe_dupe_seq = incoming
            .records()
            .iter()
            .filter_map(|r| r.first_handshake())
            .filter_map(|h| h.dupe_triggers_resend())
            .next();

        if let Some(dupe_seq) = maybe_dupe_seq {
            if dupe_seq < self.peer_handshake_seq_no {
                self.flight_resend("dupe triggers resend")?;
            }
        }

        // Drop old duplicates we've already processed
        if handshake.header.message_seq < self.peer_handshake_seq_no {
            return Ok(());
        }

        // Reject new handshakes after initial handshake is complete
        if self.release_app_data && handshake.header.message_seq >= self.peer_handshake_seq_no {
            return Err(Error::RenegotiationAttempt);
        }

        let search_result = self.queue_rx.binary_search_by(|item| {
            let key_other = item
                .first()
                .first_handshake()
                .as_ref()
                .map(|h| (h.header.message_seq, h.header.fragment_offset))
                .unwrap_or((u16::MAX, u32::MAX));
            key_other.cmp(&key_current)
        });

        match search_result {
            Err(index) => {
                // Track received record numbers for ACK generation
                for record in incoming.records().iter() {
                    let seq = record.record().sequence;
                    if seq.epoch >= 2 {
                        self.received_record_numbers
                            .push((seq.epoch as u64, seq.sequence_number));
                    }
                }
                self.queue_rx.insert(index, incoming);
            }
            Ok(_) => {
                // Exact duplicate handshake fragment
            }
        }

        Ok(())
    }

    fn insert_incoming_non_handshake(&mut self, incoming: Incoming) -> Result<(), Error> {
        let first = incoming.first();
        let seq_current = first.record().sequence;

        let search_result = self
            .queue_rx
            .binary_search_by_key(&seq_current, |item| item.first().record().sequence);

        match search_result {
            Err(index) => self.queue_rx.insert(index, incoming),
            Ok(_) => {
                // Duplicate - for encrypted records the replay window already filters these
                assert!(seq_current.epoch == 0);
            }
        }

        Ok(())
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if self.connect_timeout == Timeout::Unarmed {
            debug!(
                "Connect timeout in: {:.03}s",
                self.config.handshake_timeout().as_secs_f32()
            );
            let timeout = now + self.config.handshake_timeout();
            self.connect_timeout = Timeout::Armed(timeout);
        }
        if self.flight_timeout == Timeout::Unarmed {
            debug!(
                "Flight timeout in: {:.03}s",
                self.flight_backoff.rto().as_secs_f32()
            );
            let timeout = now + self.flight_backoff.rto();
            self.flight_timeout = Timeout::Armed(timeout);
        }

        if let Timeout::Armed(connect_timeout) = self.connect_timeout {
            if now >= connect_timeout {
                return Err(Error::Timeout("connect"));
            }
        }

        let Timeout::Armed(flight_timeout) = self.flight_timeout else {
            return Ok(());
        };

        if now >= flight_timeout {
            if self.flight_backoff.can_retry() {
                self.flight_backoff.attempt(&mut self.rng);
                debug!(
                    "Re-arm flight timeout due to resend in {}",
                    self.flight_backoff.rto().as_secs_f32()
                );
                let timeout = now + self.flight_backoff.rto();
                self.flight_timeout = Timeout::Armed(timeout);
                self.flight_resend("flight timeout")?;
            } else {
                return Err(Error::Timeout("handshake"));
            }
        }

        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8], now: Instant) -> Output<'a> {
        self.purge_handled_queue_rx();

        let buf = match self.poll_app_data(buf) {
            Ok(p) => return Output::ApplicationData(p),
            Err(b) => b,
        };

        if let Ok(p) = self.poll_packet_tx(buf) {
            return Output::Packet(p);
        }

        let next_timeout = self.poll_timeout(now);

        Output::Timeout(next_timeout)
    }

    fn poll_app_data<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], &'a mut [u8]> {
        if !self.release_app_data {
            return Err(buf);
        }

        let mut unhandled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .filter(|r| r.record().content_type == ContentType::ApplicationData)
            .skip_while(|r| r.is_handled());

        let Some(next) = unhandled.next() else {
            return Err(buf);
        };

        let record_buffer = next.buffer();
        let fragment = next.record().fragment(record_buffer);
        let len = fragment.len();

        assert!(
            len <= buf.len(),
            "Output buffer too small for application data {} > {}",
            len,
            buf.len()
        );

        buf[..len].copy_from_slice(fragment);
        next.set_handled();

        Ok(&buf[..len])
    }

    fn purge_handled_queue_rx(&mut self) {
        while let Some(peek) = self.queue_rx.front() {
            let fully_handled = peek.records().iter().all(|r| r.is_handled());

            if fully_handled {
                let incoming = self.queue_rx.pop_front().unwrap();
                incoming
                    .into_records()
                    .for_each(|r| self.buffers_free.push(r.into_buffer()));
            } else {
                break;
            }
        }
    }

    fn poll_packet_tx<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], &'a mut [u8]> {
        let Some(p) = self.queue_tx.pop_front() else {
            return Err(buf);
        };

        assert!(
            p.len() <= buf.len(),
            "Output buffer too small for packet {} > {}",
            p.len(),
            buf.len()
        );

        let len = p.len();
        buf[..len].copy_from_slice(&p);

        Ok(&buf[..len])
    }

    fn poll_timeout(&self, now: Instant) -> Instant {
        if self.connect_timeout == Timeout::Disabled && self.flight_timeout == Timeout::Disabled {
            const DISTANT_FUTURE: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
            return now + DISTANT_FUTURE;
        }

        match (self.connect_timeout, self.flight_timeout) {
            (Timeout::Armed(c), Timeout::Armed(f)) => {
                if c < f {
                    c
                } else {
                    f
                }
            }
            (Timeout::Armed(c), _) => c,
            (_, Timeout::Armed(f)) => f,
            _ => unreachable!(),
        }
    }

    pub fn flight_begin(&mut self, flight_no: u8) {
        debug!("Begin flight {}", flight_no);
        self.flight_backoff.reset(&mut self.rng);
        self.flight_clear_resends();
        self.flight_timeout = Timeout::Unarmed;
    }

    pub fn flight_stop_resend_timers(&mut self) {
        debug!("Stop connect and flight timeouts");
        self.flight_timeout = Timeout::Disabled;
        self.connect_timeout = Timeout::Disabled;
    }

    fn flight_clear_resends(&mut self) {
        for entry in self.flight_saved_records.drain(..) {
            self.buffers_free.push(entry.fragment);
        }
    }

    fn flight_resend(&mut self, reason: &str) -> Result<(), Error> {
        debug!("Resending flight due to {}", reason);
        let records = mem::take(&mut self.flight_saved_records);

        for entry in &records {
            // Selective retransmission: skip records that have been ACKed
            if entry.acked {
                continue;
            }

            if entry.epoch == 0 {
                self.create_plaintext_record(entry.content_type, false, |fragment| {
                    fragment.extend_from_slice(&entry.fragment);
                })?;
            } else {
                self.create_ciphertext_record(
                    entry.content_type,
                    entry.epoch,
                    false,
                    |fragment| {
                        fragment.extend_from_slice(&entry.fragment);
                    },
                )?;
            }
        }

        self.flight_saved_records = records;

        Ok(())
    }

    pub fn has_complete_handshake(&mut self, wanted: MessageType) -> bool {
        self.has_complete_handshake_with_seq(wanted, self.peer_handshake_seq_no)
    }

    fn has_complete_handshake_with_seq(&mut self, wanted: MessageType, expected_seq: u16) -> bool {
        let mut skip_handled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            .take(MAX_DEFRAGMENT_PACKETS)
            .flat_map(|r| r.handshakes().iter())
            .skip_while(|h| h.is_handled())
            .peekable();

        let maybe_first_handshake = skip_handled.peek();

        let Some(first) = maybe_first_handshake else {
            return false;
        };

        if first.header.message_seq != expected_seq {
            return false;
        }

        if first.header.msg_type != wanted {
            return false;
        }

        let wanted_seq = first.header.message_seq;
        let wanted_length = first.header.length;
        let mut last_fragment_end = 0;

        for h in skip_handled {
            if wanted_seq != h.header.message_seq {
                continue;
            }

            if h.header.fragment_offset != last_fragment_end {
                return false;
            }
            last_fragment_end = h.header.fragment_offset + h.header.fragment_length;

            if last_fragment_end == wanted_length {
                return true;
            }
        }

        false
    }

    pub fn next_handshake(
        &mut self,
        wanted: MessageType,
        defragment_buffer: &mut Buf,
    ) -> Result<Option<Handshake>, Error> {
        if !self.has_complete_handshake(wanted) {
            return Ok(None);
        }

        let iter = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            .flat_map(|r| r.handshakes().iter().map(move |h| (h, r.buffer())))
            .skip_while(|(h, _)| h.is_handled());

        let handshake = Handshake::defragment(
            iter,
            defragment_buffer,
            self.cipher_suite,
            Some(&mut self.transcript),
        )?;

        self.peer_handshake_seq_no = handshake.header.message_seq + 1;

        Ok(Some(handshake))
    }

    pub(crate) fn next_record(&mut self, ctype: ContentType) -> Option<&Record> {
        let record = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .find(|r| !r.is_handled())?;

        if record.record().content_type != ctype {
            return None;
        }

        record.set_handled();

        Some(record)
    }

    /// Create a DTLSPlaintext record (epoch 0, unencrypted).
    pub fn create_plaintext_record<F>(
        &mut self,
        content_type: ContentType,
        save_fragment: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        let mut fragment = self.buffers_free.pop();
        f(&mut fragment);

        let current_seq = self.sequence_epoch_0.sequence_number;

        if save_fragment {
            let mut clone = self.buffers_free.pop();
            clone.extend_from_slice(&fragment);
            self.flight_saved_records.push(Entry {
                content_type,
                epoch: 0,
                send_seq: current_seq,
                fragment: clone,
                acked: false,
            });
        }

        let record_wire_len = Dtls13Record::PLAINTEXT_HEADER_LEN + fragment.len();

        let can_append = self
            .queue_tx
            .back()
            .map(|b| b.len() + record_wire_len <= self.config.mtu())
            .unwrap_or(false);

        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx() {
            warn!(
                "Transmit queue full (max {}): {:?}",
                self.config.max_queue_tx(),
                self.queue_tx
            );
            return Err(Error::TransmitQueueFull);
        }

        let sequence = self.sequence_epoch_0;

        let record = Dtls13Record {
            content_type,
            sequence,
            length: fragment.len() as u16,
            fragment_range: 0..fragment.len(),
        };

        self.sequence_epoch_0.sequence_number += 1;

        if can_append {
            let last = self.queue_tx.back_mut().unwrap();
            record.serialize(&fragment, last);
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            record.serialize(&fragment, &mut buffer);
            self.queue_tx.push_back(buffer);
        }

        self.buffers_free.push(fragment);

        Ok(())
    }

    /// Create a DTLSCiphertext record (epoch >= 2, encrypted).
    ///
    /// The plaintext fragment is wrapped as DTLSInnerPlaintext:
    /// `content || content_type(1) || zeros*` before AEAD encryption.
    pub fn create_ciphertext_record<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        let mut fragment = self.buffers_free.pop();
        f(&mut fragment);

        // Determine sequence number for this record
        let seq = if epoch == 2 {
            self.hs_send_seq
        } else {
            self.app_send_seq
        };

        if save_fragment {
            let mut clone = self.buffers_free.pop();
            clone.extend_from_slice(&fragment);
            self.flight_saved_records.push(Entry {
                content_type,
                epoch,
                send_seq: seq,
                fragment: clone,
                acked: false,
            });
        }

        // Build DTLSInnerPlaintext: content || content_type(1)
        // (no zero padding for now)
        fragment.push(content_type.as_u8());

        let suite = self.suite_provider();
        let tag_len = suite.tag_len();

        // Get the send keys for this epoch
        let keys = if epoch == 2 {
            self.hs_send_keys.as_mut()
        } else {
            self.app_send_keys.as_mut()
        };

        let Some(keys) = keys else {
            return Err(Error::CryptoError(format!(
                "Send keys not available for epoch {}",
                epoch
            )));
        };

        // Construct the nonce: iv XOR padded_seq
        let nonce = Nonce::xor(&keys.iv, seq);

        // Build the unified header for AAD
        // Always use S=1 (2-byte seq) and L=1 (length present)
        let epoch_bits = (epoch & 0x03) as u8;
        let flags: u8 = 0b0010_0000
            | 0b0000_1000 // S=1
            | 0b0000_0100 // L=1
            | epoch_bits;

        let ciphertext_len = fragment.len() + tag_len;

        let mut header_buf = [0u8; 5];
        header_buf[0] = flags;
        header_buf[1..3].copy_from_slice(&(seq as u16).to_be_bytes());
        header_buf[3..5].copy_from_slice(&(ciphertext_len as u16).to_be_bytes());

        let aad = Aad::new_dtls13(&header_buf);

        // Save sn_key before losing mutable borrow of keys
        let mut sn_key = [0u8; 32];
        let sn_key_len = keys.sn_key.len();
        sn_key[..sn_key_len].copy_from_slice(&keys.sn_key);

        // Encrypt in place (appends tag)
        keys.cipher
            .encrypt(&mut fragment, aad, nonce)
            .map_err(|e| Error::CryptoError(format!("Encryption failed: {}", e)))?;

        // Record number encryption (RFC 9147 Section 4.2.3):
        // mask = AES-ECB(sn_key, ciphertext_sample)
        // XOR mask[0..2] over the sequence number bytes in the header
        let sn_mask = if fragment.len() >= 16 {
            // unwrap: we checked length >= 16
            let ciphertext_sample: [u8; 16] = fragment[..16].try_into().unwrap();
            suite.encrypt_sn(&sn_key[..sn_key_len], &ciphertext_sample)
        } else {
            [0u8; 16] // degenerate case: no masking if ciphertext too short
        };

        // Unified header: flags(1) + seq(2) + length(2) = 5 bytes
        let record_wire_len = 5 + fragment.len();

        let can_append = self
            .queue_tx
            .back()
            .map(|b| b.len() + record_wire_len <= self.config.mtu())
            .unwrap_or(false);

        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx() {
            warn!(
                "Transmit queue full (max {}): {:?}",
                self.config.max_queue_tx(),
                self.queue_tx
            );
            return Err(Error::TransmitQueueFull);
        }

        // Build the record for serialization
        let record = Dtls13Record {
            content_type: ContentType::ApplicationData,
            sequence: Sequence {
                epoch,
                sequence_number: seq,
            },
            length: fragment.len() as u16,
            fragment_range: 0..fragment.len(),
        };

        // Increment send sequence
        if epoch == 2 {
            self.hs_send_seq += 1;
        } else {
            self.app_send_seq += 1;
        }

        if can_append {
            let last = self.queue_tx.back_mut().unwrap();
            let header_start = last.len();
            record.serialize(&fragment, last);
            // Apply record number encryption: XOR mask over seq bytes
            // Seq bytes are at offset header_start+1..header_start+3
            last[header_start + 1] ^= sn_mask[0];
            last[header_start + 2] ^= sn_mask[1];
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            record.serialize(&fragment, &mut buffer);
            // Apply record number encryption: XOR mask over seq bytes
            buffer[1] ^= sn_mask[0];
            buffer[2] ^= sn_mask[1];
            self.queue_tx.push_back(buffer);
        }

        self.buffers_free.push(fragment);

        Ok(())
    }

    /// Create a handshake message and wrap it in a DTLS record.
    pub fn create_handshake<F>(&mut self, msg_type: MessageType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf, &mut Self) -> Result<(), Error>,
    {
        let mut body_buffer = self.buffers_free.pop();

        f(&mut body_buffer, self)?;

        let handshake_header = Header {
            msg_type,
            length: body_buffer.len() as u32,
            message_seq: self.next_handshake_seq_no,
            fragment_offset: 0,
            fragment_length: body_buffer.len() as u32,
        };

        // Write TLS 1.3 transcript: msg_type(1) + length(3) + body (no DTLS framing)
        self.transcript.push(msg_type.as_u8());
        self.transcript
            .extend_from_slice(&handshake_header.length.to_be_bytes()[1..]);
        self.transcript
            .extend_from_slice(&body_buffer[..handshake_header.length as usize]);

        self.next_handshake_seq_no += 1;

        let epoch = epoch_for_message(msg_type);
        let total_len = body_buffer.len();
        let mut offset: usize = 0;

        let handshake_header_len = 12usize;
        let tag_len = if epoch >= 2 {
            self.suite_provider().tag_len()
        } else {
            0
        };
        let aead_overhead = if epoch >= 2 { tag_len + 1 } else { 0 }; // +1 for inner content type

        while offset < total_len || (total_len == 0 && offset == 0) {
            let already_used_in_current = self.queue_tx.back().map(|b| b.len()).unwrap_or(0);
            let available_in_current = self.config.mtu().saturating_sub(already_used_in_current);

            let record_header_len = if epoch == 0 {
                Dtls13Record::PLAINTEXT_HEADER_LEN
            } else {
                5 // unified header: flags(1) + seq(2) + length(2)
            };

            let fixed_overhead = record_header_len + handshake_header_len + aead_overhead;

            let available_for_body = if available_in_current > fixed_overhead {
                available_in_current - fixed_overhead
            } else {
                self.config.mtu().saturating_sub(fixed_overhead)
            };

            let remaining_body_bytes = total_len.saturating_sub(offset);

            let chunk_len = if total_len == 0 {
                0
            } else {
                remaining_body_bytes.min(available_for_body)
            };

            let frag_range = if chunk_len == 0 {
                0..0
            } else {
                offset..offset + chunk_len
            };

            let frag_handshake = Handshake {
                header: Header {
                    msg_type,
                    length: handshake_header.length,
                    message_seq: handshake_header.message_seq,
                    fragment_offset: offset as u32,
                    fragment_length: chunk_len as u32,
                },
                body: Body::Fragment(frag_range),
                handled: AtomicBool::new(false),
            };

            if epoch == 0 {
                self.create_plaintext_record(ContentType::Handshake, true, |fragment| {
                    frag_handshake.serialize(&body_buffer, fragment);
                })?;
            } else {
                self.create_ciphertext_record(ContentType::Handshake, epoch, true, |fragment| {
                    frag_handshake.serialize(&body_buffer, fragment);
                })?;
            }

            if total_len == 0 {
                break;
            }

            offset += chunk_len;
        }

        self.buffers_free.push(body_buffer);

        Ok(())
    }

    /// Release application data from the incoming queue
    pub fn release_application_data(&mut self) {
        self.release_app_data = true;
    }

    /// Record that a handshake record was received, for ACK generation.
    pub fn record_received(&mut self, epoch: u16, seq: u64) {
        self.received_record_numbers.push((epoch as u64, seq));
    }

    /// Send an ACK record listing received handshake record numbers.
    ///
    /// ACK format: record_numbers_length(2) + N * (epoch(8) + sequence(8))
    pub fn send_ack(&mut self) -> Result<(), Error> {
        if self.received_record_numbers.is_empty() {
            return Ok(());
        }

        let entries = mem::take(&mut self.received_record_numbers);
        let epoch = if self.app_send_keys.is_some() { 3 } else { 2 };

        self.create_ciphertext_record(ContentType::Ack, epoch, false, |fragment| {
            // record_numbers_length: 2 bytes, value = entries.len() * 16
            let len = (entries.len() * 16) as u16;
            fragment.extend_from_slice(&len.to_be_bytes());
            for &(ep, seq) in &entries {
                fragment.extend_from_slice(&ep.to_be_bytes());
                fragment.extend_from_slice(&seq.to_be_bytes());
            }
        })?;

        Ok(())
    }

    /// Process an incoming ACK record, marking acknowledged flight entries.
    fn process_ack(&mut self, ack_data: &[u8]) {
        if ack_data.len() < 2 {
            return;
        }

        let record_numbers_len = u16::from_be_bytes([ack_data[0], ack_data[1]]) as usize;
        let entries_data = &ack_data[2..];

        if entries_data.len() < record_numbers_len {
            return;
        }

        let num_entries = record_numbers_len / 16;
        for i in 0..num_entries {
            let offset = i * 16;
            if offset + 16 > entries_data.len() {
                break;
            }
            let ack_epoch = u64::from_be_bytes(
                // unwrap: bounds checked above
                entries_data[offset..offset + 8].try_into().unwrap(),
            );
            let ack_seq = u64::from_be_bytes(
                // unwrap: bounds checked above
                entries_data[offset + 8..offset + 16].try_into().unwrap(),
            );

            // Mark matching flight entries as acknowledged
            for entry in &mut self.flight_saved_records {
                if entry.epoch as u64 == ack_epoch && entry.send_seq == ack_seq {
                    entry.acked = true;
                }
            }
        }
    }

    /// Pop a buffer from the buffer pool for temporary use
    pub(crate) fn pop_buffer(&mut self) -> Buf {
        self.buffers_free.pop()
    }

    /// Return a buffer to the buffer pool
    pub(crate) fn push_buffer(&mut self, buf: Buf) {
        self.buffers_free.push(buf);
    }

    // =========================================================================
    // Key Schedule
    // =========================================================================

    fn hkdf(&self) -> &dyn HkdfProvider {
        self.config.crypto_provider().hkdf_provider
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        // unwrap: cipher_suite must be set before key schedule operations
        self.cipher_suite.unwrap().hash_algorithm()
    }

    fn suite_provider(&self) -> &'static dyn SupportedDtls13CipherSuite {
        let suite = self.cipher_suite.unwrap();
        *self
            .config
            .crypto_provider()
            .dtls13_cipher_suites
            .iter()
            .find(|cs| cs.suite() == suite)
            .expect("cipher suite not found in provider")
    }

    /// Derive the early secret: HKDF-Extract(0, 0) [no PSK support]
    pub fn derive_early_secret(&self) -> Result<Buf, Error> {
        let hash = self.hash_algorithm();
        let hash_len = hash.output_len();
        let zeros = vec![0u8; hash_len];
        let mut early_secret = self.pop_buffer_internal();
        self.hkdf()
            .hkdf_extract(hash, &zeros, &zeros, &mut early_secret)
            .map_err(|e| Error::CryptoError(format!("Failed to derive early secret: {}", e)))?;
        Ok(early_secret)
    }

    /// Derive handshake secrets from ECDHE shared secret + transcript hash through ServerHello.
    ///
    /// Returns (client_handshake_traffic_secret, server_handshake_traffic_secret)
    pub fn derive_handshake_secrets(&mut self, shared_secret: &[u8]) -> Result<(Buf, Buf), Error> {
        let hash = self.hash_algorithm();
        let hash_len = hash.output_len();
        let hkdf = self.hkdf();

        // Derive-Secret(early_secret, "derived", "")
        let early_secret = self.derive_early_secret()?;
        let empty_hash = self.transcript_hash_of(b"");
        let mut derived = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &early_secret,
            b"derived",
            &empty_hash,
            &mut derived,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive 'derived' secret: {}", e)))?;

        // handshake_secret = HKDF-Extract(derived, shared_secret)
        let mut handshake_secret = Buf::new();
        hkdf.hkdf_extract(hash, &derived, shared_secret, &mut handshake_secret)
            .map_err(|e| Error::CryptoError(format!("Failed to derive handshake secret: {}", e)))?;

        // Get transcript hash up to and including ServerHello
        let mut transcript_hash = Buf::new();
        self.transcript_hash(&mut transcript_hash);

        // client_handshake_traffic_secret
        let mut c_hs_traffic = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &handshake_secret,
            b"c hs traffic",
            &transcript_hash,
            &mut c_hs_traffic,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive c_hs_traffic: {}", e)))?;

        // server_handshake_traffic_secret
        let mut s_hs_traffic = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &handshake_secret,
            b"s hs traffic",
            &transcript_hash,
            &mut s_hs_traffic,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive s_hs_traffic: {}", e)))?;

        Ok((c_hs_traffic, s_hs_traffic))
    }

    /// Install handshake keys (epoch 2) from the traffic secrets.
    pub fn install_handshake_keys(
        &mut self,
        client_traffic_secret: &Buf,
        server_traffic_secret: &Buf,
    ) -> Result<(), Error> {
        let (send_secret, recv_secret) = if self.is_client {
            (client_traffic_secret, server_traffic_secret)
        } else {
            (server_traffic_secret, client_traffic_secret)
        };

        self.hs_send_keys = Some(self.derive_epoch_keys(send_secret)?);
        self.hs_recv_keys = Some(self.derive_epoch_keys(recv_secret)?);

        // Reset send sequence for epoch 2
        self.hs_send_seq = 0;

        Ok(())
    }

    /// Derive application secrets from transcript hash through server Finished.
    ///
    /// Returns (client_app_traffic_secret, server_app_traffic_secret)
    pub fn derive_application_secrets(
        &mut self,
        handshake_secret: &[u8],
    ) -> Result<(Buf, Buf), Error> {
        let hash = self.hash_algorithm();
        let hash_len = hash.output_len();
        let hkdf = self.hkdf();

        // Derive-Secret(handshake_secret, "derived", "")
        let empty_hash = self.transcript_hash_of(b"");
        let mut derived = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            handshake_secret,
            b"derived",
            &empty_hash,
            &mut derived,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive 'derived' for master: {}", e)))?;

        // master_secret = HKDF-Extract(derived, 0)
        let zeros = vec![0u8; hash_len];
        let mut master_secret = Buf::new();
        hkdf.hkdf_extract(hash, &derived, &zeros, &mut master_secret)
            .map_err(|e| Error::CryptoError(format!("Failed to derive master secret: {}", e)))?;

        // Get transcript hash up to and including server Finished
        let mut transcript_hash = Buf::new();
        self.transcript_hash(&mut transcript_hash);

        // exporter_master_secret = Derive-Secret(master_secret, "exp master", transcript_hash)
        let mut exp_master = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &master_secret,
            b"exp master",
            &transcript_hash,
            &mut exp_master,
            hash_len,
        )
        .map_err(|e| {
            Error::CryptoError(format!("Failed to derive exporter master secret: {}", e))
        })?;

        // client_application_traffic_secret_0
        let mut c_ap_traffic = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &master_secret,
            b"c ap traffic",
            &transcript_hash,
            &mut c_ap_traffic,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive c_ap_traffic: {}", e)))?;

        // server_application_traffic_secret_0
        let mut s_ap_traffic = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &master_secret,
            b"s ap traffic",
            &transcript_hash,
            &mut s_ap_traffic,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive s_ap_traffic: {}", e)))?;

        // Store exporter master secret (deferred to avoid borrow conflict with hkdf)
        self.exporter_master_secret = Some(exp_master);

        Ok((c_ap_traffic, s_ap_traffic))
    }

    /// Install application keys (epoch 3) from the traffic secrets.
    pub fn install_application_keys(
        &mut self,
        client_traffic_secret: &Buf,
        server_traffic_secret: &Buf,
    ) -> Result<(), Error> {
        let (send_secret, recv_secret) = if self.is_client {
            (client_traffic_secret, server_traffic_secret)
        } else {
            (server_traffic_secret, client_traffic_secret)
        };

        self.app_send_keys = Some(self.derive_epoch_keys(send_secret)?);

        let recv_keys = self.derive_epoch_keys(recv_secret)?;
        self.app_recv_keys.push(RecvEpochEntry {
            epoch: 3,
            keys: recv_keys,
            expected_recv_seq: 0,
        });

        self.app_send_epoch = 3;
        self.app_send_seq = 0;

        Ok(())
    }

    /// Install send handshake keys for client flight (after receiving server Finished).
    pub fn install_send_handshake_keys(
        &mut self,
        client_traffic_secret: &Buf,
    ) -> Result<(), Error> {
        self.hs_send_keys = Some(self.derive_epoch_keys(client_traffic_secret)?);
        self.hs_send_seq = 0;
        Ok(())
    }

    /// Reset handshake state for a new ClientHello after HelloRetryRequest.
    pub fn reset_for_hello_retry(&mut self) {
        self.peer_handshake_seq_no = 0;
        self.next_handshake_seq_no = 0;
        self.hs_send_seq = 0;
    }

    /// Derive epoch keys (cipher + IV + sn_key) from a traffic secret.
    fn derive_epoch_keys(&self, traffic_secret: &Buf) -> Result<EpochKeys, Error> {
        let hash = self.hash_algorithm();
        let suite = self.suite_provider();
        let hkdf = self.hkdf();

        // key = HKDF-Expand-Label(secret, "key", "", key_length)
        let mut key = Buf::new();
        hkdf.hkdf_expand_label_dtls13(hash, traffic_secret, b"key", &[], &mut key, suite.key_len())
            .map_err(|e| Error::CryptoError(format!("Failed to derive key: {}", e)))?;

        // iv = HKDF-Expand-Label(secret, "iv", "", iv_length)
        let mut iv_buf = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            traffic_secret,
            b"iv",
            &[],
            &mut iv_buf,
            suite.iv_len(),
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive iv: {}", e)))?;

        // sn_key = HKDF-Expand-Label(secret, "sn", "", key_length)
        let mut sn_key = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            traffic_secret,
            b"sn",
            &[],
            &mut sn_key,
            suite.key_len(),
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive sn_key: {}", e)))?;

        let cipher = suite
            .create_cipher(&key)
            .map_err(|e| Error::CryptoError(format!("Failed to create cipher: {}", e)))?;

        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_buf);

        let mut secret = Buf::new();
        secret.extend_from_slice(traffic_secret);

        Ok(EpochKeys {
            cipher,
            iv,
            traffic_secret: secret,
            sn_key,
        })
    }

    /// Compute the handshake secret needed for derive_application_secrets.
    ///
    /// This re-derives the handshake secret from the shared secret and early secret.
    /// Call after handshake secrets have been derived and the shared secret is still available.
    pub fn derive_handshake_secret(&self, shared_secret: &[u8]) -> Result<Buf, Error> {
        let hash = self.hash_algorithm();
        let hash_len = hash.output_len();
        let hkdf = self.hkdf();

        let early_secret = self.derive_early_secret()?;
        let empty_hash = self.transcript_hash_of(b"");
        let mut derived = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &early_secret,
            b"derived",
            &empty_hash,
            &mut derived,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive 'derived' secret: {}", e)))?;

        let mut handshake_secret = Buf::new();
        hkdf.hkdf_extract(hash, &derived, shared_secret, &mut handshake_secret)
            .map_err(|e| Error::CryptoError(format!("Failed to derive handshake secret: {}", e)))?;

        Ok(handshake_secret)
    }

    /// Compute verify_data for Finished messages.
    ///
    /// finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.len)
    /// verify_data = HMAC(finished_key, transcript_hash) = HKDF-Extract(finished_key, transcript_hash)
    pub fn compute_verify_data(&self, traffic_secret: &[u8]) -> Result<Buf, Error> {
        let hash = self.hash_algorithm();
        let hash_len = hash.output_len();
        let hkdf = self.hkdf();

        // finished_key = HKDF-Expand-Label(secret, "finished", "", Hash.len)
        let mut finished_key = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            traffic_secret,
            b"finished",
            &[],
            &mut finished_key,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive finished key: {}", e)))?;

        // verify_data = HMAC(finished_key, transcript_hash)
        // HMAC = HKDF-Extract with salt=finished_key, IKM=transcript_hash
        let mut transcript_hash = Buf::new();
        self.transcript_hash(&mut transcript_hash);

        let mut verify_data = Buf::new();
        hkdf.hkdf_extract(hash, &finished_key, &transcript_hash, &mut verify_data)
            .map_err(|e| Error::CryptoError(format!("Failed to compute verify data: {}", e)))?;

        Ok(verify_data)
    }

    // =========================================================================
    // Transcript Management
    // =========================================================================

    pub fn transcript_hash(&self, out: &mut Buf) {
        let hash = self.hash_algorithm();
        let mut ctx = self
            .config
            .crypto_provider()
            .hash_provider
            .create_hash(hash);
        ctx.update(&self.transcript);
        ctx.clone_and_finalize(out);
    }

    /// Compute transcript hash of arbitrary data (e.g. empty for "derived" label).
    fn transcript_hash_of(&self, data: &[u8]) -> Buf {
        let hash = self.hash_algorithm();
        let mut ctx = self
            .config
            .crypto_provider()
            .hash_provider
            .create_hash(hash);
        ctx.update(data);
        let mut out = Buf::new();
        ctx.clone_and_finalize(&mut out);
        out
    }

    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    /// Replace transcript with message_hash for HelloRetryRequest.
    ///
    /// Per RFC 8446 Section 4.4.1: Hash replaces transcript with
    /// message_hash = 0xFE || 00 00 Hash.length || Hash(CH1)
    pub fn replace_transcript_with_message_hash(&mut self) {
        let hash = self.hash_algorithm();
        let mut hash_ctx = self
            .config
            .crypto_provider()
            .hash_provider
            .create_hash(hash);
        hash_ctx.update(&self.transcript);
        let mut hash_value = Buf::new();
        hash_ctx.clone_and_finalize(&mut hash_value);

        self.transcript.clear();
        // message_hash construct: msg_type=0xFE, length=hash_len
        self.transcript.push(0xFE);
        let hash_len = hash_value.len() as u32;
        self.transcript
            .extend_from_slice(&hash_len.to_be_bytes()[1..]);
        self.transcript.extend_from_slice(&hash_value);
    }

    // =========================================================================
    // Peer Encryption Management
    // =========================================================================

    pub fn enable_peer_encryption(&mut self) -> Result<(), Error> {
        debug!("Peer encryption enabled");
        self.peer_encryption_enabled = true;

        // Re-parse any buffered epoch 2+ records
        let maybe_index = self
            .queue_rx
            .iter()
            .position(|i| i.records().iter().any(|r| r.record().sequence.epoch >= 2));

        let Some(index) = maybe_index else {
            return Ok(());
        };

        let all = self.queue_rx.split_off(index);

        for incoming in all {
            let unhandled = incoming.into_records().filter(|r| !r.is_handled());

            for record in unhandled {
                let buf = record.into_buffer();
                self.parse_packet(&buf)?;
                self.buffers_free.push(buf);
            }
        }

        Ok(())
    }

    // =========================================================================
    // Key Exchange Helpers
    // =========================================================================

    pub fn find_kx_group(
        &self,
        group: crate::types::NamedGroup,
    ) -> Option<&'static dyn SupportedKxGroup> {
        self.config
            .crypto_provider()
            .kx_groups
            .iter()
            .find(|g| g.name() == group)
            .copied()
    }

    // =========================================================================
    // Signature Verification
    // =========================================================================

    pub fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash_alg: HashAlgorithm,
        sig_alg: crate::types::SignatureAlgorithm,
    ) -> Result<(), Error> {
        self.config
            .crypto_provider()
            .signature_verification
            .verify_signature(cert_der, data, signature, hash_alg, sig_alg)
            .map_err(|e| Error::CryptoError(format!("Signature verification failed: {}", e)))
    }

    // =========================================================================
    // Extract SRTP Keying Material
    // =========================================================================

    pub fn extract_srtp_keying_material(
        &self,
        profile: crate::crypto::SrtpProfile,
    ) -> Result<(ArrayVec<u8, 88>, crate::crypto::SrtpProfile), Error> {
        let hash = self.hash_algorithm();
        let hash_len = hash.output_len();
        let hkdf = self.hkdf();

        let exp_master = self.exporter_master_secret.as_ref().ok_or_else(|| {
            Error::CryptoError("Exporter master secret not yet derived".to_string())
        })?;

        let total_len = profile.keying_material_len();

        // RFC 8446 Section 7.5:
        // 1. derived_secret = Derive-Secret(exporter_master_secret, label, "")
        let empty_hash = self.transcript_hash_of(b"");
        let mut derived = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            exp_master,
            b"EXTRACTOR-dtls_srtp",
            &empty_hash,
            &mut derived,
            hash_len,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to derive SRTP exporter secret: {}", e)))?;

        // 2. result = HKDF-Expand-Label(derived_secret, "exporter", Hash(context), length)
        let context_hash = self.transcript_hash_of(b"");
        let mut keying_material_buf = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &derived,
            b"exporter",
            &context_hash,
            &mut keying_material_buf,
            total_len,
        )
        .map_err(|e| {
            Error::CryptoError(format!("Failed to extract SRTP keying material: {}", e))
        })?;

        let mut keying_material = ArrayVec::new();
        for &b in keying_material_buf.iter().take(total_len) {
            keying_material.push(b);
        }

        Ok((keying_material, profile))
    }

    /// Internal buffer pop that doesn't require &mut self (used in const-like contexts)
    fn pop_buffer_internal(&self) -> Buf {
        Buf::new()
    }
}

// =========================================================================
// Helper Functions
// =========================================================================

/// Determine the epoch for a handshake message type.
///
/// In DTLS 1.3, ClientHello and ServerHello are sent as plaintext (epoch 0).
/// All other handshake messages are encrypted (epoch 2).
fn epoch_for_message(msg_type: MessageType) -> u16 {
    match msg_type {
        MessageType::ClientHello | MessageType::ServerHello => 0,
        _ => 2,
    }
}

/// Reconstruct a full sequence number from a partial value (RFC 9147 Section 4.2.2).
///
/// Uses a sliding window centered on the expected sequence to find the full
/// 48-bit sequence that is closest to `expected`.
fn reconstruct_sequence(partial: u64, expected: u64, bits: u32) -> u64 {
    let mask = (1u64 << bits) - 1;
    let window = 1u64 << bits;
    let half = window / 2;

    let received_partial = partial & mask;
    let expected_partial = expected & mask;

    let diff = (received_partial as i64) - (expected_partial as i64);
    let diff = if diff > half as i64 {
        diff - window as i64
    } else if diff < -(half as i64) {
        diff + window as i64
    } else {
        diff
    };

    // Clamp to 0 to avoid underflow for very early sequence numbers
    (expected as i64 + diff).max(0) as u64
}

// =========================================================================
// RecordDecrypt Implementation
// =========================================================================

impl RecordDecrypt for Engine {
    fn is_peer_encryption_enabled(&self) -> bool {
        self.peer_encryption_enabled
    }

    fn resolve_epoch(&self, epoch_bits: u8) -> u16 {
        // Map 2-bit epoch field to full epoch.
        // In practice during handshake, epoch_bits=2 maps to epoch 2.
        // After KeyUpdate, epoch_bits cycles: 3→0→1→2→3→...
        let epoch_bits = epoch_bits as u16;

        // Check handshake epoch first
        if self.hs_recv_keys.is_some() && (2 & 0x03) == epoch_bits {
            return 2;
        }

        // Check application recv epochs
        for entry in &self.app_recv_keys {
            if (entry.epoch & 0x03) == epoch_bits {
                return entry.epoch;
            }
        }

        // Default to the epoch bits value
        epoch_bits
    }

    fn resolve_sequence(&self, epoch: u16, seq_bits: u64, s_flag: bool) -> u64 {
        let expected = if epoch == 2 {
            self.hs_expected_recv_seq
        } else {
            self.app_recv_keys
                .iter()
                .find(|e| e.epoch == epoch)
                .map(|e| e.expected_recv_seq)
                .unwrap_or(0)
        };

        let bits: u32 = if s_flag { 16 } else { 8 };
        reconstruct_sequence(seq_bits, expected, bits)
    }

    fn replay_check_and_update(&mut self, seq: Sequence) -> bool {
        if !self.replay.check_and_update(seq) {
            return false;
        }

        // Advance expected receive sequence for this epoch
        let next = seq.sequence_number + 1;
        if seq.epoch == 2 {
            if next > self.hs_expected_recv_seq {
                self.hs_expected_recv_seq = next;
            }
        } else {
            for entry in &mut self.app_recv_keys {
                if entry.epoch == seq.epoch {
                    if next > entry.expected_recv_seq {
                        entry.expected_recv_seq = next;
                    }
                    break;
                }
            }
        }

        true
    }

    fn decrypt_record(
        &mut self,
        header: &[u8],
        seq: Sequence,
        ciphertext: &mut TmpBuf,
    ) -> Result<(), Error> {
        // Find the right keys based on epoch
        let keys = if seq.epoch == 2 {
            self.hs_recv_keys.as_mut()
        } else {
            // Look up in app recv keys
            self.app_recv_keys
                .iter_mut()
                .find(|e| e.epoch == seq.epoch)
                .map(|e| &mut e.keys)
        };

        let Some(keys) = keys else {
            return Err(Error::CryptoError(format!(
                "No recv keys for epoch {}",
                seq.epoch
            )));
        };

        // Construct nonce: iv XOR padded_seq
        let nonce = Nonce::xor(&keys.iv, seq.sequence_number);

        // AAD is the raw header bytes
        let aad = Aad::new_dtls13(header);

        keys.cipher
            .decrypt(ciphertext, aad, nonce)
            .map_err(|e| Error::CryptoError(format!("Decryption failed: {}", e)))?;

        Ok(())
    }

    fn decrypt_sequence_number(
        &self,
        epoch: u16,
        seq_bytes: &mut [u8],
        ciphertext_sample: &[u8; 16],
    ) {
        // Find the sn_key for this epoch
        let sn_key = if epoch == 2 {
            self.hs_recv_keys.as_ref().map(|k| &k.sn_key)
        } else {
            self.app_recv_keys
                .iter()
                .find(|e| e.epoch == epoch)
                .map(|e| &e.keys.sn_key)
        };

        let Some(sn_key) = sn_key else {
            return; // No keys yet, leave seq bytes as-is
        };

        let mask = self.suite_provider().encrypt_sn(sn_key, ciphertext_sample);
        for (i, byte) in seq_bytes.iter_mut().enumerate() {
            *byte ^= mask[i];
        }
    }
}
