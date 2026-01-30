use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::queue::{QueueRx, QueueTx};
use crate::buffer::{Buf, BufferPool, TmpBuf};
use crate::crypto::{Aad, Iv, Nonce, DTLS_AEAD_OVERHEAD, DTLS_EXPLICIT_NONCE_LEN};
use crate::dtls12::context::CryptoContext;
use crate::dtls12::incoming::{Incoming, Record};
use crate::dtls12::message::{Body, HashAlgorithm, Header, MessageType, ProtocolVersion, Sequence};
use crate::dtls12::message::{ContentType, DTLSRecord, Dtls12CipherSuite, Handshake};
use crate::timer::ExponentialBackoff;
use crate::window::ReplayWindow;
use crate::{Config, Error, Output, SeededRng};

const MAX_DEFRAGMENT_PACKETS: usize = 50;

// Using debug_ignore_primary since CryptoContext doesn't implement Debug
pub struct Engine {
    config: Arc<Config>,

    /// Seedable random number generator for deterministic testing
    pub(crate) rng: SeededRng,

    /// Pool of buffers
    buffers_free: BufferPool,

    /// Counters for sending DTLSRecord during epoch 0.
    ///
    /// This is kept separate since resends might force us to
    /// "go back" to these sequence number even if we technically
    /// progressed to epoch 1.
    sequence_epoch_0: Sequence,

    /// Counters for epoch 1 and beyond.
    sequence_epoch_n: Sequence,

    /// Queue of incoming packets.
    queue_rx: QueueRx,

    /// Queue of outgoing packets.
    queue_tx: QueueTx,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<Dtls12CipherSuite>,

    /// Cryptographic context for handling encryption/decryption
    pub(crate) crypto_context: CryptoContext,

    /// Whether the remote peer has enabled encryption
    peer_encryption_enabled: bool,

    /// Whether this engine is for a client (true) or server (false)
    is_client: bool,

    /// Expected peer handshake sequence number
    peer_handshake_seq_no: u16,

    /// Next handshake message sequence number for sending
    next_handshake_seq_no: u16,

    /// Handshakes collected for hash computation.
    ///
    /// NB: pub(crate) because we need to sign it in client.rs
    pub(crate) transcript: Buf,

    /// Anti-replay window state (per current epoch)
    replay: ReplayWindow,

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
    fragment: Buf,
}

impl Engine {
    pub fn new(config: Arc<Config>, certificate: crate::DtlsCertificate) -> Self {
        let mut rng = SeededRng::new(config.rng_seed());

        let flight_backoff =
            ExponentialBackoff::new(config.flight_start_rto(), config.flight_retries(), &mut rng);

        let crypto_context = CryptoContext::new(
            certificate.certificate,
            certificate.private_key,
            Arc::clone(&config),
        );

        Self {
            config,
            rng,
            buffers_free: BufferPool::default(),
            sequence_epoch_0: Sequence::new(0),
            sequence_epoch_n: Sequence::new(1),
            queue_rx: QueueRx::new(),
            queue_tx: QueueTx::new(),
            cipher_suite: None,
            crypto_context,
            peer_encryption_enabled: false,
            is_client: false,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            transcript: Buf::new(),
            replay: ReplayWindow::new(),
            flight_saved_records: Vec::new(),
            flight_backoff,
            flight_timeout: Timeout::Unarmed,
            connect_timeout: Timeout::Unarmed,
            release_app_data: false,
        }
    }

    pub fn set_client(&mut self, is_client: bool) {
        self.is_client = is_client;
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the cipher suite
    pub fn cipher_suite(&self) -> Option<Dtls12CipherSuite> {
        self.cipher_suite
    }

    /// Is the given cipher suite allowed by configuration
    pub fn is_cipher_suite_allowed(&self, suite: Dtls12CipherSuite) -> bool {
        self.crypto_context
            .provider()
            .supported_cipher_suites()
            .any(|cs| cs.suite() == suite)
    }

    /// Get a reference to the crypto context
    pub fn crypto_context(&self) -> &CryptoContext {
        &self.crypto_context
    }

    /// Get a mutable reference to the crypto context
    pub fn crypto_context_mut(&mut self) -> &mut CryptoContext {
        &mut self.crypto_context
    }

    pub fn parse_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let incoming = Incoming::parse_packet(packet, self)?;
        if let Some(incoming) = incoming {
            self.insert_incoming(incoming)?;
        }

        Ok(())
    }

    /// Insert the Incoming using the logic:
    ///
    /// 1. If it is a handshake, sort by the message_seq
    /// 2. If it is not a handshake, sort by sequence_number
    ///
    fn insert_incoming(&mut self, incoming: Incoming) -> Result<(), Error> {
        // Capacity guard
        if self.queue_rx.len() >= self.config.max_queue_rx() {
            warn!(
                "Receive queue full (max {}): {:?}",
                self.config.max_queue_rx(),
                self.queue_rx
            );
            return Err(Error::ReceiveQueueFull);
        }

        // Dispatch to specialized handlers
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

        // Some MessageType when resent, means we must trigger
        // an immediate resend of the entire flight.
        if let Some(dupe_seq) = maybe_dupe_seq {
            if dupe_seq < self.peer_handshake_seq_no {
                self.flight_resend("dupe triggers resend")?;
            }
        }

        // Drop old duplicates we've already processed - don't let them block newer messages.
        if handshake.header.message_seq < self.peer_handshake_seq_no {
            return Ok(());
        }

        // Reject new handshakes after initial handshake is complete (renegotiation not supported).
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
                // Insert in order of handshake key
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
                // For epoch 0, we can get duplicates due to resends.
                // For epoch 1, we have the replay window and there should
                // be no duplicates.
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

        // The connect timeout is the overall timeout for establishing the connection
        if let Timeout::Armed(connect_timeout) = self.connect_timeout {
            if now >= connect_timeout {
                return Err(Error::Timeout("connect"));
            }
        }

        // If there is no flight timeout, we have already checked the global connect timeout.
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
        // Drain incoming queue of processed records.
        self.purge_handled_queue_rx();

        // First check if we have any decrypted app data.
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
        // No timeouts, return a distant future
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
        // For lifetime issues, we take the entries out of self
        let records = mem::take(&mut self.flight_saved_records);

        for entry in &records {
            self.create_record(entry.content_type, entry.epoch, false, |fragment| {
                fragment.extend_from_slice(&entry.fragment);
            })?;
        }

        // Put the entries back into self
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
            // Cap to MAX_DEFRAGMENT_PACKETS to avoid misbehaving peers
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
            // A different seq means we're looking at a different handshake
            if wanted_seq != h.header.message_seq {
                continue;
            }

            // Check fragment contiguity
            if h.header.fragment_offset != last_fragment_end {
                return false;
            }
            last_fragment_end = h.header.fragment_offset + h.header.fragment_length;

            // Found the last fragment to complete the wanted handshake.
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

        // This sets the handled flag on the handshake.
        // Passing Some(&mut self.transcript) to have defragment write to transcript
        // before creating the handshake, avoiding borrow conflicts.
        let handshake = Handshake::defragment(
            iter,
            defragment_buffer,
            self.cipher_suite,
            Some(&mut self.transcript),
        )?;

        // Move the expected seq_no along
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

    /// Mark any pending ChangeCipherSpec records as handled and purge them.
    /// We can accumulate multiple ChangeCipherSpec due to resends. Since they
    /// don't have any Handshake message_seq and each resend gives a new DTLSRecord
    /// sequence number, we might have multiple.
    pub fn drop_pending_ccs(&mut self) {
        for incoming in self.queue_rx.iter() {
            for record in incoming.records().iter() {
                if record.record().content_type == ContentType::ChangeCipherSpec {
                    record.set_handled();
                }
            }
        }
    }

    /// Create a DTLS record and serialize it into a buffer
    pub fn create_record<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        // Prepare the plaintext fragment
        let mut fragment = self.buffers_free.pop();

        // Let the caller fill the fragment (plaintext)
        f(&mut fragment);

        // Use this as a marker to know whether we are to record fragments for resends.
        if save_fragment {
            let mut clone = self.buffers_free.pop();
            clone.extend_from_slice(&fragment);
            self.flight_saved_records.push(Entry {
                content_type,
                epoch,
                fragment: clone,
            });
        }

        // Compute wire length of the record if serialized into a datagram
        // Record header (13) + handshake/change/app data bytes + AEAD overhead (if epoch >= 1)
        let overhead = if epoch >= 1 { DTLS_AEAD_OVERHEAD } else { 0 };
        let record_wire_len = DTLSRecord::HEADER_LEN + fragment.len() + overhead;

        // Decide whether to append to the existing last datagram or create a new one
        let can_append = self
            .queue_tx
            .back()
            .map(|b| b.len() + record_wire_len <= self.config.mtu())
            .unwrap_or(false);

        // If we cannot append, ensure we have space for a new datagram
        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx() {
            warn!(
                "Transmit queue full (max {}): {:?}",
                self.config.max_queue_tx(),
                self.queue_tx
            );
            return Err(Error::TransmitQueueFull);
        }

        // Sequence number to use for this record
        let sequence = if epoch == 0 {
            self.sequence_epoch_0
        } else {
            self.sequence_epoch_n
        };
        let length = fragment.len() as u16;

        // Handle encryption for epochs >= 1
        if epoch >= 1 {
            // Get the fixed part of the IV (4 bytes)
            let iv = if self.is_client {
                self.crypto_context.get_client_write_iv()
            } else {
                self.crypto_context.get_server_write_iv()
            };

            let Some(iv) = iv else {
                return Err(Error::CryptoError(format!(
                    "{} write IV not available",
                    if self.is_client { "Client" } else { "Server" }
                )));
            };

            // Generate 8 random bytes for the explicit part of the nonce
            let explicit_nonce: [u8; 8] = self.rng.random();

            // Combine the fixed IV and the explicit nonce
            let nonce = Nonce::new(iv, &explicit_nonce);

            // DTLS 1.2 AEAD (AES-GCM): AAD uses the plaintext length (DTLSCompressed.length).
            // See RFC 5246/5288 and RFC 6347. The record fragment on the wire will be:
            // 8-byte explicit nonce || ciphertext(plaintext) || 16-byte GCM tag.
            let aad = Aad::new(content_type, sequence, length);

            // Encrypt the fragment in-place
            self.encrypt_data(&mut fragment, aad, nonce)?;
            let ctext_len = fragment.len();

            // Increase the size to make space for the explicit nonce.
            fragment.resize(DTLS_EXPLICIT_NONCE_LEN + ctext_len, 0);

            // Shift the encrypted data to make space for the nonce and write it
            fragment.copy_within(0..ctext_len, DTLS_EXPLICIT_NONCE_LEN);
            fragment[..DTLS_EXPLICIT_NONCE_LEN].copy_from_slice(&explicit_nonce);
        }

        // Build the record structure referencing the (possibly encrypted) fragment
        let record = DTLSRecord {
            content_type,
            version: ProtocolVersion::DTLS1_2,
            sequence,
            length: fragment.len() as u16,
            fragment_range: 0..fragment.len(),
        };

        // Increment the sequence number for the next transmission
        if epoch == 0 {
            self.sequence_epoch_0.sequence_number += 1;
        } else {
            self.sequence_epoch_n.sequence_number += 1;
        }

        // Serialize the record into the chosen datagram buffer
        if can_append {
            let last = self.queue_tx.back_mut().unwrap();
            record.serialize(&fragment, last);
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            record.serialize(&fragment, &mut buffer);
            self.queue_tx.push_back(buffer);
        }

        // Return the fragment buffer to the pool
        self.buffers_free.push(fragment);

        Ok(())
    }

    /// Create a handshake message and wrap it in a DTLS record
    pub fn create_handshake<F>(&mut self, msg_type: MessageType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf, &mut Self) -> Result<(), Error>,
    {
        // Get a buffer for the handshake body
        let mut body_buffer = self.buffers_free.pop();

        // Let the callback fill the handshake body
        f(&mut body_buffer, self)?;

        // Create the handshake header with the next sequence number
        let handshake_header = Header {
            msg_type,
            length: body_buffer.len() as u32,
            message_seq: self.next_handshake_seq_no,
            fragment_offset: 0,
            fragment_length: body_buffer.len() as u32,
        };

        let mut buffer_full = self.buffers_free.pop();
        {
            let handshake = Handshake {
                header: handshake_header,
                body: Body::Fragment(0..body_buffer.len()),
                handled: AtomicBool::new(false),
            };
            // Serialize with body_buffer as source
            handshake.serialize(&body_buffer, &mut buffer_full);
        }
        self.transcript.extend_from_slice(&buffer_full);
        self.buffers_free.push(buffer_full);

        // Increment the sequence number for the next handshake message
        self.next_handshake_seq_no += 1;

        // We want to pack as much as possible into the outgoing datagram and
        // remain within the MTU. Fragment the handshake across records as needed.

        let epoch = msg_type.epoch();
        let total_len = body_buffer.len();
        let mut offset: usize = 0;

        // Handshake header is 12 bytes
        let handshake_header_len = 12usize;
        let aead_overhead = if epoch >= 1 { DTLS_AEAD_OVERHEAD } else { 0 };

        // At least one record must be created even if total_len == 0
        while offset < total_len || (total_len == 0 && offset == 0) {
            // How many bytes are already used in the current datagram (if any)?
            let already_used_in_current = self.queue_tx.back().map(|b| b.len()).unwrap_or(0);
            let available_in_current = self.config.mtu().saturating_sub(already_used_in_current);

            // Fixed overhead per handshake record on the wire:
            // DTLS record header + handshake header + AEAD overhead (if epoch >= 1)
            let fixed_overhead = DTLSRecord::HEADER_LEN + handshake_header_len + aead_overhead;

            // Prefer to pack into the current datagram. If the current one cannot fit even
            // the fixed overhead, we will start a fresh datagram and compute space again.
            let available_for_body = if available_in_current > fixed_overhead {
                // There is room for at least 1 byte of handshake body in the current datagram
                available_in_current - fixed_overhead
            } else {
                // Not enough space in the current datagram for any body bytes; start a fresh datagram
                self.config.mtu().saturating_sub(fixed_overhead)
            };

            // Remaining bytes from the handshake body we still need to send.
            let remaining_body_bytes = total_len.saturating_sub(offset);

            // For empty-body handshakes (e.g., ServerHelloDone), we still send a header-only record.
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

            // Emit the record; packing into current datagram happens inside create_record
            self.create_record(ContentType::Handshake, epoch, true, |fragment| {
                // Serialize with body_buffer as source
                frag_handshake.serialize(&body_buffer, fragment);
            })?;

            if total_len == 0 {
                // Nothing more to send for empty-body handshake
                break;
            }

            offset += chunk_len;
        }

        // Return the buffer
        self.buffers_free.push(body_buffer);

        Ok(())
    }

    /// Release application data from the incoming queue
    pub fn release_application_data(&mut self) {
        self.release_app_data = true;
    }

    /// Pop a buffer from the buffer pool for temporary use
    pub(crate) fn pop_buffer(&mut self) -> Buf {
        self.buffers_free.pop()
    }

    /// Return a buffer to the buffer pool
    pub(crate) fn push_buffer(&mut self, buf: Buf) {
        self.buffers_free.push(buf);
    }

    /// Encrypt data appropriate for the role (client or server)
    fn encrypt_data(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), Error> {
        if self.is_client {
            self.crypto_context
                .encrypt_client_to_server(plaintext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Client encryption failed: {}", e)))
        } else {
            self.crypto_context
                .encrypt_server_to_client(plaintext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Server encryption failed: {}", e)))
        }
    }

    /// Decrypt data appropriate for the role (client or server)
    pub fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error> {
        if self.is_client {
            self.crypto_context
                .decrypt_server_to_client(ciphertext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Client decryption failed: {}", e)))
        } else {
            self.crypto_context
                .decrypt_client_to_server(ciphertext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Server decryption failed: {}", e)))
        }
    }

    /// Anti-replay check and update state. Returns true if record is fresh/acceptable.
    pub fn replay_check_and_update(&mut self, seq: Sequence) -> bool {
        self.replay.check_and_update(seq)
    }

    /// Reset server handshake state after sending HelloVerifyRequest.
    ///
    /// Per RFC 6347 §4.2.2, the HelloVerifyRequest exchange is stateless. After sending
    /// HVR, the server expects a fresh ClientHello containing the cookie with message_seq=1.
    ///
    /// The message flow per RFC 6347 §4.2.2:
    ///   ClientHello (seq=0)  ------>
    ///                    <------  HelloVerifyRequest (seq=0)
    ///   ClientHello (seq=1)  ------>  (with cookie)
    ///                    <------  ServerHello (seq=1)
    pub fn reset_server_for_hello_verify_request(&mut self) {
        self.transcript.clear();
        // Per RFC 6347 §4.2.2, the next ClientHello (with cookie) has message_seq=1.
        // We keep peer_handshake_seq_no at 1 (already incremented after first ClientHello).
        // Clear queued incoming handshakes so the next ClientHello (with cookie)
        // isn't rejected as a duplicate of the first ClientHello (without cookie).
        self.queue_rx.clear();
        // Note: Don't clear flight_saved_records here - the HelloVerifyRequest should
        // still be resendable via timeout until we receive the valid ClientHello with cookie.
        // The flight_begin(4) call when processing the cookie-bearing ClientHello will
        // clear the old records.
    }

    /// Reset client handshake state after receiving HelloVerifyRequest.
    ///
    /// Per RFC 6347 §4.2.2, the client sends the next ClientHello (with cookie) using
    /// message_seq=1. The transcript is cleared because the initial ClientHello and
    /// HelloVerifyRequest are not part of the handshake transcript per RFC 6347 §4.2.1.
    ///
    /// Note: next_handshake_seq_no is already 1 after sending the first ClientHello,
    /// so we don't reset it - the next ClientHello will correctly have message_seq=1.
    pub fn reset_client_for_hello_verify_request(&mut self) {
        self.transcript.clear();
        // Note: next_handshake_seq_no stays at 1 - the next ClientHello (with cookie)
        // will have message_seq=1 per RFC 6347 §4.2.2.
        // Note: peer_handshake_seq_no stays at 1 - the next message from server
        // (ServerHello) will have message_seq=1 per RFC 6347 §4.2.2.
    }

    pub fn transcript_hash(&self, algorithm: HashAlgorithm, out: &mut Buf) {
        let mut hash = self.crypto_context.create_hash(algorithm);
        hash.update(&self.transcript);
        hash.clone_and_finalize(out);
    }

    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: Dtls12CipherSuite) {
        self.cipher_suite = Some(cipher_suite);
    }

    pub fn enable_peer_encryption(&mut self) -> Result<(), Error> {
        debug!("Peer encryption enabled");
        self.peer_encryption_enabled = true;

        let maybe_index_epoch1 = self
            .queue_rx
            .iter()
            .position(|i| i.records().iter().any(|r| r.record().sequence.epoch == 1));

        let Some(index_epoch1) = maybe_index_epoch1 else {
            return Ok(());
        };

        // Now decrypt all entries remaining.
        let all = self.queue_rx.split_off(index_epoch1);

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

    pub fn is_peer_encryption_enabled(&self) -> bool {
        self.peer_encryption_enabled
    }

    fn peer_iv(&self) -> Iv {
        if self.is_client {
            self.crypto_context
                .get_server_write_iv()
                .expect("Server write IV not available - keys not derived yet")
        } else {
            self.crypto_context
                .get_client_write_iv()
                .expect("Client write IV not available - keys not derived yet")
        }
    }

    pub fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord, buf: &[u8]) -> (Aad, Nonce) {
        // DTLS 1.2 AEAD (AES-GCM): AAD uses the plaintext length. The fragment on the wire is
        // 8-byte explicit nonce || ciphertext || 16-byte GCM tag. Recover plaintext length from
        // the record header's fragment length field.
        let plaintext_len = dtls.length.saturating_sub(DTLS_AEAD_OVERHEAD as u16);
        let aad = Aad::new(dtls.content_type, dtls.sequence, plaintext_len);
        let iv = self.peer_iv();
        let nonce = Nonce::new(iv, dtls.nonce(buf));
        (aad, nonce)
    }

    pub fn generate_verify_data(&mut self, is_client: bool) -> Result<[u8; 12], Error> {
        let Some(suite) = self.cipher_suite() else {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            ));
        };
        let algorithm = suite.hash_algorithm();
        let mut handshake_hash = self.buffers_free.pop();
        self.transcript_hash(algorithm, &mut handshake_hash);

        let suite_hash = suite.hash_algorithm();
        let mut out = self.buffers_free.pop();
        let mut scratch = self.buffers_free.pop();
        let verify_data_vec = self
            .crypto_context()
            .generate_verify_data(
                &handshake_hash,
                is_client,
                suite_hash,
                &mut out,
                &mut scratch,
            )
            .map_err(|e| Error::CryptoError(format!("Failed to generate verify data: {}", e)))?;

        if verify_data_vec.len() != 12 {
            return Err(Error::CryptoError("Invalid verify data length".to_string()));
        }

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&verify_data_vec);

        self.buffers_free.push(handshake_hash);
        self.buffers_free.push(out);
        self.buffers_free.push(scratch);

        Ok(verify_data)
    }
}
