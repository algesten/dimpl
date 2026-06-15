use std::mem;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use super::queue::{QueueRx, QueueTx};
use crate::buffer::{Buf, BufferPool, TmpBuf};
use crate::crypto::{Aad, Iv, Nonce};
use crate::dtls12::context::{AuthMode, CryptoContext};
use crate::dtls12::incoming::{Incoming, Record, RecordHandler};
use crate::dtls12::message::{Body, HashAlgorithm, Header, MessageType, ProtocolVersion, Sequence};
use crate::dtls12::message::{ContentType, DTLSRecord, Dtls12CipherSuite, Handshake};
use crate::error::bounded_error_len;
use crate::timer::ExponentialBackoff;
use crate::window::ReplayWindow;
use crate::{Config, Error, InternalError, Output, SeededRng};

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

    /// Per-record explicit nonce length, cached from the provider suite at
    /// `set_cipher_suite` time. 0 for ChaCha20-Poly1305, 8 for AES-GCM.
    explicit_nonce_len: usize,

    /// Minimum length of a protected record's encrypted fragment, cached from
    /// the provider suite. See
    /// [`crate::crypto::SupportedDtls12CipherSuite::min_protected_fragment_len`].
    /// For AEAD suites this is `explicit_nonce + tag`; used both to reject
    /// short incoming records and to size outgoing record overhead.
    min_protected_fragment_len: usize,

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

    /// Whether we have confirmation that the peer completed the handshake, i.e.
    /// that the peer received our final flight. Once set, a stale plaintext
    /// handshake (which is unauthenticated and replayable after encryption is
    /// enabled) no longer triggers a courtesy flight retransmission.
    ///
    /// This is set from two signals, each meaningful for one role:
    /// - the client stops its resend timer when it completes, which means the
    ///   server received our final flight (the client confirms at completion);
    /// - receiving authenticated application data, which means the peer is past
    ///   its handshake (the server's only proof the client received flight 6).
    peer_handshake_confirmed: bool,

    /// Whether a close_notify alert has been received from the peer.
    close_notify_received: bool,

    /// Whether [`Output::CloseNotify`] has already been emitted.
    close_notify_reported: bool,
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
    pub fn new(config: Arc<Config>, auth: AuthMode) -> Self {
        let mut rng = SeededRng::new(config.rng_seed());

        let flight_backoff =
            ExponentialBackoff::new(config.flight_start_rto(), config.flight_retries(), &mut rng);

        let crypto_context = CryptoContext::new(auth, Arc::clone(&config));

        Self {
            config,
            rng,
            buffers_free: BufferPool::default(),
            sequence_epoch_0: Sequence::new(0),
            sequence_epoch_n: Sequence::new(1),
            queue_rx: QueueRx::new(),
            queue_tx: QueueTx::new(),
            cipher_suite: None,
            explicit_nonce_len: 0,
            min_protected_fragment_len: 0,
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
            peer_handshake_confirmed: false,
            close_notify_received: false,
            close_notify_reported: false,
        }
    }

    pub fn set_client(&mut self, is_client: bool) {
        self.is_client = is_client;
    }

    /// Set the next outgoing handshake message sequence number.
    ///
    /// Used by `Client::new_from_hybrid` to account for the hybrid
    /// ClientHello (message_seq=0) that was already sent outside this engine.
    pub fn set_next_handshake_seq_no(&mut self, seq: u16) {
        self.next_handshake_seq_no = seq;
    }

    /// Advance the epoch-0 record sequence number by one.
    ///
    /// Used by `Client::new_from_hybrid` so subsequent epoch-0 records
    /// don't reuse the sequence number of the hybrid ClientHello record.
    pub fn advance_epoch_0_sequence(&mut self) {
        self.sequence_epoch_0.sequence_number += 1;
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the cipher suite
    pub fn cipher_suite(&self) -> Option<Dtls12CipherSuite> {
        self.cipher_suite
    }

    /// Minimum length of a protected record's encrypted fragment for the
    /// negotiated suite. See
    /// [`crate::crypto::SupportedDtls12CipherSuite::min_protected_fragment_len`].
    pub fn min_protected_fragment_len(&self) -> usize {
        self.min_protected_fragment_len
    }

    /// Is the given cipher suite allowed by configuration
    pub fn is_cipher_suite_allowed(&self, suite: Dtls12CipherSuite) -> bool {
        self.config
            .dtls12_cipher_suites()
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

    pub fn parse_packet(&mut self, packet: &[u8]) -> Result<(), InternalError> {
        let cs = self.cipher_suite;
        let incoming = Incoming::parse_packet(packet, self, cs)?;
        if let Some(incoming) = incoming {
            self.insert_incoming(incoming)?;
        }

        Ok(())
    }

    /// Insert a parsed datagram into the receive queue.
    fn insert_incoming(&mut self, incoming: Incoming) -> Result<(), Error> {
        self.purge_handled_queue_rx();

        // Capacity guard before iterating records.
        if self.queue_rx.len() >= self.config.max_queue_rx() {
            warn!(
                "Receive queue full (max {}): {:?}",
                self.config.max_queue_rx(),
                self.queue_rx
            );
            return Err(Error::ReceiveQueueFull);
        }

        // Dispatch to specialized handlers. A datagram can start with a
        // non-handshake record (for example CCS) and still carry a handshake
        // record later in the same packet.
        if incoming.first().first_handshake().is_some()
            || (!self.release_app_data
                && incoming
                    .records()
                    .iter()
                    .any(|r| !r.handshakes().is_empty()))
        {
            self.insert_incoming_handshake(incoming)
        } else {
            self.insert_incoming_non_handshake(incoming)
        }
    }

    fn insert_incoming_handshake(&mut self, incoming: Incoming) -> Result<(), Error> {
        let maybe_dupe_seq = incoming
            .records()
            .iter()
            .filter_map(|r| r.first_handshake())
            .filter_map(|h| h.dupe_triggers_resend())
            .next();

        // Some MessageType when resent, means we must trigger
        // an immediate resend of the entire flight. Once the peer is confirmed
        // to have completed the handshake, a stale plaintext handshake is just
        // unauthenticated noise (or a replay/amplification attempt) and must not
        // drive a resend.
        if let Some(dupe_seq) = maybe_dupe_seq {
            if dupe_seq < self.peer_handshake_seq_no && !self.peer_handshake_confirmed {
                self.flight_resend("dupe triggers resend")?;
            }
        }

        mark_stale_handshakes(&incoming, self.peer_handshake_seq_no);

        let Some((record, handshake)) =
            first_relevant_handshake(&incoming, self.peer_handshake_seq_no)
        else {
            return Ok(());
        };

        let key_current = (
            handshake.header.message_seq,
            handshake.header.fragment_offset,
        );

        if self.peer_encryption_enabled && record.record().sequence.epoch == 0 {
            // Keep old plaintext handshake records available long enough to
            // trigger flight resends above, but never queue or process them as
            // new messages after peer encryption is enabled.
            return Ok(());
        }

        // Reject new handshakes after initial handshake is complete (renegotiation not supported).
        if self.release_app_data && handshake.header.message_seq >= self.peer_handshake_seq_no {
            return Err(Error::RenegotiationAttempt);
        }

        let search_result = self.queue_rx.binary_search_by(|item| {
            let key_other = first_relevant_handshake(item, self.peer_handshake_seq_no)
                .map(|(_, h)| h)
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

        if self.peer_encryption_enabled
            && seq_current.epoch == 0
            && first.record().content_type == ContentType::Handshake
        {
            return Ok(());
        }

        if self.peer_encryption_enabled {
            for record in incoming.records().iter() {
                if record.record().sequence.epoch == 0
                    && record.record().content_type == ContentType::Handshake
                {
                    if record.handshakes().is_empty() {
                        record.set_handled();
                    } else {
                        for handshake in record.handshakes() {
                            handshake.set_handled();
                        }
                    }
                }
            }
        }

        let search_result = self
            .queue_rx
            .binary_search_by_key(&seq_current, |item| item.first().record().sequence);

        match search_result {
            Err(index) => self.queue_rx.insert(index, incoming),
            Ok(_) => {
                // For epoch 0, we can get duplicates due to resends.
                // For epoch 1, we have the replay window and there should
                // be no duplicates.
                assert_eq!(seq_current.epoch, 0);
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
                return Err(Error::Timeout(crate::TimeoutError::Connect));
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
                return Err(Error::Timeout(crate::TimeoutError::Handshake));
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

        if self.close_notify_received && !self.close_notify_reported {
            self.close_notify_reported = true;
            return Output::CloseNotify;
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
            // Both Unarmed or mixed Unarmed/Disabled: return current time
            // to trigger handle_timeout on the next cycle.
            _ => now,
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

        // The client stops its resend timer only once it has received the
        // server's final flight, which proves the server received the client's
        // final flight — so the peer is confirmed. The server, by contrast,
        // stops its timer right after sending flight 6, before the client has
        // confirmed anything, so it must NOT confirm here (it relies on later
        // authenticated application data instead).
        if self.is_client {
            self.peer_handshake_confirmed = true;
        }
    }

    fn flight_clear_resends(&mut self) {
        for entry in self.flight_saved_records.drain(..) {
            self.buffers_free.push(entry.fragment);
        }
    }

    fn flight_resend(&mut self, reason: &str) -> Result<(), Error> {
        debug!("Resending flight due to {}", reason);

        let replace_pending_handshake_output = !self.release_app_data;

        if replace_pending_handshake_output {
            self.queue_tx.clear();
        }

        // For lifetime issues, we take the entries out of self
        let records = mem::take(&mut self.flight_saved_records);

        let mut result = Ok(());
        for (index, entry) in records.iter().enumerate() {
            result = self.create_record_inner(
                entry.content_type,
                entry.epoch,
                false,
                replace_pending_handshake_output && index == 0,
                |fragment| {
                    fragment.extend_from_slice(&entry.fragment);
                },
            );
            if result.is_err() {
                break;
            }
        }

        // Put the entries back into self
        self.flight_saved_records = records;

        result
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
    ) -> Result<Option<Handshake>, InternalError> {
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

    pub(crate) fn handshake_progress_snapshot(&self) -> HandshakeProgressSnapshot {
        HandshakeProgressSnapshot {
            peer_handshake_seq_no: self.peer_handshake_seq_no,
            transcript_len: self.transcript.len(),
        }
    }

    pub(crate) fn rollback_handshake_progress(&mut self, snapshot: HandshakeProgressSnapshot) {
        self.peer_handshake_seq_no = snapshot.peer_handshake_seq_no;
        self.transcript.resize(snapshot.transcript_len, 0);

        for incoming in self.queue_rx.iter() {
            let reject_incoming = incoming
                .records()
                .iter()
                .flat_map(|r| r.handshakes())
                .any(|h| h.header.message_seq >= snapshot.peer_handshake_seq_no);

            if reject_incoming {
                mark_rejected_handshakes(incoming, snapshot.peer_handshake_seq_no);
            }
        }
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
        self.create_record_inner(content_type, epoch, save_fragment, false, f)
    }

    fn create_record_inner<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        save_fragment: bool,
        force_new_datagram: bool,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        let maybe_suite = if epoch >= 1 {
            Some(self.cipher_suite().ok_or(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ))?)
        } else {
            None
        };

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

        // Compute wire length of the record if serialized into a datagram.
        // Record header (13) + handshake/change/app data bytes + per-suite
        // protection overhead (if epoch >= 1). For AEAD suites the protection
        // overhead equals the min-protected-fragment-len.
        let overhead = if maybe_suite.is_some() {
            self.min_protected_fragment_len()
        } else {
            0
        };
        let record_wire_len = DTLSRecord::HEADER_LEN + fragment.len() + overhead;

        // Decide whether to append to the existing last datagram or create a new one
        let can_append = self
            .queue_tx
            .back()
            .map(|b| !force_new_datagram && b.len() + record_wire_len <= self.config.mtu())
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
            let suite = maybe_suite.expect("cipher suite must be set for encrypted epochs");

            // Get the fixed part of the IV
            let iv = if self.is_client {
                self.crypto_context.get_client_write_iv()
            } else {
                self.crypto_context.get_server_write_iv()
            };

            let Some(iv) = iv else {
                return Err(Error::CryptoError(
                    crate::CryptoError::WriteIvNotAvailable {
                        is_client: self.is_client,
                    },
                ));
            };

            let explicit_nonce_len = self.explicit_nonce_len;
            let mut explicit_nonce = [0u8; DTLSRecord::EXPLICIT_NONCE_LEN];
            let seq64 = ((sequence.epoch as u64) << 48) | sequence.sequence_number;
            let nonce = match explicit_nonce_len {
                0 => Nonce::xor(iv.as_12_bytes(), seq64),
                DTLSRecord::EXPLICIT_NONCE_LEN => {
                    explicit_nonce = self.rng.random();
                    Nonce::new(iv, &explicit_nonce)
                }
                _ => {
                    return Err(Error::CryptoError(
                        crate::CryptoError::UnsupportedDtls12RecordIvLen {
                            len: bounded_error_len(explicit_nonce_len),
                            suite,
                        },
                    ));
                }
            };

            // DTLS 1.2 AEAD: AAD uses the plaintext length (DTLSCompressed.length).
            let aad = Aad::new_dtls12(content_type, sequence, length);

            // Encrypt the fragment in-place
            self.encrypt_data(&mut fragment, aad, nonce)?;
            let ctext_len = fragment.len();

            // For suites with a per-record nonce (e.g. AES-GCM), prefix it on the wire.
            if explicit_nonce_len > 0 {
                fragment.resize(explicit_nonce_len + ctext_len, 0);
                fragment.copy_within(0..ctext_len, explicit_nonce_len);
                fragment[..explicit_nonce_len]
                    .copy_from_slice(&explicit_nonce[..explicit_nonce_len]);
            }
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
        // Per-record protection overhead on the wire (for AEAD suites this is
        // explicit_nonce + tag). Used to size fragments to fit the MTU.
        let protection_overhead = if epoch >= 1 {
            self.cipher_suite().ok_or(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
            ))?;
            self.min_protected_fragment_len()
        } else {
            0
        };

        // At least one record must be created even if total_len == 0
        while offset < total_len || (total_len == 0 && offset == 0) {
            // How many bytes are already used in the current datagram (if any)?
            let already_used_in_current = self.queue_tx.back().map(|b| b.len()).unwrap_or(0);
            let available_in_current = self.config.mtu().saturating_sub(already_used_in_current);

            // Fixed overhead per handshake record on the wire:
            // DTLS record header + handshake header + protection overhead (if epoch >= 1)
            let fixed_overhead =
                DTLSRecord::HEADER_LEN + handshake_header_len + protection_overhead;

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

    /// Whether a close_notify alert has been received from the peer.
    pub fn close_notify_received(&self) -> bool {
        self.close_notify_received
    }

    /// Discard all pending outgoing data.
    ///
    /// RFC 5246 §7.2.1: on receiving close_notify, discard any pending writes.
    pub fn discard_pending_writes(&mut self) {
        self.queue_tx.clear();
    }

    /// Abort the connection: flush all queued output, retransmission state, and
    /// disable timers so that no further packets are emitted.
    pub fn abort(&mut self) {
        self.queue_tx.clear();
        self.flight_saved_records.clear();
        self.flight_timeout = Timeout::Disabled;
        self.connect_timeout = Timeout::Disabled;
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
                .map_err(Error::CryptoError)
        } else {
            self.crypto_context
                .encrypt_server_to_client(plaintext, aad, nonce)
                .map_err(Error::CryptoError)
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
                .map_err(Error::CryptoError)
        } else {
            self.crypto_context
                .decrypt_client_to_server(ciphertext, aad, nonce)
                .map_err(Error::CryptoError)
        }
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
        // Cache AEAD record parameters from the provider suite. The formula
        // (explicit_nonce + tag) lives on the suite trait; Engine just stores
        // the resolved values for hot-path access.
        let provider_suite = self
            .crypto_context
            .provider()
            .cipher_suites
            .iter()
            .find(|cs| cs.suite() == cipher_suite)
            .expect("cipher suite must be in provider");
        self.explicit_nonce_len = provider_suite.explicit_nonce_len();
        self.min_protected_fragment_len = provider_suite.min_protected_fragment_len();
        self.cipher_suite = Some(cipher_suite);
    }

    pub fn enable_peer_encryption(&mut self) -> Result<(), InternalError> {
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
        // DTLS 1.2 AEAD: AAD uses the plaintext length. Recover plaintext length
        // from the record header by subtracting this suite's wire overhead.
        let plaintext_len = dtls
            .length
            .saturating_sub(self.min_protected_fragment_len() as u16);
        let aad = Aad::new_dtls12(dtls.content_type, dtls.sequence, plaintext_len);
        let iv = self.peer_iv();
        let seq64 = ((dtls.sequence.epoch as u64) << 48) | dtls.sequence.sequence_number;
        let nonce = match self.explicit_nonce_len {
            0 => Nonce::xor(iv.as_12_bytes(), seq64),
            DTLSRecord::EXPLICIT_NONCE_LEN => Nonce::new(iv, dtls.nonce(buf)),
            len => Nonce::new(iv, dtls.nonce_with_len(buf, len)),
        };
        (aad, nonce)
    }

    pub fn generate_verify_data(&mut self, is_client: bool) -> Result<[u8; 12], Error> {
        let Some(suite) = self.cipher_suite() else {
            return Err(Error::InvalidState(
                crate::InvalidStateError::NoCipherSuiteSelected,
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
            .map_err(Error::CryptoError)?;

        if verify_data_vec.len() != 12 {
            return Err(Error::CryptoError(
                crate::CryptoError::InvalidVerifyDataLength,
            ));
        }

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&verify_data_vec);

        self.buffers_free.push(handshake_hash);
        self.buffers_free.push(out);
        self.buffers_free.push(scratch);

        Ok(verify_data)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct HandshakeProgressSnapshot {
    peer_handshake_seq_no: u16,
    transcript_len: usize,
}

fn first_relevant_handshake(
    incoming: &Incoming,
    peer_handshake_seq_no: u16,
) -> Option<(&Record, &Handshake)> {
    incoming
        .records()
        .iter()
        .flat_map(|r| r.handshakes().iter().map(move |h| (r, h)))
        .filter(|(_, h)| !h.is_handled())
        .find(|(_, h)| h.header.message_seq >= peer_handshake_seq_no)
}

fn mark_stale_handshakes(incoming: &Incoming, peer_handshake_seq_no: u16) {
    for handshake in incoming
        .records()
        .iter()
        .flat_map(|r| r.handshakes())
        .filter(|h| h.header.message_seq < peer_handshake_seq_no)
    {
        handshake.set_handled();
    }
}

fn mark_rejected_handshakes(incoming: &Incoming, peer_handshake_seq_no: u16) {
    for record in incoming.records().iter() {
        for handshake in record
            .handshakes()
            .iter()
            .filter(|h| h.header.message_seq >= peer_handshake_seq_no)
        {
            handshake.set_handled();
        }
    }
}

impl RecordHandler for Engine {
    fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
        let epoch = record.record().sequence.epoch;

        if record.record().content_type == ContentType::ChangeCipherSpec
            && epoch == 0
            && self.peer_encryption_enabled
        {
            // DTLS 1.2 peers may retransmit their last handshake flight after
            // we have already enabled peer encryption. A late plaintext CCS is
            // no longer actionable; queuing it would leave an unhandled control
            // record in queue_rx and prevent handled app-data records behind it
            // from being purged.
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        if record.record().content_type == ContentType::Handshake
            && epoch == 0
            && self.peer_encryption_enabled
            && record
                .first_handshake()
                .and_then(|handshake| handshake.dupe_triggers_resend())
                .is_none()
        {
            // Stale plaintext handshakes must still be visible to
            // insert_incoming_handshake when they can trigger final-flight
            // retransmission. Other post-encryption epoch-0 handshakes are
            // unauthenticated and no longer actionable.
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        if record.record().content_type == ContentType::Alert {
            if epoch == 0 {
                if self.peer_encryption_enabled {
                    // Post-handshake: epoch 0 alerts are unauthenticated, discard.
                    self.push_buffer(record.into_buffer());
                    return Ok(None);
                }

                let fatal_description = {
                    let fragment = record.record().fragment(record.buffer());
                    (fragment.len() >= 2 && fragment[0] == 2).then(|| fragment[1])
                };
                self.push_buffer(record.into_buffer());

                if let Some(description) = fatal_description {
                    return Err(Error::SecurityError(crate::SecurityError::FatalAlert {
                        description,
                    }));
                }

                return Ok(None);
            }

            if !self.peer_encryption_enabled {
                // Epoch >= 1 before peer encryption is enabled must stay queued
                // for re-parsing after enable_peer_encryption().
                return Ok(Some(record));
            }

            let alert = {
                let fragment = record.record().fragment(record.buffer());
                (fragment.len() >= 2).then(|| (fragment[0], fragment[1]))
            };
            self.push_buffer(record.into_buffer());

            if let Some((level, description)) = alert {
                if description == 0 {
                    self.close_notify_received = true;
                    return Ok(None);
                }

                if level == 2 {
                    return Err(Error::SecurityError(crate::SecurityError::FatalAlert {
                        description,
                    }));
                }
            }

            return Ok(None);
        }

        if self.close_notify_received
            && record.record().content_type == ContentType::ApplicationData
        {
            self.push_buffer(record.into_buffer());
            return Ok(None);
        }

        Ok(Some(record))
    }

    fn is_peer_encryption_enabled(&self) -> bool {
        self.peer_encryption_enabled
    }

    fn replay_check(&self, seq: Sequence) -> bool {
        // Only epoch 1 (encrypted) records reach here; epoch 0 records are
        // returned early by the DTLS 1.2 incoming parser.
        self.replay.check(seq.sequence_number)
    }

    fn replay_update(&mut self, seq: Sequence) {
        self.replay.update(seq.sequence_number);
    }

    fn note_decrypted_record(&mut self, content_type: ContentType) {
        // A decrypted (so authenticated) application-data record proves the peer
        // is past its handshake, which means it received our final flight. Once
        // that's known, a stale plaintext handshake (unauthenticated, replayable)
        // must no longer drive a courtesy flight retransmission. The client
        // confirms separately at its own completion (flight_stop_resend_timers).
        if content_type == ContentType::ApplicationData {
            self.peer_handshake_confirmed = true;
        }
    }

    fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord, buf: &[u8]) -> (Aad, Nonce) {
        Engine::decryption_aad_and_nonce(self, dtls, buf)
    }

    fn explicit_nonce_len(&self) -> usize {
        self.explicit_nonce_len
    }

    fn min_protected_fragment_len(&self) -> usize {
        self.min_protected_fragment_len
    }

    fn decrypt_data(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), Error> {
        Engine::decrypt_data(self, ciphertext, aad, nonce)
    }

    fn can_discard_bad_protected_record(&self) -> bool {
        self.release_app_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PassthroughRecordHandler;

    impl RecordHandler for PassthroughRecordHandler {
        fn classify_record(&mut self, record: Record) -> Result<Option<Record>, Error> {
            Ok(Some(record))
        }

        fn is_peer_encryption_enabled(&self) -> bool {
            true
        }

        fn replay_check(&self, _seq: Sequence) -> bool {
            true
        }

        fn replay_update(&mut self, _seq: Sequence) {}

        fn decryption_aad_and_nonce(&self, _dtls: &DTLSRecord, _buf: &[u8]) -> (Aad, Nonce) {
            (
                Aad::new_dtls12(ContentType::Handshake, Sequence::new(1), 0),
                Nonce::xor(&[0; 12], 0),
            )
        }

        fn explicit_nonce_len(&self) -> usize {
            0
        }

        fn min_protected_fragment_len(&self) -> usize {
            0
        }

        fn decrypt_data(
            &mut self,
            _ciphertext: &mut TmpBuf,
            _aad: Aad,
            _nonce: Nonce,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    fn test_engine() -> Engine {
        Engine::new(Arc::new(Config::default()), AuthMode::Psk)
    }

    fn handshake_record(content_type: ContentType, epoch: u16, seq: u64, msg_seq: u16) -> Vec<u8> {
        let mut fragment = Vec::new();
        fragment.push(MessageType::Finished.as_u8());
        fragment.extend_from_slice(&0u32.to_be_bytes()[1..]);
        fragment.extend_from_slice(&msg_seq.to_be_bytes());
        fragment.extend_from_slice(&0u32.to_be_bytes()[1..]);
        fragment.extend_from_slice(&0u32.to_be_bytes()[1..]);

        let mut out = Vec::new();
        out.push(content_type.as_u8());
        out.extend_from_slice(&[0xFE, 0xFD]);
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..]);
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(&fragment);
        out
    }

    fn ccs_record(seq: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ContentType::ChangeCipherSpec.as_u8());
        out.extend_from_slice(&[0xFE, 0xFD]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes()[2..]);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(1);
        out
    }

    #[test]
    fn encrypted_relevant_handshake_after_stale_plaintext_is_queued() {
        let mut engine = test_engine();
        engine.peer_encryption_enabled = true;
        engine.peer_handshake_seq_no = 1;

        let mut packet = handshake_record(ContentType::Handshake, 0, 0, 0);
        packet.extend_from_slice(&ccs_record(1));
        packet.extend_from_slice(&handshake_record(ContentType::Handshake, 1, 0, 1));

        let incoming = Incoming::parse_packet(
            &packet,
            &mut PassthroughRecordHandler,
            Some(Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256),
        )
        .expect("parse packet")
        .expect("packet contains records");

        engine
            .insert_incoming(incoming)
            .expect("insert mixed retransmission");

        assert_eq!(engine.queue_rx.len(), 1);
        assert!(
            engine.queue_rx[0]
                .records()
                .iter()
                .any(|record| record.record().sequence.epoch == 1
                    && record
                        .handshakes()
                        .iter()
                        .any(|handshake| handshake.header.message_seq == 1)),
            "relevant encrypted Finished must remain queued even when stale plaintext starts the datagram"
        );
    }
}
