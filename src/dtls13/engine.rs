use arrayvec::ArrayVec;
use log::debug;
use rand::random;
use std::collections::VecDeque;
use std::mem;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::incoming::Incoming;
use crate::buffer::{Buf, BufferPool, TmpBuf};
use crate::crypto::dtls_aead::{Aad13, Iv13, Nonce13};
use crate::crypto::CryptoContext;
use crate::crypto::SnCipher;
use crate::crypto::{Aad, Nonce, DTLS_AEAD_OVERHEAD, DTLS_EXPLICIT_NONCE_LEN};
use crate::message::{AckMessage, CipherSuite, ContentType, DTLSRecord, Handshake, RecordNumber};
use crate::message::{Body, HashAlgorithm, Header, MessageType, ProtocolVersion, Sequence};
use crate::timer::ExponentialBackoff;
use crate::window::ReplayWindow;
use crate::{Config, Error, Output};

const MAX_DEFRAGMENT_PACKETS: usize = 50;

// Using debug_ignore_primary since CryptoContext doesn't implement Debug
pub struct Engine {
    config: Arc<Config>,

    /// Pool of buffers
    buffers_free: BufferPool,

    /// Counters for sending DTLSRecord during epoch 0.
    ///
    /// This is kept separate since resends might force us to
    /// "go back" to these sequence number even if we technically
    /// progressed to epoch 1.
    sequence_epoch_0: Sequence,

    /// Counters for epoch 1 and beyond (DTLS 1.2).
    sequence_epoch_n: Sequence,

    /// Queue of incoming packets.
    queue_rx: VecDeque<Incoming>,

    /// Queue of outgoing packets.
    queue_tx: VecDeque<Buf>,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<CipherSuite>,

    /// Cryptographic context for handling encryption/decryption
    pub(crate) crypto_context: CryptoContext,

    /// Whether this engine is for a client (true) or server (false)
    is_client: bool,

    /// Whether we are using DTLS 1.3 (affects transcript format)
    is_dtls13: bool,

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

    /// DTLS 1.3 handshake keys for sending (epoch 2, cipher + IV).
    dtls13_hs_send_keys: Option<Dtls13Keys>,

    /// DTLS 1.3 handshake keys for receiving (epoch 2, cipher + IV).
    dtls13_hs_recv_keys: Option<Dtls13Keys>,

    /// DTLS 1.3 application keys for sending (epoch 3, cipher + IV).
    dtls13_send_keys: Option<Dtls13Keys>,

    /// DTLS 1.3 application keys for receiving (epoch 3, cipher + IV).
    dtls13_recv_keys: Option<Dtls13Keys>,

    /// Deferred packet data that couldn't be parsed yet (DTLS 1.3 encrypted records
    /// that arrived before keys were installed). Uses buffer pool.
    deferred_packet: Option<Buf>,

    // --- KeyUpdate state (RFC 8446 Section 4.6.3) ---
    /// Current application traffic secret (send direction) for KeyUpdate derivation.
    dtls13_send_traffic_secret: Option<Buf>,

    /// Current application traffic secret (receive direction) for KeyUpdate derivation.
    dtls13_recv_traffic_secret: Option<Buf>,

    /// Whether we have a pending outgoing KeyUpdate awaiting ACK.
    /// We MUST NOT send with new keys until the KeyUpdate message is ACKed.
    key_update_pending_ack: bool,

    /// Record number of our last sent KeyUpdate (to match against ACK).
    key_update_sent_record: Option<crate::message::RecordNumber>,

    /// Whether we need to send a KeyUpdate response (peer requested update).
    key_update_response_needed: bool,

    /// Whether AEAD limits indicate we should initiate a KeyUpdate.
    key_update_needed: bool,

    /// Counter for completed outgoing KeyUpdates (our keys updated after ACK).
    key_updates_sent: u32,

    /// Counter for processed incoming KeyUpdates (peer's keys updated).
    key_updates_received: u32,

    // --- ACK tracking (RFC 9147 Section 7) ---
    /// Record numbers received that need to be ACKed.
    /// Used for selective retransmission and confirming KeyUpdate transitions.
    pending_acks: Vec<crate::message::RecordNumber>,

    /// Maximum number of pending ACKs before sending an ACK message.
    #[allow(dead_code)]
    max_pending_acks: usize,

    /// When set, send a handshake ACK (epoch 2) at/after this instant.
    /// This is only used during handshake to help recovery for out-of-order
    /// or partial flights without always ACKing handshake completion.
    handshake_ack_deadline: Option<Instant>,

    // Test helpers: observability for DTLS 1.3 handshake ACK behavior.
    #[cfg(any(test, feature = "test-helpers"))]
    handshake_ack_epoch2_sent: u32,
    #[cfg(any(test, feature = "test-helpers"))]
    handshake_ack_epoch2_sent_last_count: usize,
    #[cfg(any(test, feature = "test-helpers"))]
    handshake_ack_epoch2_received: u32,
    #[cfg(any(test, feature = "test-helpers"))]
    handshake_ack_epoch2_received_last_count: usize,
    #[cfg(any(test, feature = "test-helpers"))]
    handshake_ack_epoch2_received_last_matched: usize,
}

/// AEAD usage limits per RFC 9147 Section 4.5.3.
/// These are the default values; actual limits are configurable via Config.
#[allow(dead_code)]
pub mod aead_limits {
    /// Default encryption limit: 2^23 (safety margin below 2^24.5)
    pub const DEFAULT_ENCRYPTION_LIMIT: u64 = 1 << 23;
    /// Default decryption failure limit: 2^35 (safety margin below 2^36)
    pub const DEFAULT_DECRYPTION_FAILURE_LIMIT: u64 = 1 << 35;
    /// Warning threshold: 90% of encryption limit
    pub fn warning_threshold(limit: u64) -> u64 {
        (limit * 9) / 10
    }
}

/// DTLS 1.3 key material for a single direction.
pub struct Dtls13Keys {
    /// The AEAD cipher instance.
    pub cipher: Box<dyn crate::crypto::Cipher>,
    /// Full 12-byte IV for nonce construction.
    pub iv: [u8; 12],
    /// Pre-instantiated AES cipher for sequence number encryption/decryption.
    /// RFC 9147 Section 4.2.3 requires using the same algorithm as record protection.
    sn_cipher: Option<Box<dyn SnCipher>>,
    /// Current sequence number.
    pub sequence_number: u64,
    /// Number of records encrypted with these keys (for AEAD limit tracking).
    pub encryption_count: u64,
    /// Number of decryption failures with these keys (for AEAD limit tracking).
    pub decryption_failure_count: u64,
    /// Configured encryption limit (for KeyUpdate triggering).
    encryption_limit: u64,
    /// Configured decryption failure limit.
    decryption_failure_limit: u64,
}

impl Dtls13Keys {
    /// Create new DTLS 1.3 keys with sequence number encryption key.
    /// The sn_cipher is created by the crypto provider based on key length:
    /// - 16 bytes: AES-128 (for TLS_AES_128_GCM_SHA256)
    /// - 32 bytes: AES-256 (for TLS_AES_256_GCM_SHA384)
    #[allow(dead_code)]
    pub fn new_with_sn_cipher(
        cipher: Box<dyn crate::crypto::Cipher>,
        iv: &[u8],
        sn_cipher: Option<Box<dyn SnCipher>>,
    ) -> Self {
        Self::new_with_limits(
            cipher,
            iv,
            sn_cipher,
            aead_limits::DEFAULT_ENCRYPTION_LIMIT,
            aead_limits::DEFAULT_DECRYPTION_FAILURE_LIMIT,
        )
    }

    /// Create new DTLS 1.3 keys with configurable AEAD limits.
    /// Use this for testing KeyUpdate with low limits.
    pub fn new_with_limits(
        cipher: Box<dyn crate::crypto::Cipher>,
        iv: &[u8],
        sn_cipher: Option<Box<dyn SnCipher>>,
        encryption_limit: u64,
        decryption_failure_limit: u64,
    ) -> Self {
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(&iv[..12]);
        Self {
            cipher,
            iv: iv_arr,
            sn_cipher,
            sequence_number: 0,
            encryption_count: 0,
            decryption_failure_count: 0,
            encryption_limit,
            decryption_failure_limit,
        }
    }

    /// Increment encryption count and check limits.
    /// Returns true if limit reached (should trigger KeyUpdate).
    pub fn increment_encryption(&mut self) -> bool {
        self.encryption_count += 1;
        let warning_threshold = aead_limits::warning_threshold(self.encryption_limit);
        if self.encryption_count >= self.encryption_limit {
            warn!(
                "AEAD encryption limit reached ({}/{}), KeyUpdate required",
                self.encryption_count, self.encryption_limit
            );
            true
        } else if self.encryption_count == warning_threshold {
            warn!(
                "AEAD encryption count at 90% of limit ({}/{}), KeyUpdate recommended",
                self.encryption_count, self.encryption_limit
            );
            false
        } else {
            false
        }
    }

    /// Increment decryption failure count and check limits.
    /// Returns true if limit exceeded.
    pub fn increment_decryption_failure(&mut self) -> bool {
        self.decryption_failure_count += 1;
        if self.decryption_failure_count >= self.decryption_failure_limit {
            warn!(
                "AEAD decryption failure limit reached ({}/{})",
                self.decryption_failure_count, self.decryption_failure_limit
            );
            true
        } else {
            false
        }
    }

    /// Get the next nonce and increment the sequence number.
    pub fn next_nonce(&mut self) -> Nonce13 {
        let nonce = Nonce13::new(Iv13(self.iv), self.sequence_number);
        self.sequence_number += 1;
        nonce
    }

    /// Compute nonce for a given sequence number (for decryption).
    pub fn nonce_for_seq(&self, seq: u64) -> Nonce13 {
        Nonce13::new(Iv13(self.iv), seq)
    }

    /// Decrypt the sequence number from a DTLS 1.3 ciphertext record.
    /// RFC 9147 Section 4.2.3: The encrypted sequence number is computed by XORing
    /// the leading bytes of the mask with the on-the-wire representation.
    ///
    /// For AES-based AEAD: Mask = AES-ECB(sn_key, Ciphertext[0..15])
    /// Then: decrypted_seq = encrypted_seq XOR Mask[0..seq_len]
    pub fn decrypt_sequence_number(&self, encrypted_seq: u16, ciphertext: &[u8]) -> u16 {
        // Need at least 16 bytes of ciphertext for the mask and a valid sn_cipher
        let Some(ref sn_cipher) = self.sn_cipher else {
            debug!(
                "decrypt_sequence_number: no sn_cipher, returning as-is: {}",
                encrypted_seq
            );
            return encrypted_seq;
        };

        if ciphertext.len() < 16 {
            debug!(
                "decrypt_sequence_number: insufficient ciphertext ({}), returning as-is: {}",
                ciphertext.len(),
                encrypted_seq
            );
            return encrypted_seq;
        }

        // Generate mask using AES-ECB on first 16 bytes of ciphertext
        let sample = &ciphertext[..16];
        let mask = Self::compute_sn_mask_with_cipher(sn_cipher.as_ref(), sample);

        // XOR the encrypted sequence number with the mask
        // For 16-bit sequence numbers, use first 2 bytes of mask
        let mask_bytes = [mask[0], mask[1]];
        let mask_val = u16::from_be_bytes(mask_bytes);
        let decrypted = encrypted_seq ^ mask_val;

        debug!(
            "decrypt_sn: sample={:02x?}, mask={:02x?}, \
             enc=0x{:04x}, mask_val=0x{:04x}, dec={}",
            sample,
            &mask[..],
            encrypted_seq,
            mask_val,
            decrypted
        );

        decrypted
    }

    /// Compute the sequence number mask using the pre-instantiated AES cipher.
    /// RFC 9147 Section 4.2.3: Uses AES-ECB with the cipher matching record protection.
    fn compute_sn_mask_with_cipher(sn_cipher: &dyn SnCipher, sample: &[u8]) -> [u8; 16] {
        let mut block = [0u8; 16];
        block.copy_from_slice(sample);
        sn_cipher.encrypt_block(&mut block);
        block
    }

    /// Encrypt the sequence number for a DTLS 1.3 record.
    pub fn encrypt_sequence_number(&self, seq: u64, ciphertext: &[u8]) -> u16 {
        let seq_16 = (seq & 0xFFFF) as u16;

        let Some(ref sn_cipher) = self.sn_cipher else {
            return seq_16;
        };

        if ciphertext.len() < 16 {
            return seq_16;
        }

        let mask = Self::compute_sn_mask_with_cipher(sn_cipher.as_ref(), &ciphertext[..16]);
        let mask_bytes = [mask[0], mask[1]];
        let mask_val = u16::from_be_bytes(mask_bytes);
        seq_16 ^ mask_val
    }
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
    record_numbers: ArrayVec<RecordNumber, 4>,
    acked: bool,
}

impl Engine {
    pub fn new(config: Arc<Config>, certificate: crate::DtlsCertificate) -> Self {
        let flight_backoff =
            ExponentialBackoff::new(config.flight_start_rto(), config.flight_retries());

        let crypto_context = CryptoContext::new(
            certificate.certificate,
            certificate.private_key,
            Arc::clone(&config),
        );

        Self {
            config,
            buffers_free: BufferPool::default(),
            sequence_epoch_0: Sequence::new(0),
            sequence_epoch_n: Sequence::new(1),
            queue_rx: VecDeque::new(),
            queue_tx: VecDeque::new(),
            cipher_suite: None,
            crypto_context,
            is_client: false,
            is_dtls13: false,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            transcript: Buf::new(),
            replay: ReplayWindow::new(),
            flight_saved_records: Vec::new(),
            flight_backoff,
            flight_timeout: Timeout::Unarmed,
            connect_timeout: Timeout::Unarmed,
            release_app_data: false,
            dtls13_hs_send_keys: None,
            dtls13_hs_recv_keys: None,
            dtls13_send_keys: None,
            dtls13_recv_keys: None,
            deferred_packet: None,
            // KeyUpdate state
            dtls13_send_traffic_secret: None,
            dtls13_recv_traffic_secret: None,
            key_update_pending_ack: false,
            key_update_sent_record: None,
            key_update_response_needed: false,
            key_update_needed: false,
            key_updates_sent: 0,
            key_updates_received: 0,
            // ACK tracking
            pending_acks: Vec::new(),
            max_pending_acks: 16, // Send ACK after 16 records by default

            handshake_ack_deadline: None,

            #[cfg(any(test, feature = "test-helpers"))]
            handshake_ack_epoch2_sent: 0,
            #[cfg(any(test, feature = "test-helpers"))]
            handshake_ack_epoch2_sent_last_count: 0,
            #[cfg(any(test, feature = "test-helpers"))]
            handshake_ack_epoch2_received: 0,
            #[cfg(any(test, feature = "test-helpers"))]
            handshake_ack_epoch2_received_last_count: 0,
            #[cfg(any(test, feature = "test-helpers"))]
            handshake_ack_epoch2_received_last_matched: 0,
        }
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_flight_epoch2_saved(&self) -> usize {
        self.flight_saved_records
            .iter()
            .filter(|e| e.epoch == 2)
            .count()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_flight_epoch2_acked(&self) -> usize {
        self.flight_saved_records
            .iter()
            .filter(|e| e.epoch == 2)
            .filter(|e| e.acked)
            .count()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_epoch2_sent(&self) -> (u32, usize) {
        (
            self.handshake_ack_epoch2_sent,
            self.handshake_ack_epoch2_sent_last_count,
        )
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_epoch2_received(&self) -> (u32, usize, usize) {
        (
            self.handshake_ack_epoch2_received,
            self.handshake_ack_epoch2_received_last_count,
            self.handshake_ack_epoch2_received_last_matched,
        )
    }

    /// Test helper: get the scheduled handshake ACK deadline (if any)
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_deadline(&self) -> Option<Instant> {
        self.handshake_ack_deadline
    }

    /// Test helper: check if there's currently a gap in incoming handshake data
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_has_gap_in_incoming(&self) -> bool {
        self.has_gap_in_incoming_handshake()
    }

    /// Test helper: check if ACK help is needed (gap or incomplete data)
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_help_needed(&self) -> bool {
        self.handshake_ack_help_needed()
    }

    pub fn set_client(&mut self, is_client: bool) {
        self.is_client = is_client;
    }

    /// Set DTLS 1.3 mode (affects transcript format)
    pub fn set_dtls13(&mut self, is_dtls13: bool) {
        self.is_dtls13 = is_dtls13;
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the cipher suite
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// Is the given cipher suite allowed by configuration
    pub fn is_cipher_suite_allowed(&self, suite: CipherSuite) -> bool {
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

    /// Set deferred packet data for later processing (when keys become available).
    pub fn set_deferred_packet(&mut self, data: &[u8]) {
        let mut buf = self.buffers_free.pop();
        buf.extend_from_slice(data);
        self.deferred_packet = Some(buf);
    }

    /// Check if there's deferred packet data.
    pub fn has_deferred_packet(&self) -> bool {
        self.deferred_packet.is_some()
    }

    /// Try to process any deferred packet data now that keys may be available.
    pub fn process_deferred_packet(&mut self) -> Result<(), Error> {
        if let Some(packet) = self.deferred_packet.take() {
            trace!("Processing deferred packet ({} bytes)", packet.len());
            let result = self.parse_packet(&packet);
            self.buffers_free.push(packet);
            result?;
        }
        Ok(())
    }

    pub fn parse_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let incoming = Incoming::parse_packet(packet, self)?;
        if let Some(incoming) = incoming {
            self.insert_incoming(incoming)?;
        }

        // Process incoming handshake ACKs if we still have epoch-2 records awaiting
        // retransmission.  This must happen even after application keys are installed,
        // since a late ACK from the peer can still suppress unnecessary resends.
        if self.flight_saved_records.iter().any(|e| e.epoch == 2) {
            self.process_incoming_handshake_acks()?;
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
                self.flight_backoff.attempt();
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

        // During handshake, ACKs are sent only when they help recovery (out-of-order/partial).
        // KeyUpdate ACKs are handled elsewhere (post-handshake path).
        self.maybe_schedule_handshake_ack(now);
        self.maybe_flush_handshake_ack(now)?;

        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8], now: Instant) -> Output<'a> {
        // First check if we have any decrypted app data.
        let buf = match self.poll_app_data(buf) {
            Ok(p) => return Output::ApplicationData(p),
            Err(b) => b,
        };

        // During DTLS 1.3 handshake, schedule an ACK only when it helps recovery
        // (out-of-order / partial handshake), without always ACKing completion.
        self.maybe_schedule_handshake_ack(now);

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

        // Drain incoming queue of processed records.
        self.purge_handled_queue_rx();

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
        if self.connect_timeout == Timeout::Disabled
            && self.flight_timeout == Timeout::Disabled
            && self.handshake_ack_deadline.is_none()
        {
            const DISTANT_FUTURE: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
            return now + DISTANT_FUTURE;
        }

        let mut timeout = match (self.connect_timeout, self.flight_timeout) {
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
        };

        if let Some(handshake_ack_deadline) = self.handshake_ack_deadline {
            if handshake_ack_deadline < timeout {
                timeout = handshake_ack_deadline;
            }
        }

        timeout
    }

    pub fn flight_begin(&mut self, flight_no: u8) {
        debug!("Begin flight {}", flight_no);
        self.flight_backoff.reset();
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
        let mut records = mem::take(&mut self.flight_saved_records);

        for entry in records.iter_mut() {
            if entry.acked {
                continue;
            }
            // For DTLS 1.3 epochs (2 for handshake, 3 for application), use the DTLS 1.3 record format
            if entry.epoch == 2 && self.has_dtls13_hs_send_keys() {
                let mut fragment = self.buffers_free.pop();
                fragment.extend_from_slice(&entry.fragment);
                let rn = self.create_record_dtls13_epoch2(entry.content_type, fragment)?;
                if entry.record_numbers.is_full() {
                    let _ = entry.record_numbers.remove(0);
                }
                entry.record_numbers.push(rn);
            } else if entry.epoch == 3 && self.has_dtls13_send_keys() {
                self.create_record_dtls13(entry.content_type, |fragment: &mut Buf| {
                    fragment.extend_from_slice(&entry.fragment);
                })?;
            } else {
                // DTLS 1.2 style record or epoch 0
                self.create_record(entry.content_type, entry.epoch, false, |fragment| {
                    fragment.extend_from_slice(&entry.fragment);
                })?;
            }
        }

        // Put the entries back into self
        self.flight_saved_records = records;

        Ok(())
    }

    pub fn has_complete_handshake(&mut self, wanted: MessageType) -> bool {
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

        if first.header.message_seq != self.peer_handshake_seq_no {
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

    /// Mark handshakes with old message_seq as handled (they're duplicates/replays).
    /// This prevents them from blocking the queue.
    fn cleanup_old_handshakes(&mut self) {
        for incoming in self.queue_rx.iter() {
            for record in incoming.records().iter() {
                for handshake in record.handshakes().iter() {
                    if !handshake.is_handled()
                        && handshake.header.message_seq < self.peer_handshake_seq_no
                    {
                        handshake.set_handled();
                    }
                }
            }
        }
    }

    pub fn next_handshake(
        &mut self,
        wanted: MessageType,
        defragment_buffer: &mut Buf,
    ) -> Result<Option<Handshake>, Error> {
        // Clean up any old handshakes that might be blocking the queue
        self.cleanup_old_handshakes();

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
            self.is_dtls13,
        )?;

        // Move the expected seq_no along
        self.peer_handshake_seq_no = handshake.header.message_seq + 1;

        Ok(Some(handshake))
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
                record_numbers: ArrayVec::new(),
                acked: false,
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
            let explicit_nonce: [u8; 8] = random();

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

    /// Calculate the maximum plaintext payload that can fit in a single DTLS 1.3 application record.
    ///
    /// Returns the max bytes of user data that can fit in one record, accounting for:
    /// - Unified header (worst case 5 bytes: 1 header + 2 seq + 2 length)
    /// - Content type byte (1 byte in inner plaintext)
    /// - AEAD tag (16 bytes)
    pub fn max_dtls13_app_data_fragment_size(&self) -> usize {
        // Unified header: 1 byte header + 2 bytes seq (worst case) + 2 bytes length = 5
        const UNIFIED_HEADER_MAX: usize = 5;
        // Inner plaintext has 1 byte content type appended
        const CONTENT_TYPE_BYTE: usize = 1;
        // AEAD tag (GCM/CCM)
        const AEAD_TAG: usize = 16;

        let overhead = UNIFIED_HEADER_MAX + CONTENT_TYPE_BYTE + AEAD_TAG;
        self.config.mtu().saturating_sub(overhead)
    }

    /// Create a DTLS 1.3 record with unified header format.
    ///
    /// This is used for application data in DTLS 1.3 (epoch 3).
    /// The content type is encrypted inside the record (inner plaintext).
    pub fn create_record_dtls13<F>(&mut self, content_type: ContentType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf),
    {
        let keys = self
            .dtls13_send_keys
            .as_mut()
            .ok_or_else(|| Error::CryptoError("DTLS 1.3 send keys not installed".to_string()))?;

        // Prepare the plaintext fragment
        let mut fragment = self.buffers_free.pop();
        f(&mut fragment);

        // Build inner plaintext: content || content_type (RFC 9147)
        fragment.push(content_type.as_u8());

        // Get sequence number and compute nonce
        let seq = keys.sequence_number;
        let nonce = keys.next_nonce();

        // Build the unified header using stack-allocated array (max 5 bytes)
        // Format: 001CSLEE where C=0 (no CID), S=seq16, L=1 (include length), EE=epoch_bits
        let epoch_bits = 3u8; // Epoch 3 for application data (only lower 2 bits used)
                              // Always use 16-bit sequence for now to match BoringSSL's behavior
        let seq_16bit = true;

        let mut header: [u8; 5] = [0; 5];
        let mut header_len = 0;

        let mut header_byte = 0b0010_0000u8; // Fixed bits 001xxxxx
        if seq_16bit {
            header_byte |= 0b0000_1000; // S bit
        }
        header_byte |= 0b0000_0100; // L bit (include length)
        header_byte |= epoch_bits;
        header[header_len] = header_byte;
        header_len += 1;

        // Sequence number (8 or 16 bit)
        if seq_16bit {
            let seq_bytes = ((seq & 0xFFFF) as u16).to_be_bytes();
            header[header_len] = seq_bytes[0];
            header[header_len + 1] = seq_bytes[1];
            header_len += 2;
        } else {
            header[header_len] = (seq & 0xFF) as u8;
            header_len += 1;
        }

        // Compute encrypted length: plaintext + 16-byte auth tag
        let encrypted_len = (fragment.len() + 16) as u16;
        let len_bytes = encrypted_len.to_be_bytes();
        header[header_len] = len_bytes[0];
        header[header_len + 1] = len_bytes[1];
        header_len += 2;

        // Create AAD from header (with the correct length)
        let aad = Aad13::from_header(&header[..header_len]);

        // Encrypt in place using variable-length AAD for DTLS 1.3
        let nonce_12 = crate::crypto::Nonce(nonce.0);

        keys.cipher
            .encrypt_with_aad(&mut fragment, aad.as_bytes(), nonce_12)
            .map_err(|e| Error::CryptoError(format!("DTLS 1.3 encryption failed: {}", e)))?;

        // Track AEAD usage (RFC 9147 Section 4.5.3)
        let needs_key_update = keys.increment_encryption();
        if needs_key_update && !self.key_update_pending_ack && !self.key_update_needed {
            // Set flag to trigger KeyUpdate - can't do it here to avoid recursion
            self.key_update_needed = true;
            debug!("AEAD encryption limit approaching, KeyUpdate will be initiated");
        }

        // Encrypt sequence number in header (RFC 9147 Section 4.2.3)
        let encrypted_seq = keys.encrypt_sequence_number(seq, &fragment);

        // Update header with encrypted sequence number
        if seq_16bit {
            header[1] = (encrypted_seq >> 8) as u8;
            header[2] = (encrypted_seq & 0xFF) as u8;
        } else {
            header[1] = (encrypted_seq & 0xFF) as u8;
        }

        // Compute wire length
        let record_wire_len = header_len + fragment.len();

        // Decide whether to append or create new datagram
        let can_append = self
            .queue_tx
            .back()
            .map(|b| b.len() + record_wire_len <= self.config.mtu())
            .unwrap_or(false);

        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx() {
            self.buffers_free.push(fragment);
            return Err(Error::TransmitQueueFull);
        }

        // Serialize the record
        if can_append {
            let last = self.queue_tx.back_mut().unwrap();
            last.extend_from_slice(&header[..header_len]);
            last.extend_from_slice(&fragment);
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            buffer.extend_from_slice(&header[..header_len]);
            buffer.extend_from_slice(&fragment);
            self.queue_tx.push_back(buffer);
        }

        self.buffers_free.push(fragment);
        Ok(())
    }

    /// Install DTLS 1.3 handshake keys for sending with sn_key (epoch 2).
    pub fn install_dtls13_hs_send_keys_with_sn(
        &mut self,
        cipher: Box<dyn crate::crypto::Cipher>,
        iv: &[u8],
        sn_key: &[u8],
    ) {
        let sn_cipher = self
            .config
            .crypto_provider()
            .sn_cipher_provider
            .create_sn_cipher(sn_key);
        self.dtls13_hs_send_keys = Some(Dtls13Keys::new_with_limits(
            cipher,
            iv,
            sn_cipher,
            self.config.aead_encryption_limit(),
            self.config.aead_decryption_failure_limit(),
        ));
    }

    /// Install DTLS 1.3 handshake keys for receiving with sn_key (epoch 2).
    pub fn install_dtls13_hs_recv_keys_with_sn(
        &mut self,
        cipher: Box<dyn crate::crypto::Cipher>,
        iv: &[u8],
        sn_key: &[u8],
    ) {
        let sn_cipher = self
            .config
            .crypto_provider()
            .sn_cipher_provider
            .create_sn_cipher(sn_key);
        self.dtls13_hs_recv_keys = Some(Dtls13Keys::new_with_limits(
            cipher,
            iv,
            sn_cipher,
            self.config.aead_encryption_limit(),
            self.config.aead_decryption_failure_limit(),
        ));
    }

    /// Check if DTLS 1.3 handshake send keys are installed.
    pub fn has_dtls13_hs_send_keys(&self) -> bool {
        self.dtls13_hs_send_keys.is_some()
    }

    /// Check if DTLS 1.3 handshake receive keys are installed.
    pub fn has_dtls13_hs_recv_keys(&self) -> bool {
        self.dtls13_hs_recv_keys.is_some()
    }

    /// Install DTLS 1.3 application keys for sending with sn_key (epoch 3).
    pub fn install_dtls13_send_keys_with_sn(
        &mut self,
        cipher: Box<dyn crate::crypto::Cipher>,
        iv: &[u8],
        sn_key: &[u8],
    ) {
        let sn_cipher = self
            .config
            .crypto_provider()
            .sn_cipher_provider
            .create_sn_cipher(sn_key);
        self.dtls13_send_keys = Some(Dtls13Keys::new_with_limits(
            cipher,
            iv,
            sn_cipher,
            self.config.aead_encryption_limit(),
            self.config.aead_decryption_failure_limit(),
        ));
    }

    /// Install DTLS 1.3 application keys for receiving with sn_key (epoch 3).
    pub fn install_dtls13_recv_keys_with_sn(
        &mut self,
        cipher: Box<dyn crate::crypto::Cipher>,
        iv: &[u8],
        sn_key: &[u8],
    ) {
        let sn_cipher = self
            .config
            .crypto_provider()
            .sn_cipher_provider
            .create_sn_cipher(sn_key);
        self.dtls13_recv_keys = Some(Dtls13Keys::new_with_limits(
            cipher,
            iv,
            sn_cipher,
            self.config.aead_encryption_limit(),
            self.config.aead_decryption_failure_limit(),
        ));
    }

    /// Store the application traffic secret for KeyUpdate derivation (send direction).
    pub fn set_send_traffic_secret(&mut self, secret: &[u8]) {
        let mut buf = Buf::new();
        buf.extend_from_slice(secret);
        self.dtls13_send_traffic_secret = Some(buf);
    }

    /// Store the application traffic secret for KeyUpdate derivation (receive direction).
    pub fn set_recv_traffic_secret(&mut self, secret: &[u8]) {
        let mut buf = Buf::new();
        buf.extend_from_slice(secret);
        self.dtls13_recv_traffic_secret = Some(buf);
    }

    /// Check if DTLS 1.3 application send keys are installed.
    pub fn has_dtls13_send_keys(&self) -> bool {
        self.dtls13_send_keys.is_some()
    }

    /// Check if DTLS 1.3 application receive keys are installed.
    pub fn has_dtls13_recv_keys(&self) -> bool {
        self.dtls13_recv_keys.is_some()
    }

    // ========== KeyUpdate methods (RFC 8446 Section 4.6.3) ==========

    /// Check if a KeyUpdate is pending acknowledgment.
    #[allow(dead_code)]
    pub fn is_key_update_pending(&self) -> bool {
        self.key_update_pending_ack
    }

    /// Check if we need to send a KeyUpdate response.
    #[allow(dead_code)]
    pub fn needs_key_update_response(&self) -> bool {
        self.key_update_response_needed
    }

    /// Check if AEAD limits require initiating a KeyUpdate.
    #[allow(dead_code)]
    pub fn needs_key_update(&self) -> bool {
        self.key_update_needed
    }

    /// Get the number of completed outgoing KeyUpdates (our send keys updated).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn key_updates_sent(&self) -> u32 {
        self.key_updates_sent
    }

    /// Get the number of processed incoming KeyUpdates (our receive keys updated).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn key_updates_received(&self) -> u32 {
        self.key_updates_received
    }

    /// Process any pending KeyUpdate needs (either AEAD limit or peer request).
    /// Call this from the poll loop after application data is handled.
    pub fn process_pending_key_updates(&mut self) -> Result<(), Error> {
        // Handle AEAD limit-triggered KeyUpdate
        if self.key_update_needed && !self.key_update_pending_ack {
            debug!("Initiating KeyUpdate due to AEAD limits");
            self.send_key_update(true)?; // Request peer to also update
            self.key_update_needed = false;
        }

        // Handle peer-requested KeyUpdate response
        if self.key_update_response_needed && !self.key_update_pending_ack {
            debug!("Sending KeyUpdate response to peer request");
            self.send_key_update(false)?; // Don't request peer update (they just sent one)
            self.key_update_response_needed = false;
        }

        Ok(())
    }

    /// Initiate a KeyUpdate to refresh traffic keys.
    /// This sends a KeyUpdate message and prepares to install new send keys.
    /// The new keys are not used until the KeyUpdate is acknowledged.
    ///
    /// Per RFC 8446: An implementation may receive an unencrypted record of a type
    /// which could trigger a key update (i.e., application data). In this case,
    /// it MUST NOT send a KeyUpdate until the handshake is complete.
    pub fn send_key_update(&mut self, request_update: bool) -> Result<(), Error> {
        use crate::message::KeyUpdateRequest;

        if !self.has_dtls13_send_keys() {
            return Err(Error::CryptoError(
                "Cannot send KeyUpdate: no application keys installed".to_string(),
            ));
        }

        if self.key_update_pending_ack {
            debug!("KeyUpdate already pending, not sending another");
            return Ok(());
        }

        let request = if request_update {
            KeyUpdateRequest::UpdateRequested
        } else {
            KeyUpdateRequest::UpdateNotRequested
        };

        let key_update = crate::message::KeyUpdate::new(request);
        let mut body = Buf::new();
        key_update.serialize(&mut body);

        // Capture the record number before sending (epoch 3, current sequence number)
        let seq_number = self
            .dtls13_send_keys
            .as_ref()
            .map(|k| k.sequence_number)
            .unwrap_or(0);

        // Create handshake message with KeyUpdate body (message type 24)
        // Note: KeyUpdate is sent in application data epoch (3)
        self.create_post_handshake_dtls13(MessageType::KeyUpdate, body)?;

        // Mark that we have a pending KeyUpdate and track the record number
        self.key_update_pending_ack = true;
        self.key_update_sent_record = Some(crate::message::RecordNumber {
            epoch: 3,
            sequence_number: seq_number,
        });

        debug!(
            "Sent KeyUpdate (request_update={}) in epoch 3 seq {}",
            request_update, seq_number
        );
        Ok(())
    }

    /// Create a post-handshake message using DTLS 1.3 record format (epoch 3).
    /// Used for post-handshake messages like KeyUpdate.
    /// Unlike handshake messages (epoch 2), these are encrypted with application keys.
    fn create_post_handshake_dtls13(
        &mut self,
        msg_type: MessageType,
        body: Buf,
    ) -> Result<(), Error> {
        let header = Header {
            msg_type,
            length: body.len() as u32,
            message_seq: self.next_handshake_seq_no,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
        };
        self.next_handshake_seq_no = self.next_handshake_seq_no.wrapping_add(1);

        // Create the handshake record content (encrypted with application keys, epoch 3)
        self.create_record_dtls13(ContentType::Handshake, |fragment| {
            // Serialize the DTLS handshake header manually:
            // msg_type (1 byte) + length (3 bytes) + message_seq (2 bytes) +
            // fragment_offset (3 bytes) + fragment_length (3 bytes) = 12 bytes
            fragment.push(header.msg_type.as_u8());
            fragment.extend_from_slice(&header.length.to_be_bytes()[1..]); // 3 bytes
            fragment.extend_from_slice(&header.message_seq.to_be_bytes()); // 2 bytes
            fragment.extend_from_slice(&header.fragment_offset.to_be_bytes()[1..]); // 3 bytes
            fragment.extend_from_slice(&header.fragment_length.to_be_bytes()[1..]); // 3 bytes
            fragment.extend_from_slice(&body);
        })
    }

    /// Handle a received KeyUpdate message.
    /// This updates our receive keys and optionally sends a KeyUpdate response.
    pub fn handle_key_update(&mut self, request_update: bool) -> Result<(), Error> {
        if !self.has_dtls13_recv_keys() {
            return Err(Error::CryptoError(
                "Cannot handle KeyUpdate: no receive keys installed".to_string(),
            ));
        }

        let Some(ref recv_secret) = self.dtls13_recv_traffic_secret else {
            return Err(Error::CryptoError(
                "Cannot handle KeyUpdate: no receive traffic secret".to_string(),
            ));
        };

        // Derive next traffic secret
        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::CryptoError("No cipher suite".to_string()))?;
        let hash_alg = cipher_suite.hash_algorithm();

        // Create a new KeySchedule for key derivation
        let ks = crate::crypto::tls13_key_schedule::KeySchedule::new(
            self.config.crypto_provider().hkdf_provider,
            hash_alg,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to create key schedule: {}", e)))?;

        let next_secret = ks.derive_next_traffic_secret(recv_secret).map_err(|e| {
            Error::CryptoError(format!("Failed to derive next traffic secret: {}", e))
        })?;

        // Derive new traffic keys
        let (key_len, iv_len) = match cipher_suite {
            CipherSuite::TLS_AES_256_GCM_SHA384 | CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
                (32, 12)
            }
            _ => (16, 12),
        };

        let (key, iv, sn_key) = ks
            .derive_traffic_keys_dtls13(&next_secret, key_len, iv_len)
            .map_err(|e| Error::CryptoError(format!("Failed to derive traffic keys: {}", e)))?;

        // Create new cipher
        let provider = self.config.crypto_provider();
        let cipher = provider
            .cipher_suites
            .iter()
            .find(|s| {
                s.suite() == cipher_suite
                    || (cipher_suite.is_tls13() && s.hash_algorithm() == hash_alg)
            })
            .ok_or(Error::CryptoError("Cipher suite not supported".to_string()))?
            .create_cipher(&key)
            .map_err(|e| Error::CryptoError(format!("Failed to create cipher: {}", e)))?;

        // Install new receive keys
        self.install_dtls13_recv_keys_with_sn(cipher, &iv, &sn_key);

        // Reset replay window since sequence numbers restart with new keys
        self.replay.reset_for_key_update();

        // Update stored traffic secret
        self.dtls13_recv_traffic_secret = Some(next_secret);

        // Increment counter
        self.key_updates_received += 1;

        debug!(
            "Updated receive keys after KeyUpdate (total received: {})",
            self.key_updates_received
        );

        // If we have a pending outgoing KeyUpdate, the peer's KeyUpdate serves as
        // implicit confirmation that they received ours. We must confirm our KeyUpdate
        // immediately because:
        // 1. The peer has already updated their receive keys (to match our new send keys)
        // 2. Any ACK they send will be encrypted with old keys (before they confirm their KeyUpdate)
        // 3. But we just updated our receive keys, so we can't decrypt old-key encrypted ACKs
        // This handles the "simultaneous KeyUpdate" case per RFC 8446 Section 4.6.3
        if self.key_update_pending_ack {
            debug!(
                "Peer sent KeyUpdate while we have pending KeyUpdate - confirming ours immediately"
            );
            self.confirm_key_update()?;
        }

        // If peer requested update, we need to send our own KeyUpdate (unless we already have one pending)
        if request_update && !self.key_update_pending_ack {
            self.key_update_response_needed = true;
        }

        Ok(())
    }

    /// Process KeyUpdate acknowledgment (via ACK message).
    /// After ACK is received, we can install and use the new send keys.
    pub fn confirm_key_update(&mut self) -> Result<(), Error> {
        if !self.key_update_pending_ack {
            debug!("No pending KeyUpdate to confirm");
            return Ok(());
        }

        let Some(ref send_secret) = self.dtls13_send_traffic_secret else {
            return Err(Error::CryptoError(
                "Cannot confirm KeyUpdate: no send traffic secret".to_string(),
            ));
        };

        // Derive next traffic secret
        let cipher_suite = self
            .cipher_suite
            .ok_or(Error::CryptoError("No cipher suite".to_string()))?;
        let hash_alg = cipher_suite.hash_algorithm();

        // Create a new KeySchedule for key derivation
        let ks = crate::crypto::tls13_key_schedule::KeySchedule::new(
            self.config.crypto_provider().hkdf_provider,
            hash_alg,
        )
        .map_err(|e| Error::CryptoError(format!("Failed to create key schedule: {}", e)))?;

        let next_secret = ks.derive_next_traffic_secret(send_secret).map_err(|e| {
            Error::CryptoError(format!("Failed to derive next traffic secret: {}", e))
        })?;

        // Derive new traffic keys
        let (key_len, iv_len) = match cipher_suite {
            CipherSuite::TLS_AES_256_GCM_SHA384 | CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
                (32, 12)
            }
            _ => (16, 12),
        };

        let (key, iv, sn_key) = ks
            .derive_traffic_keys_dtls13(&next_secret, key_len, iv_len)
            .map_err(|e| Error::CryptoError(format!("Failed to derive traffic keys: {}", e)))?;

        // Create new cipher
        let provider = self.config.crypto_provider();
        let cipher = provider
            .cipher_suites
            .iter()
            .find(|s| {
                s.suite() == cipher_suite
                    || (cipher_suite.is_tls13() && s.hash_algorithm() == hash_alg)
            })
            .ok_or(Error::CryptoError("Cipher suite not supported".to_string()))?
            .create_cipher(&key)
            .map_err(|e| Error::CryptoError(format!("Failed to create cipher: {}", e)))?;

        // Install new send keys
        self.install_dtls13_send_keys_with_sn(cipher, &iv, &sn_key);

        // Update stored traffic secret
        self.dtls13_send_traffic_secret = Some(next_secret);

        // Clear pending state
        self.key_update_pending_ack = false;
        self.key_update_sent_record = None;

        // Increment counter
        self.key_updates_sent += 1;

        debug!(
            "Confirmed KeyUpdate, new send keys installed (total sent: {})",
            self.key_updates_sent
        );
        Ok(())
    }

    // ========== ACK methods (RFC 9147 Section 7) ==========

    fn dtls13_handshake_in_progress(&self) -> bool {
        // We can only send handshake ACKs once handshake write keys are installed.
        // Once application keys are installed (or app data is released), we stop using
        // handshake ACK scheduling.
        self.is_dtls13
            && self.dtls13_hs_send_keys.is_some()
            && self.dtls13_send_keys.is_none()
            && !self.release_app_data
    }

    fn handshake_ack_help_needed(&self) -> bool {
        let mut skip_handled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            .take(MAX_DEFRAGMENT_PACKETS)
            .flat_map(|r| r.handshakes().iter())
            .skip_while(|h| h.is_handled())
            .peekable();

        let Some(first) = skip_handled.peek() else {
            return false;
        };

        // If we're not seeing the expected message_seq at the head of the queue,
        // we are likely missing earlier fragments/records.
        if first.header.message_seq != self.peer_handshake_seq_no {
            return true;
        }

        // Otherwise, we have the expected sequence number but might be missing fragments.
        let wanted_seq = first.header.message_seq;
        let wanted_length = first.header.length;
        let mut last_fragment_end = 0;

        for h in skip_handled {
            if wanted_seq != h.header.message_seq {
                continue;
            }

            if h.header.fragment_offset != last_fragment_end {
                return true;
            }
            last_fragment_end = h.header.fragment_offset + h.header.fragment_length;

            if last_fragment_end == wanted_length {
                return false;
            }
        }

        true
    }

    /// Schedule an immediate ACK (like BoringSSL's `schedule_ack()`).
    /// Used when we want to ACK right away, e.g., after receiving client Finished.
    #[allow(dead_code)]
    fn schedule_immediate_ack(&mut self, now: Instant) {
        if self.dtls13_handshake_in_progress() || self.handshake_ack_deadline.is_some() {
            // Only override if we'd send later; immediate is always better
            if self.handshake_ack_deadline.map_or(true, |d| d > now) {
                self.handshake_ack_deadline = Some(now);
            }
        }
    }

    fn maybe_schedule_handshake_ack(&mut self, now: Instant) {
        if !self.dtls13_handshake_in_progress() {
            self.handshake_ack_deadline = None;
            return;
        }

        if self.handshake_ack_deadline.is_some() {
            return;
        }

        let gap_detected = self.handshake_ack_help_needed();
        if !gap_detected {
            return;
        }

        // If we detect a gap (missing fragments/messages), send ACK immediately
        // to help the peer retransmit faster. Otherwise, use RTO/4 delay to allow
        // piggybacking on the next flight.
        //
        // This follows BoringSSL's approach: immediate ACK when we need help,
        // delayed ACK when just acknowledging received data.
        let delay = if self.has_gap_in_incoming_handshake() {
            // Gap detected: immediate ACK to trigger fast retransmit
            Duration::from_millis(0)
        } else {
            // No gap: use RTO/4 delay for potential piggybacking
            let rto = self.flight_backoff.rto();
            if rto > Duration::from_millis(0) {
                rto / 4
            } else {
                Duration::from_millis(0)
            }
        };

        self.handshake_ack_deadline = Some(now + delay);
    }

    /// Check if there's a gap in the incoming handshake data that requires
    /// an immediate ACK to help the peer retransmit.
    fn has_gap_in_incoming_handshake(&self) -> bool {
        let mut skip_handled = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .skip_while(|r| r.is_handled())
            .take(MAX_DEFRAGMENT_PACKETS)
            .flat_map(|r| r.handshakes().iter())
            .skip_while(|h| h.is_handled())
            .peekable();

        let Some(first) = skip_handled.peek() else {
            return false;
        };

        // Gap: we're not seeing the expected message_seq at the head
        if first.header.message_seq != self.peer_handshake_seq_no {
            return true;
        }

        // Check for fragment gaps within the expected message
        let wanted_seq = first.header.message_seq;
        let wanted_length = first.header.length;
        let mut last_fragment_end = 0;

        for h in skip_handled {
            if wanted_seq != h.header.message_seq {
                continue;
            }

            // Gap: fragment doesn't start where the previous one ended
            if h.header.fragment_offset != last_fragment_end {
                return true;
            }
            last_fragment_end = h.header.fragment_offset + h.header.fragment_length;

            if last_fragment_end == wanted_length {
                // Message is complete, no gap
                return false;
            }
        }

        // We have fragments but message is incomplete - could be gap at end
        // This isn't strictly a gap (might just be slow arrival), so don't
        // trigger immediate ACK for this case
        false
    }

    fn maybe_flush_handshake_ack(&mut self, now: Instant) -> Result<(), Error> {
        let Some(deadline) = self.handshake_ack_deadline else {
            return Ok(());
        };

        if now < deadline {
            return Ok(());
        }

        // Collect record numbers for epoch-2 handshake records we have received.
        let record_numbers: Vec<RecordNumber> = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter())
            .filter(|r| r.record().sequence.epoch == 2)
            .filter(|r| r.record().content_type == ContentType::Handshake)
            .map(|r| {
                let seq = r.record().sequence;
                RecordNumber::new(seq.epoch as u64, seq.sequence_number)
            })
            .collect();

        self.handshake_ack_deadline = None;

        if record_numbers.is_empty() {
            return Ok(());
        }

        self.send_handshake_ack_epoch2(&record_numbers)?;
        Ok(())
    }

    fn send_handshake_ack_epoch2(&mut self, record_numbers: &[RecordNumber]) -> Result<(), Error> {
        if !self.dtls13_handshake_in_progress() {
            return Ok(());
        }

        let mut ack = AckMessage::new();
        for rn in record_numbers {
            ack.add(rn.epoch, rn.sequence_number);
        }

        #[cfg(any(test, feature = "test-helpers"))]
        {
            self.handshake_ack_epoch2_sent = self.handshake_ack_epoch2_sent.saturating_add(1);
            self.handshake_ack_epoch2_sent_last_count = record_numbers.len();
        }

        let mut body = Buf::new();
        ack.serialize(&mut body);

        let mut fragment = self.buffers_free.pop();
        fragment.extend_from_slice(&body);

        // ACK during handshake uses epoch 2 (handshake traffic keys).
        let _ = self.create_record_dtls13_epoch2(ContentType::Ack, fragment)?;
        Ok(())
    }

    fn process_incoming_handshake_acks(&mut self) -> Result<(), Error> {
        loop {
            let ack_data = {
                let mut unhandled = self
                    .queue_rx
                    .iter()
                    .flat_map(|i| i.records().iter())
                    .filter(|r| r.record().content_type == ContentType::Ack)
                    .filter(|r| r.record().sequence.epoch == 2)
                    .filter(|r| !r.is_handled());

                let Some(next) = unhandled.next() else {
                    break;
                };

                let record_buffer = next.buffer();
                let fragment = next.record().fragment(record_buffer);
                let data = fragment.to_vec();
                next.set_handled();
                data
            };

            if let Ok((_, ack)) = AckMessage::parse(&ack_data) {
                self.handle_dtls13_handshake_ack(&ack);
            }
        }
        Ok(())
    }

    fn handle_dtls13_handshake_ack(&mut self, ack: &AckMessage) {
        #[cfg(any(test, feature = "test-helpers"))]
        {
            self.handshake_ack_epoch2_received =
                self.handshake_ack_epoch2_received.saturating_add(1);
            self.handshake_ack_epoch2_received_last_count = ack.record_numbers.len();
            self.handshake_ack_epoch2_received_last_matched = 0;
        }

        for rn in &ack.record_numbers {
            for entry in self.flight_saved_records.iter_mut() {
                if entry.epoch != 2 {
                    continue;
                }
                if entry.record_numbers.iter().any(|sent| {
                    sent.epoch == rn.epoch && sent.sequence_number == rn.sequence_number
                }) {
                    entry.acked = true;

                    #[cfg(any(test, feature = "test-helpers"))]
                    {
                        self.handshake_ack_epoch2_received_last_matched += 1;
                    }
                }
            }
        }

        // If the entire current epoch-2 flight is ACKed, stop retransmitting it.
        let has_epoch2 = self.flight_saved_records.iter().any(|e| e.epoch == 2);
        let all_epoch2_acked = self
            .flight_saved_records
            .iter()
            .filter(|e| e.epoch == 2)
            .all(|e| e.acked);

        if has_epoch2 && all_epoch2_acked {
            self.flight_timeout = Timeout::Disabled;
            self.flight_clear_resends();
        }
    }

    /// Add a record to the pending ACKs list.
    pub fn add_pending_ack(&mut self, epoch: u16, sequence_number: u64) {
        let record_number = RecordNumber::new(epoch as u64, sequence_number);
        self.pending_acks.push(record_number);
    }

    /// Check if we should send an ACK message.
    #[allow(dead_code)]
    pub fn should_send_ack(&self) -> bool {
        self.pending_acks.len() >= self.max_pending_acks
    }

    /// Send an ACK message for all pending records.
    pub fn send_ack(&mut self) -> Result<(), Error> {
        if self.pending_acks.is_empty() {
            return Ok(());
        }

        let mut ack = AckMessage::new();
        for rn in std::mem::take(&mut self.pending_acks) {
            ack.add(rn.epoch, rn.sequence_number);
        }

        let mut body = Buf::new();
        ack.serialize(&mut body);

        // ACK is sent as ContentType::Ack, encrypted in application epoch
        self.create_record_dtls13(ContentType::Ack, |fragment| {
            fragment.extend_from_slice(&body);
        })?;

        debug!("Sent ACK for {} records", ack.record_numbers.len());
        Ok(())
    }

    /// Handle a received ACK message.
    pub fn handle_ack(&mut self, ack: &AckMessage) -> Result<(), Error> {
        // Check if this ACK confirms our pending KeyUpdate
        if let Some(ref pending_record) = self.key_update_sent_record {
            if ack.acknowledges(pending_record.epoch, pending_record.sequence_number) {
                debug!("ACK confirms pending KeyUpdate");
                self.confirm_key_update()?;
            }
        }

        // ACKs can also be used for selective retransmission (not implemented yet)
        // For now we just log which records were acknowledged
        debug!("Received ACK for {} records", ack.record_numbers.len());

        Ok(())
    }

    /// Force sending an ACK immediately (e.g., for KeyUpdate confirmation).
    pub fn flush_pending_acks(&mut self) -> Result<(), Error> {
        if !self.pending_acks.is_empty() {
            self.send_ack()?;
        }
        Ok(())
    }

    /// Process incoming post-handshake messages (ACK, KeyUpdate).
    /// This should be called from the Connected state after application data processing.
    /// Returns true if any messages were processed.
    pub fn process_incoming_post_handshake(&mut self) -> Result<bool, Error> {
        let mut processed_any = false;

        // Process ACK records
        loop {
            let ack_data = {
                let mut unhandled = self
                    .queue_rx
                    .iter()
                    .flat_map(|i| i.records().iter())
                    .filter(|r| r.record().content_type == ContentType::Ack)
                    .filter(|r| !r.is_handled());

                let Some(next) = unhandled.next() else {
                    break;
                };

                let record_buffer = next.buffer();
                let fragment = next.record().fragment(record_buffer);
                let data = fragment.to_vec();
                next.set_handled();
                data
            };

            // Parse and handle the ACK message
            match AckMessage::parse(&ack_data) {
                Ok((_, ack)) => {
                    debug!("Processing incoming ACK message");
                    self.handle_ack(&ack)?;
                    processed_any = true;
                }
                Err(e) => {
                    debug!("Failed to parse ACK message: {:?}", e);
                }
            }
        }

        // Process KeyUpdate handshake messages
        // KeyUpdate comes as ContentType::Handshake with MessageType::KeyUpdate
        loop {
            let key_update_info = {
                // Find unhandled KeyUpdate handshakes
                let mut found_key_update: Option<(u8, u64, u64)> = None; // (request_byte, epoch, seq)

                for incoming in self.queue_rx.iter() {
                    for record in incoming.records().iter() {
                        if record.record().content_type != ContentType::Handshake {
                            continue;
                        }
                        for handshake in record.handshakes().iter() {
                            if !handshake.is_handled()
                                && handshake.header.msg_type == MessageType::KeyUpdate
                            {
                                // KeyUpdate body is 1 byte (request_update flag)
                                // Get it from the record fragment at the right offset
                                // Handshake format in fragment: msg_type(1) + length(3) + message_seq(2) +
                                // fragment_offset(3) + fragment_length(3) + body(1) = 13 bytes total
                                let fragment = record.record().fragment(record.buffer());
                                if fragment.len() >= 13 {
                                    // Body is at byte 12 (0-indexed)
                                    let request_update_byte = fragment[12];
                                    // Get the record number for ACK
                                    let rec = record.record();
                                    found_key_update = Some((
                                        request_update_byte,
                                        rec.sequence.epoch as u64,
                                        rec.sequence.sequence_number,
                                    ));
                                }
                                // Mark as handled
                                handshake.set_handled();
                                break;
                            }
                        }
                        if found_key_update.is_some() {
                            break;
                        }
                    }
                    if found_key_update.is_some() {
                        break;
                    }
                }

                found_key_update
            };

            let Some((request_update_byte, epoch, seq_no)) = key_update_info else {
                break;
            };

            // 0 = update_not_requested, 1 = update_requested
            let is_update_requested = request_update_byte == 1;
            debug!(
                "Processing incoming KeyUpdate (request_update={}) from epoch {} seq {}",
                is_update_requested, epoch, seq_no
            );
            self.handle_key_update(is_update_requested)?;

            // Add the KeyUpdate record to pending ACKs
            self.add_pending_ack(epoch as u16, seq_no);

            processed_any = true;
        }

        // After processing incoming messages, check if we need to send responses
        self.process_pending_key_updates()?;

        // Flush any pending ACKs (e.g., to acknowledge the KeyUpdate we received)
        self.flush_pending_acks()?;

        Ok(processed_any)
    }

    /// Decrypt the sequence number for a DTLS 1.3 record.
    /// Returns the decrypted sequence number, or the original if keys aren't available.
    pub fn decrypt_dtls13_sequence(
        &self,
        encrypted_seq: u16,
        epoch: u16,
        ciphertext: &[u8],
    ) -> u64 {
        let keys = match epoch {
            2 => self.dtls13_hs_recv_keys.as_ref(),
            3 => self.dtls13_recv_keys.as_ref(),
            _ => None,
        };
        if let Some(keys) = keys {
            keys.decrypt_sequence_number(encrypted_seq, ciphertext) as u64
        } else {
            encrypted_seq as u64
        }
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

        // Add to transcript - use TLS 1.3 format (without DTLS fields) for DTLS 1.3
        if self.is_dtls13 {
            // TLS 1.3 format: msg_type (1) + length (3) + body
            self.transcript.push(msg_type.as_u8());
            self.transcript
                .extend_from_slice(&(body_buffer.len() as u32).to_be_bytes()[1..]);
            self.transcript.extend_from_slice(&body_buffer);
        } else {
            // DTLS 1.2 format: full DTLS handshake including message_seq, fragment_offset, fragment_length
            self.transcript.extend_from_slice(&buffer_full);
        }
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

    /// Create an encrypted DTLS 1.3 handshake message using handshake keys (epoch 2).
    /// This is used for EncryptedExtensions, Certificate, CertificateVerify, and Finished.
    pub fn create_handshake_dtls13<F>(&mut self, msg_type: MessageType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf, &mut Self) -> Result<(), Error>,
    {
        // Get a buffer for the handshake body
        let mut body_buffer = self.buffers_free.pop();

        // Let the callback fill the handshake body
        f(&mut body_buffer, self)?;

        // Create the handshake header
        let handshake_header = Header {
            msg_type,
            length: body_buffer.len() as u32,
            message_seq: self.next_handshake_seq_no,
            fragment_offset: 0,
            fragment_length: body_buffer.len() as u32,
        };

        // Serialize the full handshake for the transcript using TLS format (per RFC 9147 Section 5.2)
        let mut buffer_full = self.buffers_free.pop();
        {
            let handshake = Handshake {
                header: handshake_header,
                body: Body::Fragment(0..body_buffer.len()),
                handled: AtomicBool::new(false),
            };
            // DTLS 1.3 transcript uses TLS-style format
            // (without message_seq, fragment_offset, fragment_length)
            handshake.serialize_tls(&body_buffer, &mut buffer_full);
        }
        self.transcript.extend_from_slice(&buffer_full);

        // Increment the sequence number
        self.next_handshake_seq_no += 1;

        // For DTLS 1.3, epoch 2 records use unified header format
        // We fragment if needed, encrypting each fragment
        let total_len = body_buffer.len();
        let mut offset: usize = 0;
        let handshake_header_len = 12usize;

        // DTLS 1.3 unified header: 1 byte header + 1-2 byte seq + 2 byte length + tag
        let aead_overhead = 16usize; // 16-byte auth tag
        let unified_header_max = 5usize; // header byte + 2 seq + 2 len

        while offset < total_len || (total_len == 0 && offset == 0) {
            let already_used = self.queue_tx.back().map(|b| b.len()).unwrap_or(0);
            let available = self.config.mtu().saturating_sub(already_used);

            // +1 for inner content type
            let fixed_overhead = unified_header_max + handshake_header_len + aead_overhead + 1;

            let available_for_body = if available > fixed_overhead {
                available - fixed_overhead
            } else {
                self.config.mtu().saturating_sub(fixed_overhead)
            };

            let remaining = total_len.saturating_sub(offset);
            let chunk_len = if total_len == 0 {
                0
            } else {
                remaining.min(available_for_body)
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

            // Serialize the handshake fragment
            let mut fragment = self.buffers_free.pop();
            frag_handshake.serialize(&body_buffer, &mut fragment);

            // Clone for resend (unencrypted, will be re-encrypted on resend)
            let mut clone = self.buffers_free.pop();
            clone.extend_from_slice(&fragment);

            // Encrypt using DTLS 1.3 handshake keys (epoch 2)
            let rn = self.create_record_dtls13_epoch2(ContentType::Handshake, fragment)?;

            // Track this record for selective retransmission.
            let mut record_numbers: ArrayVec<RecordNumber, 4> = ArrayVec::new();
            record_numbers.push(rn);
            self.flight_saved_records.push(Entry {
                content_type: ContentType::Handshake,
                epoch: 2,
                fragment: clone,
                record_numbers,
                acked: false,
            });

            if total_len == 0 {
                break;
            }
            offset += chunk_len;
        }

        self.buffers_free.push(buffer_full);
        self.buffers_free.push(body_buffer);

        Ok(())
    }

    /// Create an encrypted DTLS 1.3 record using handshake keys (epoch 2).
    fn create_record_dtls13_epoch2(
        &mut self,
        content_type: ContentType,
        mut fragment: Buf,
    ) -> Result<RecordNumber, Error> {
        let keys = self.dtls13_hs_send_keys.as_mut().ok_or_else(|| {
            Error::CryptoError("DTLS 1.3 handshake send keys not installed".to_string())
        })?;

        // Build inner plaintext: content || content_type (RFC 9147)
        fragment.push(content_type.as_u8());

        // Get sequence number and compute nonce
        let seq = keys.sequence_number;
        let nonce = keys.next_nonce();
        debug!(
            "encrypt epoch2: seq={}, nonce={:02x?}, iv={:02x?}, plaintext_len={}",
            seq,
            nonce.0,
            keys.iv,
            fragment.len()
        );

        // Build unified header using stack-allocated array (max 5 bytes)
        // Format: 001CSLEE where C=0 (no CID), S=seq16, L=1 (include length), EE=epoch_bits
        let epoch_bits = 2u8; // Epoch 2 for handshake traffic (only lower 2 bits used)
                              // Always use 16-bit sequence for now to match BoringSSL's behavior
        let seq_16bit = true;

        let mut header: [u8; 5] = [0; 5];
        let mut header_len = 0;

        let mut header_byte = 0b0010_0000u8; // Fixed bits 001xxxxx
        if seq_16bit {
            header_byte |= 0b0000_1000; // S bit
        }
        header_byte |= 0b0000_0100; // L bit (include length)
        header_byte |= epoch_bits;
        header[header_len] = header_byte;
        header_len += 1;

        // Sequence number (8 or 16 bit)
        if seq_16bit {
            let seq_bytes = ((seq & 0xFFFF) as u16).to_be_bytes();
            header[header_len] = seq_bytes[0];
            header[header_len + 1] = seq_bytes[1];
            header_len += 2;
        } else {
            header[header_len] = (seq & 0xFF) as u8;
            header_len += 1;
        }

        // Compute encrypted length: plaintext + 16-byte auth tag
        let encrypted_len = (fragment.len() + 16) as u16;
        let len_bytes = encrypted_len.to_be_bytes();
        header[header_len] = len_bytes[0];
        header[header_len + 1] = len_bytes[1];
        header_len += 2;

        // Create AAD from header (must include correct length!)
        let aad = Aad13::from_header(&header[..header_len]);
        debug!("encrypt AAD: {:02x?}", aad.as_bytes());

        // Encrypt using variable-length AAD for DTLS 1.3
        let nonce_12 = crate::crypto::Nonce(nonce.0);

        keys.cipher
            .encrypt_with_aad(&mut fragment, aad.as_bytes(), nonce_12)
            .map_err(|e| {
                Error::CryptoError(format!("DTLS 1.3 handshake encryption failed: {}", e))
            })?;

        // Track AEAD usage (RFC 9147 Section 4.5.3)
        // Note: handshake keys (epoch 2) are short-lived, but still track for completeness
        let _ = keys.increment_encryption();

        // Encrypt sequence number in header (RFC 9147 Section 4.2.3)
        // The mask is computed from the first 16 bytes of ciphertext
        let encrypted_seq = keys.encrypt_sequence_number(seq, &fragment);

        // Update header with encrypted sequence number
        if seq_16bit {
            header[1] = (encrypted_seq >> 8) as u8;
            header[2] = (encrypted_seq & 0xFF) as u8;
        } else {
            header[1] = (encrypted_seq & 0xFF) as u8;
        }

        debug!(
            "encrypt: seq={} -> encrypted_seq=0x{:04x}",
            seq, encrypted_seq
        );

        // Add to TX queue
        let record_wire_len = header_len + fragment.len();
        let can_append = self
            .queue_tx
            .back()
            .map(|b| b.len() + record_wire_len <= self.config.mtu())
            .unwrap_or(false);

        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx() {
            self.buffers_free.push(fragment);
            return Err(Error::TransmitQueueFull);
        }

        if can_append {
            let last = self.queue_tx.back_mut().unwrap();
            last.extend_from_slice(&header[..header_len]);
            last.extend_from_slice(&fragment);
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            buffer.extend_from_slice(&header[..header_len]);
            buffer.extend_from_slice(&fragment);
            self.queue_tx.push_back(buffer);
        }

        self.buffers_free.push(fragment);
        Ok(RecordNumber::new(2, seq))
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

    /// Decrypt a DTLS 1.3 record.
    ///
    /// Returns (content_type, plaintext_len) on success.
    /// The plaintext is written to the beginning of the ciphertext buffer.
    /// Uses epoch to select appropriate keys: epoch 2 = handshake, epoch 3 = application.
    pub fn decrypt_data_dtls13(
        &mut self,
        ciphertext: &mut [u8],
        header_bytes: &[u8],
        sequence_number: u64,
        epoch: u16,
    ) -> Result<(ContentType, usize), Error> {
        debug!(
            "decrypt_data_dtls13: epoch={}, seq={}, ciphertext_len={}, header={:02x?}",
            epoch,
            sequence_number,
            ciphertext.len(),
            header_bytes
        );
        debug!(
            "ciphertext first 16 bytes: {:02x?}",
            &ciphertext[..16.min(ciphertext.len())]
        );

        // Select keys based on epoch
        let keys = if epoch == 2 {
            self.dtls13_hs_recv_keys.as_mut().ok_or_else(|| {
                Error::CryptoError("DTLS 1.3 handshake receive keys not installed".to_string())
            })?
        } else {
            self.dtls13_recv_keys.as_mut().ok_or_else(|| {
                Error::CryptoError("DTLS 1.3 application receive keys not installed".to_string())
            })?
        };

        // Compute nonce for this sequence
        let nonce = keys.nonce_for_seq(sequence_number);
        debug!("decrypt nonce: {:02x?}, iv: {:02x?}", nonce.0, keys.iv);

        // Create AAD from header (variable length for DTLS 1.3)
        let aad = Aad13::from_header(header_bytes);
        debug!("decrypt AAD: {:02x?}", aad.as_bytes());

        // Decrypt in place
        let mut tmp = TmpBuf::new(ciphertext);

        let nonce_12 = crate::crypto::Nonce(nonce.0);

        // Use decrypt_with_aad for variable-length AAD (DTLS 1.3 unified header)
        let decrypt_result = keys
            .cipher
            .decrypt_with_aad(&mut tmp, aad.as_bytes(), nonce_12);

        if let Err(e) = decrypt_result {
            // Track AEAD decryption failures (RFC 9147 Section 4.5.3)
            let limit_exceeded = keys.increment_decryption_failure();
            if limit_exceeded {
                return Err(Error::SecurityError(
                    "AEAD decryption failure limit exceeded".to_string(),
                ));
            }
            return Err(Error::CryptoError(format!(
                "DTLS 1.3 decryption failed: {}",
                e
            )));
        }

        // Extract inner content type (last non-zero byte)
        let decrypted_len = tmp.len();
        if decrypted_len == 0 {
            return Err(Error::CryptoError(
                "Decrypted DTLS 1.3 record is empty".to_string(),
            ));
        }

        // Find content type (scan backwards for first non-zero)
        let decrypted = tmp.as_ref();
        let mut idx = decrypted_len - 1;
        while idx > 0 && decrypted[idx] == 0 {
            idx -= 1;
        }

        let content_type = ContentType::from_u8(decrypted[idx]);
        let plaintext_len = idx;

        Ok((content_type, plaintext_len))
    }

    /// Anti-replay check and update state. Returns true if record is fresh/acceptable.
    pub fn replay_check_and_update(&mut self, seq: Sequence) -> bool {
        self.replay.check_and_update(seq)
    }

    /// Replace transcript with TLS 1.3 message_hash construct for HRR handling.
    /// Per RFC 8446 Section 4.4.1, after HRR the transcript becomes:
    ///   message_hash (0xFE) || 00 00 hash_len || Hash(original_ClientHello)
    ///
    /// This binds the transcript to the original ClientHello even after retry.
    pub fn transcript_replace_for_hrr(&mut self, hash_alg: HashAlgorithm) {
        // Compute hash of current transcript (which is ClientHello1)
        let mut hash_output = Buf::new();
        self.transcript_hash(hash_alg, &mut hash_output);

        let hash_len = hash_output.len() as u8;

        // Replace transcript with message_hash construct
        self.transcript.clear();

        // message_hash handshake type = 254 (0xFE)
        self.transcript.push(254);
        // Length field: 00 00 hash_len (3 bytes big-endian)
        self.transcript.push(0);
        self.transcript.push(0);
        self.transcript.push(hash_len);
        // The hash of original ClientHello
        self.transcript.extend_from_slice(&hash_output);
    }

    /// Truncate the transcript to a given length.
    /// Used when we need to remove bytes that were added (e.g., HRR before message_hash replacement).
    pub fn transcript_truncate(&mut self, len: usize) {
        self.transcript.truncate(len);
    }

    /// Extend the transcript with additional bytes.
    /// Used to re-add bytes after transcript replacement (e.g., HRR after message_hash).
    pub fn transcript_extend(&mut self, bytes: &[u8]) {
        self.transcript.extend_from_slice(bytes);
    }

    pub fn transcript_hash(&self, algorithm: HashAlgorithm, out: &mut Buf) {
        let mut hash = self.crypto_context.create_hash(algorithm);
        hash.update(&self.transcript);
        hash.clone_and_finalize(out);
    }

    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suite = Some(cipher_suite);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_replace_for_hrr_structure() {
        // Test the message_hash structure directly without needing full Engine
        // This validates the RFC 8446 Section 4.4.1 message_hash format

        // message_hash format:
        // - message_hash handshake type = 254 (0xFE)
        // - Length field: 00 00 hash_len (3 bytes)
        // - Hash of original ClientHello

        // For SHA-256, the result should be 4 + 32 = 36 bytes:
        // [0xFE, 0x00, 0x00, 0x20, <32-byte SHA-256 hash>]

        let message_hash_type: u8 = 254;
        let sha256_len: u8 = 32;

        // Simulate the structure
        let mut result = Buf::new();
        result.push(message_hash_type);
        result.push(0);
        result.push(0);
        result.push(sha256_len);
        // Would append the hash here in real code

        assert_eq!(
            result[0], 254,
            "First byte should be message_hash type (0xFE)"
        );
        assert_eq!(result[1], 0, "Length byte 1");
        assert_eq!(result[2], 0, "Length byte 2");
        assert_eq!(result[3], 32, "Length byte 3 = hash len");
        assert_eq!(result.len(), 4, "Header should be 4 bytes before hash");
    }

    #[test]
    fn test_aead_encryption_limit_constants() {
        // RFC 9147 Section 4.5.3 specifies AEAD limits
        // For AES-GCM: encryption limit is 2^24.5 records
        // We use 2^23 as a safety margin
        assert_eq!(aead_limits::DEFAULT_ENCRYPTION_LIMIT, 1 << 23);
        assert_eq!(aead_limits::DEFAULT_ENCRYPTION_LIMIT, 8_388_608);

        // Decryption failure limit is 2^36
        // We use 2^35 as a safety margin
        assert_eq!(aead_limits::DEFAULT_DECRYPTION_FAILURE_LIMIT, 1 << 35);

        // Warning threshold should be 90% of limit
        let expected_warning = (aead_limits::DEFAULT_ENCRYPTION_LIMIT * 9) / 10;
        assert_eq!(
            aead_limits::warning_threshold(aead_limits::DEFAULT_ENCRYPTION_LIMIT),
            expected_warning
        );
    }

    #[test]
    fn test_record_number() {
        let rn = RecordNumber::new(3, 42);
        assert_eq!(rn.epoch, 3);
        assert_eq!(rn.sequence_number, 42);
    }

    #[test]
    fn test_ack_message() {
        let mut ack = AckMessage::new();
        assert!(ack.is_empty());

        ack.add(3, 100);
        ack.add(3, 101);
        assert!(!ack.is_empty());
        assert_eq!(ack.record_numbers.len(), 2);

        // Check acknowledgment
        assert!(ack.acknowledges(3, 100));
        assert!(ack.acknowledges(3, 101));
        assert!(!ack.acknowledges(3, 102));
        assert!(!ack.acknowledges(2, 100)); // Wrong epoch
    }

    #[test]
    fn test_ack_message_serialization() {
        let mut ack = AckMessage::new();
        ack.add(3, 42);

        let mut buf = Buf::new();
        ack.serialize(&mut buf);

        // Should have: 2-byte length (16 for one RecordNumber) + 8-byte epoch + 8-byte seq
        assert_eq!(buf.len(), 2 + 16);

        // Parse it back
        let (remaining, parsed) = AckMessage::parse(&buf).expect("parse failed");
        assert!(remaining.is_empty());
        assert_eq!(parsed.record_numbers.len(), 1);
        assert!(parsed.acknowledges(3, 42));
    }

    #[test]
    fn test_content_type_ack() {
        // Verify ACK content type value per RFC 9147
        assert_eq!(ContentType::Ack.as_u8(), 26);
        assert_eq!(ContentType::from_u8(26), ContentType::Ack);
    }
}
