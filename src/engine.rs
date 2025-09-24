use rand::{rngs::OsRng, RngCore};
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::buffer::{Buf, BufferPool};
use crate::crypto::{Aad, CertVerifier, CryptoContext, Hash};
use crate::crypto::{Iv, KeyingMaterial, DTLS_AEAD_OVERHEAD};
use crate::crypto::{Nonce, SrtpProfile, DTLS_EXPLICIT_NONCE_LEN};
use crate::incoming::{Incoming, Record};
use crate::message::{Body, HashAlgorithm, Header, MessageType, ProtocolVersion, Sequence};
use crate::message::{CipherSuite, ContentType, DTLSRecord, Handshake};
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

    /// Counters for epoch 1 and beyond.
    sequence_epoch_n: Sequence,

    /// Queue of incoming packets.
    ///
    /// Not decrypted but handshakes are parsed.
    queue_rx: VecDeque<Incoming>,

    /// Queue of outgoing packets.
    queue_tx: VecDeque<Buf<'static>>,

    /// Queue of Output events
    queue_events: VecDeque<Output<'static>>,

    /// Holder of last packet. To be able to return a reference.
    last_packet: Option<Buf<'static>>,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<CipherSuite>,

    /// Cryptographic context for handling encryption/decryption
    crypto_context: CryptoContext,

    /// Whether the remote peer has enabled encryption
    peer_encryption_enabled: bool,

    /// Whether this engine is for a client (true) or server (false)
    is_client: bool,

    /// Expected peer handshake sequence number
    peer_handshake_seq_no: u16,

    /// Next handshake message sequence number for sending
    next_handshake_seq_no: u16,

    /// Handshakes collected for hash computation.
    transcript: Buf<'static>,

    /// Anti-replay window state (per current epoch)
    replay: ReplayWindow,

    /// Whether the flight timers are active. This turns off once
    /// the connection is established.
    flight_timers_active: bool,

    /// Flight backoff
    flight_backoff: ExponentialBackoff,

    /// Timeout for the current flight
    flight_timeout: Option<Instant>,

    /// Global timeout for the entire connect operation.
    connect_timeout: Option<Instant>,
}

impl Engine {
    pub fn new(
        config: Arc<Config>,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
    ) -> Self {
        let flight_backoff =
            ExponentialBackoff::new(config.flight_start_rto, config.flight_retries);

        Self {
            config,
            buffers_free: BufferPool::default(),
            sequence_epoch_0: Sequence::new(0),
            sequence_epoch_n: Sequence::new(1),
            queue_rx: VecDeque::new(),
            queue_tx: VecDeque::new(),
            queue_events: VecDeque::new(),
            last_packet: None,
            cipher_suite: None,
            crypto_context: CryptoContext::new(certificate, private_key, cert_verifier),
            peer_encryption_enabled: false,
            is_client: false,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            transcript: Buf::new(),
            replay: ReplayWindow::new(),
            flight_timers_active: true,
            flight_backoff,
            flight_timeout: None,
            connect_timeout: None,
        }
    }

    pub fn set_client(&mut self, is_client: bool) {
        self.is_client = is_client;
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
        self.config.cipher_suites.contains(&suite)
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
        let buffer = self.buffers_free.pop();

        let incoming = Incoming::parse_packet(packet, self, buffer)?;
        self.insert_incoming(incoming)?;

        Ok(())
    }

    /// Insert the Incoming using the logic:
    ///
    /// 1. If it is a handshake, sort by the message_seq
    /// 2. If it is not a handshake, sort by sequence_number
    ///
    fn insert_incoming(&mut self, incoming: Incoming) -> Result<(), Error> {
        let first = incoming.first();

        // Check if the queue has reached the maximum size
        if self.queue_rx.len() >= self.config.max_queue_rx {
            return Err(Error::ReceiveQueueFull);
        }

        if let Some(h) = first.handshake() {
            if let Err(index) = self.queue_rx.binary_search_by(|i| {
                let other = i
                    .first()
                    .handshake()
                    .as_ref()
                    .map(|h| (h.header.message_seq, h.header.fragment_offset))
                    .unwrap_or((u16::MAX, u32::MAX));
                let current = (h.header.message_seq, h.header.fragment_offset);
                other.cmp(&current)
            }) {
                // Insert in order of handshake
                self.queue_rx.insert(index, incoming);
            } else {
                // We have already received this exact handshake packet.
                // Ignore the new one.
                debug!(
                    "Dupe handshake with message_seq: {} and offset: {}",
                    h.header.message_seq, h.header.fragment_offset
                );
            }
        } else if let Err(index) = self
            .queue_rx
            .binary_search_by_key(&first.record().sequence, |i| i.first().record().sequence)
        {
            // Insert in order of sequence_number
            self.queue_rx.insert(index, incoming);
        } else {
            debug!("Dupe record with sequence: {}", first.record().sequence);
        }

        Ok(())
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if self.connect_timeout.is_none() {
            self.connect_timeout = Some(now + self.config.handshake_timeout);
        }
        if self.flight_timeout.is_none() {
            self.flight_timeout = Some(now + self.flight_backoff.rto());
        }

        // Unwrap is ok because we set it above
        let connect_timeout = self.connect_timeout.as_mut().unwrap();
        let flight_timeout = self.flight_timeout.as_mut().unwrap();

        if now >= *connect_timeout {
            return Err(Error::Timeout("connect"));
        }

        if now >= *flight_timeout {
            if self.flight_backoff.can_retry() {
                self.flight_backoff.attempt();
                self.flight_timeout = Some(now + self.flight_backoff.rto());
                self.flight_resend();
            } else {
                return Err(Error::Timeout("handshake"));
            }
        }

        Ok(())
    }

    pub fn poll_output(&mut self, now: Instant) -> Output {
        // Do we need a handle_timeout()?
        if self.flight_timeout.is_none() {
            return Output::Timeout(now);
        }

        // First check if we have any events
        if let Some(event) = self.queue_events.pop_front() {
            return event;
        }

        let next_timeout = self.poll_timeout(now);

        if let Some(packet) = self.poll_packet_tx() {
            return Output::Packet(packet);
        }

        Output::Timeout(next_timeout)
    }

    fn poll_timeout(&self, now: Instant) -> Instant {
        if !self.flight_timers_active {
            const DISTANT_FUTURE: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
            return now + DISTANT_FUTURE;
        }

        let Some(next_flight_timeout) = self.flight_timeout else {
            return now;
        };
        let Some(handshake_timeout) = self.flight_timeout else {
            return now;
        };

        if next_flight_timeout < handshake_timeout {
            next_flight_timeout
        } else {
            handshake_timeout
        }
    }

    fn poll_packet_tx(&mut self) -> Option<&[u8]> {
        // If there is a previous packet, return it to the pool.
        if let Some(last) = self.last_packet.take() {
            self.buffers_free.push(last);
        }

        let buffer = self.queue_tx.pop_front()?;
        self.last_packet = Some(buffer);

        // unwrap is ok because we set it right now.
        let p = self.last_packet.as_ref().unwrap();

        Some(p)
    }

    pub fn begin_flight(&mut self, flight_no: u8) {
        debug!("Beginning flight {}", flight_no);
        self.flight_backoff.reset();
        self.flight_timeout = None;
    }

    fn flight_resend(&mut self) {
        //
    }

    pub fn stop_flight_resends(&mut self) {
        self.flight_timers_active = false;
        self.flight_timeout = None;
        self.connect_timeout = None;
    }

    pub fn has_complete_handshake(&mut self, wanted: MessageType) -> bool {
        let maybe_first_handshake = self
            .queue_rx
            .front()
            .and_then(|i| i.records().iter().find(|r| !r.is_handled()))
            .and_then(|r| r.handshake());

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

        // Cap to MAX_DEFRAGMENT_PACKETS to avoid misbehaving peers
        for incoming in self.queue_rx.iter().take(MAX_DEFRAGMENT_PACKETS) {
            for record in incoming.records().iter() {
                if let Some(h) = &record.handshake() {
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
            }
        }

        false
    }

    pub fn next_handshake<'b>(
        &mut self,
        wanted: MessageType,
        defragment_buffer: &'b mut Buf<'static>,
    ) -> Result<Option<Handshake<'b>>, Error> {
        self.purge_queue_rx();

        if !self.has_complete_handshake(wanted) {
            return Ok(None);
        }

        let iter = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter().filter_map(|r| r.handshake()))
            // Handled in previous iteration
            .skip_while(|h| h.handled.get());

        // This sets the handled flag on the handshake.
        let handshake = Handshake::defragment(iter, defragment_buffer, self.cipher_suite)?;

        // Update the stored handshakes used for CertificateVerify and Finished
        handshake.serialize(&mut self.transcript);

        // Move the expected seq_no along
        self.peer_handshake_seq_no = handshake.header.message_seq + 1;

        Ok(Some(handshake))
    }

    pub(crate) fn next_record(&mut self, ctype: ContentType) -> Option<&Record> {
        self.purge_queue_rx();

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

    // Purge completely handled packets. We can only purge the Incoming if all the
    // Handshake in it are handled.
    fn purge_queue_rx(&mut self) {
        while let Some(incoming) = self.queue_rx.front() {
            // Records/handshakes are marked as handled, which means they should be skipped
            // from further processing.
            let all_handled = incoming.records().iter().all(|r| r.is_handled());

            if all_handled {
                let _ = self.queue_rx.pop_front();
            } else {
                break;
            }
        }
    }

    /// Create a DTLS record and serialize it into a buffer
    pub fn create_record<F>(
        &mut self,
        content_type: ContentType,
        epoch: u16,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf<'static>),
    {
        // Prepare the plaintext fragment
        let mut fragment = self.buffers_free.pop();

        // Let the caller fill the fragment (plaintext)
        f(&mut fragment);

        // Compute wire length of the record if serialized into a datagram
        // Record header (13) + handshake/change/app data bytes + AEAD overhead (if epoch >= 1)
        let overhead = if epoch >= 1 { DTLS_AEAD_OVERHEAD } else { 0 };
        let record_wire_len = DTLSRecord::HEADER_LEN + fragment.len() + overhead;

        // Decide whether to append to the existing last datagram or create a new one
        let can_append = self
            .queue_tx
            .back()
            .map(|b| b.len() + record_wire_len <= self.config.mtu)
            .unwrap_or(false);

        // If we cannot append, ensure we have space for a new datagram
        if !can_append && self.queue_tx.len() >= self.config.max_queue_tx {
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
            let mut explicit_nonce = [0u8; 8];
            OsRng.fill_bytes(&mut explicit_nonce);

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
            fragment: &mut fragment,
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
            record.serialize(last);
        } else {
            let mut buffer = self.buffers_free.pop();
            buffer.clear();
            record.serialize(&mut buffer);
            self.queue_tx.push_back(buffer);
        }

        // Return the fragment buffer to the pool
        self.buffers_free.push(fragment);

        Ok(())
    }

    /// Create a handshake message and wrap it in a DTLS record
    pub fn create_handshake<F>(&mut self, msg_type: MessageType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Buf<'static>, &mut Self) -> Result<(), Error>,
    {
        // Get a buffer for the handshake body
        let mut body_buffer = self.buffers_free.pop();

        // Let the callback fill the handshake body
        f(&mut body_buffer, self)?;

        // Create the handshake header with the next sequence number
        let handshake = Handshake {
            header: Header {
                msg_type,
                length: body_buffer.len() as u32,
                message_seq: self.next_handshake_seq_no,
                fragment_offset: 0,
                fragment_length: body_buffer.len() as u32,
            },
            body: Body::Fragment(&body_buffer),
            handled: Cell::new(false),
        };

        let mut buffer_full = self.buffers_free.pop();
        handshake.serialize(&mut buffer_full);
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
            let available_in_current = self.config.mtu.saturating_sub(already_used_in_current);

            // Fixed overhead per handshake record on the wire:
            // DTLS record header + handshake header + AEAD overhead (if epoch >= 1)
            let fixed_overhead = DTLSRecord::HEADER_LEN + handshake_header_len + aead_overhead;

            // Prefer to pack into the current datagram. If the current one cannot fit even
            // the fixed overhead, we will start a fresh datagram and compute space again.
            let available_for_body = if available_in_current >= fixed_overhead {
                available_in_current - fixed_overhead
            } else {
                self.config.mtu.saturating_sub(fixed_overhead)
            };

            // Remaining bytes from the handshake body we still need to send.
            let remaining_body_bytes = total_len.saturating_sub(offset);

            // For empty-body handshakes (e.g., ServerHelloDone), we still send a header-only record.
            let chunk_len = if total_len == 0 {
                0
            } else {
                remaining_body_bytes.min(available_for_body)
            };

            let frag_body = if chunk_len == 0 {
                &[][..]
            } else {
                &body_buffer[offset..offset + chunk_len]
            };

            let frag_handshake = Handshake {
                header: Header {
                    msg_type,
                    length: handshake.header.length,
                    message_seq: handshake.header.message_seq,
                    fragment_offset: offset as u32,
                    fragment_length: chunk_len as u32,
                },
                body: Body::Fragment(frag_body),
                handled: Cell::new(false),
            };

            // Emit the record; packing into current datagram happens inside create_record
            self.create_record(ContentType::Handshake, epoch, |fragment| {
                frag_handshake.serialize(fragment);
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

    /// Process application data packets from the incoming queue
    /// Returns true if any application data was processed
    pub fn process_application_data(&mut self) -> Result<bool, Error> {
        let mut processed_any = false;
        // Process any incoming packets with application data
        while let Some(incoming) = self.queue_rx.pop_front() {
            let records = incoming.records();

            for i in 0..records.len() {
                let record = &records[i];
                if record.record().content_type == ContentType::ApplicationData {
                    // This is already decrypted as part of the parsing.
                    let plaintext = record.record().fragment.to_vec();

                    // Push the decrypted data to the queue
                    self.queue_events
                        .push_back(Output::ApplicationData(plaintext));
                    processed_any = true;
                }
            }
        }
        Ok(processed_any)
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
        ciphertext: &mut Buf,
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

    /// Push a Connected event to the queue
    pub fn push_connected(&mut self) {
        self.queue_events.push_back(Output::Connected);
    }

    /// Push a PeerCert event to the queue
    pub fn push_peer_cert(&mut self, cert_data: Vec<u8>) {
        self.queue_events.push_back(Output::PeerCert(cert_data));
    }

    /// Push a KeyingMaterial event to the queue
    pub fn push_keying_material(&mut self, keying_material: KeyingMaterial, profile: SrtpProfile) {
        self.queue_events
            .push_back(Output::KeyingMaterial(keying_material, profile));
    }

    pub fn transcript_reset(&mut self) {
        self.transcript.clear();
    }

    pub fn transcript_hash(&self, algorithm: HashAlgorithm) -> Vec<u8> {
        let mut hash = Hash::new(algorithm);
        hash.update(&self.transcript);
        hash.clone_and_finalize()
    }

    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suite = Some(cipher_suite);
    }

    pub fn enable_peer_encryption(&mut self) -> Result<(), Error> {
        debug!("Peer encryption enabled");
        self.peer_encryption_enabled = true;

        // Make doubly sure all fully used entries are gone.
        self.purge_queue_rx();

        // Now decrypt all entries remaining.
        let all = self.queue_rx.split_off(0);

        for incoming in all {
            // Part of the incoming buffer has already been handled since
            // the ChangeCipherSpec happens mid-flight.
            let offset = incoming
                .records()
                .iter()
                .take_while(|r| r.is_handled())
                .map(|r| r.len())
                .sum::<usize>();

            let mut buffer = incoming.into_owner();

            // This has already been used up and does not need decrypting.
            let _ = buffer.drain(..offset);

            self.parse_packet(&buffer)?;
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

    pub fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord) -> (Aad, Nonce) {
        // DTLS 1.2 AEAD (AES-GCM): AAD uses the plaintext length. The fragment on the wire is
        // 8-byte explicit nonce || ciphertext || 16-byte GCM tag. Recover plaintext length from
        // the record header's fragment length field.
        let plaintext_len = dtls.length.saturating_sub(DTLS_AEAD_OVERHEAD as u16);
        let aad = Aad::new(dtls.content_type, dtls.sequence, plaintext_len);
        let iv = self.peer_iv();
        let nonce = Nonce::new(iv, dtls.nonce());
        (aad, nonce)
    }

    pub fn generate_verify_data(&self, is_client: bool) -> Result<[u8; 12], Error> {
        let Some(suite) = self.cipher_suite() else {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            ));
        };
        let algorithm = suite.hash_algorithm();
        let handshake_hash = self.transcript_hash(algorithm);

        let suite_hash = suite.hash_algorithm();
        let verify_data_vec = self
            .crypto_context()
            .generate_verify_data(&handshake_hash, is_client, suite_hash)
            .map_err(|e| Error::CryptoError(format!("Failed to generate verify data: {}", e)))?;

        if verify_data_vec.len() != 12 {
            return Err(Error::CryptoError("Invalid verify data length".to_string()));
        }

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&verify_data_vec);

        Ok(verify_data)
    }
}
