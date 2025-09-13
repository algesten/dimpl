use rand::RngCore;
use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::buffer::{Buffer, BufferPool};
use crate::crypto::{
    Aad, CertVerifier, CryptoContext, Hash, Iv, KeyingMaterial, Nonce, SrtpProfile,
};
use crate::incoming::Incoming;
use crate::message::{
    CipherSuite, ContentType, DTLSRecord, Handshake, HashAlgorithm, MessageType, ProtocolVersion,
    Sequence,
};
use crate::{Config, Error, Output};

const MAX_DEFRAGMENT_PACKETS: usize = 50;

// Using debug_ignore_primary since CryptoContext doesn't implement Debug
pub struct Engine {
    config: Arc<Config>,

    /// Pool of buffers
    buffers_free: BufferPool,

    /// Counters for sending DTLSRecord.
    next_sequence_tx: Sequence,

    /// Queue of incoming packets.
    queue_rx: VecDeque<Incoming>,

    /// Queue of outgoing packets.
    queue_tx: VecDeque<Buffer>,

    /// Queue of Output events
    queue_events: VecDeque<Output<'static>>,

    /// Holder of last packet. To be able to return a reference.
    last_packet: Option<Buffer>,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<CipherSuite>,

    /// Cryptographic context for handling encryption/decryption
    crypto_context: CryptoContext,

    /// Server encryption enabled flag
    server_encryption_enabled: bool,

    /// Client encryption enabled flag
    client_encryption_enabled: bool,

    /// Whether this engine is for a client (true) or server (false)
    is_client: bool,

    /// Expected peer handshake sequence number
    peer_handshake_seq_no: u16,

    /// Next handshake message sequence number for sending
    next_handshake_seq_no: u16,

    /// Handshakes collected for hash computation.
    handshakes: Vec<u8>,
}

impl Engine {
    pub fn new(
        config: Arc<Config>,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
        is_client: bool,
    ) -> Self {
        Self {
            config,
            buffers_free: BufferPool::default(),
            next_sequence_tx: Sequence::default(),
            queue_rx: VecDeque::new(),
            queue_tx: VecDeque::new(),
            queue_events: VecDeque::new(),
            last_packet: None,
            cipher_suite: None,
            crypto_context: CryptoContext::new(certificate, private_key, cert_verifier),
            server_encryption_enabled: false,
            client_encryption_enabled: false,
            is_client,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            handshakes: Vec::with_capacity(10 * 1024),
        }
    }

    /// Get a reference to the cipher suite
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    /// Get a reference to the crypto context
    pub fn crypto_context(&self) -> &CryptoContext {
        &self.crypto_context
    }

    /// Get a mutable reference to the crypto context
    pub fn crypto_context_mut(&mut self) -> &mut CryptoContext {
        &mut self.crypto_context
    }

    /// Enable server encryption
    pub fn enable_server_encryption(&mut self) {
        self.server_encryption_enabled = true;

        // Start epoch 1 for server
        if !self.is_client {
            self.next_sequence_tx.epoch = 1;
            self.next_sequence_tx.sequence_number = 0;
        }
    }

    /// Enable client encryption
    pub fn enable_client_encryption(&mut self) {
        self.client_encryption_enabled = true;

        // Start epoch 1 for client
        if self.is_client {
            self.next_sequence_tx.epoch = 1;
            self.next_sequence_tx.sequence_number = 0;
        }
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
            match self.queue_rx.binary_search_by(|i| {
                let other = i
                    .first()
                    .handshake()
                    .as_ref()
                    .map(|h| (h.header.message_seq, h.header.fragment_offset))
                    .unwrap_or((u16::MAX, u32::MAX));
                let current = (h.header.message_seq, h.header.fragment_offset);
                other.cmp(&current)
            }) {
                Ok(_) => {
                    // We have already received this exact handshake packet.
                    // Ignore the new one.
                    debug!(
                        "Dupe handshake with message_seq: {} and offset: {}",
                        h.header.message_seq, h.header.fragment_offset
                    );
                }
                Err(index) => {
                    // Insert in order of handshake
                    self.queue_rx.insert(index, incoming);
                }
            }
        } else {
            match self
                .queue_rx
                .binary_search_by_key(&first.record().sequence, |i| i.first().record().sequence)
            {
                Ok(_) => {
                    debug!("Dupe record with sequence: {}", first.record().sequence);
                }
                Err(index) => {
                    // Insert in order of sequence_number
                    self.queue_rx.insert(index, incoming);
                }
            }
        }

        Ok(())
    }

    pub fn poll_packet_tx(&mut self) -> Option<&[u8]> {
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

    pub fn poll_output(&mut self) -> Output {
        // First check if we have any events
        if let Some(event) = self.queue_events.pop_front() {
            return event;
        }

        let next_timeout = self.poll_timeout();

        if let Some(packet) = self.poll_packet_tx() {
            return Output::Packet(packet);
        }

        Output::Timeout(next_timeout)
    }

    fn poll_timeout(&self) -> Instant {
        Instant::now()
    }

    pub fn has_flight(&mut self, to: MessageType) -> Option<Flight> {
        if self.queue_rx.is_empty() {
            return None;
        }

        let first = self.queue_rx.front().unwrap().first().handshake()?;

        if first.header.message_seq != self.peer_handshake_seq_no {
            return None;
        }

        let mut current_seq = first.header.message_seq;
        let mut found_end = false;
        let mut last_fragment_end = 0;

        // Cap to MAX_DEFRAGMENT_PACKETS to avoid misbehaving peers
        for incoming in self.queue_rx.iter().take(MAX_DEFRAGMENT_PACKETS) {
            for record in incoming.records().iter() {
                if let Some(h) = &record.handshake() {
                    // Check message sequence contiguity
                    if h.header.message_seq != current_seq {
                        // Reset fragment tracking for new message sequence
                        last_fragment_end = 0;
                        current_seq = h.header.message_seq;
                    }

                    // Check fragment contiguity
                    if h.header.fragment_offset > 0 && h.header.fragment_offset != last_fragment_end
                    {
                        return None;
                    }
                    last_fragment_end = h.header.fragment_offset + h.header.fragment_length;

                    if h.header.msg_type == to {
                        found_end = true;
                        break;
                    }
                }
            }
            if found_end {
                break;
            }
        }

        if !found_end {
            return None;
        }

        Some(Flight {
            to,
            current: Some(first.header.msg_type),
        })
    }

    pub fn next_from_flight<'b>(
        &mut self,
        flight: &mut Flight,
        defragment_buffer: &'b mut Vec<u8>,
    ) -> Result<Option<Handshake<'b>>, Error> {
        if flight.current.is_none() {
            return Ok(None);
        }

        let iter = self
            .queue_rx
            .iter()
            .flat_map(|i| i.records().iter().filter_map(|r| r.handshake()))
            // Handled in previous iteration
            .skip_while(|h| h.handled.get());

        let (handshake, next_type) =
            Handshake::defragment(iter, defragment_buffer, self.cipher_suite)?;

        // Update the stored handshakes used for CertificateVerify and Finished
        handshake.serialize(&mut self.handshakes);

        // Update the flight with the next message type, this eventually returns None
        // and that makes the flight complete.
        flight.current = if flight.current == Some(flight.to) {
            // We reached the end condition
            None
        } else {
            // There might be another message after this one
            next_type
        };

        // Purge completely handled packets. We can only purge the Incoming if all the
        // Handshake in it are handled.
        while let Some(incoming) = self.queue_rx.front() {
            let all_handled = incoming
                .records()
                .iter()
                .filter_map(|r| r.handshake())
                .all(|h| h.handled.get());

            if all_handled {
                let incoming = self.queue_rx.pop_front().unwrap();

                // The last handled handshake
                let last_handshake = incoming.last().handshake().unwrap();

                // Move the expected sequence number
                self.peer_handshake_seq_no = last_handshake.header.message_seq + 1;
            } else {
                break;
            }
        }

        Ok(Some(handshake))
    }

    /// Get the next incoming packet
    pub fn next_incoming(&mut self) -> Option<Incoming> {
        self.queue_rx.pop_front()
    }

    /// Create a DTLS record and serialize it into a buffer
    pub fn create_record<F>(&mut self, content_type: ContentType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Vec<u8>) -> Option<MessageType>,
    {
        // Check if the queue has reached the maximum size before creating a new buffer
        if self.queue_tx.len() >= self.config.max_queue_tx {
            return Err(Error::TransmitQueueFull);
        }

        let mut buffer = self.buffers_free.pop();
        let mut fragment = self.buffers_free.pop();

        // Let the callback fill the fragment
        let maybe_msg_type = f(&mut fragment);

        // As long as we're handshaking, update the hash with the fragment.
        if maybe_msg_type.is_some() {
            self.handshakes.extend_from_slice(&fragment);
        }

        let sequence = self.next_sequence_tx;
        let length = fragment.len() as u16;

        // Handle encryption if enabled and content type requires it
        if self.should_encrypt(content_type) {
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
            rand::thread_rng().fill_bytes(&mut explicit_nonce);

            // Combine the fixed IV and the explicit nonce
            let nonce = Nonce::new(iv, &explicit_nonce);

            // Create proper AAD for encryption - for encrypted records, we need to use
            // the length after encryption (plaintext + 16 bytes tag for AES-GCM)
            let final_length = length; // + 16; // Add 16 bytes for auth tag
            let aad = Aad::new(content_type, sequence, final_length);

            // Encrypt the fragment in-place
            self.encrypt_data(&mut fragment, aad, nonce)?;

            // Create a new buffer that includes the explicit nonce
            let mut encrypted_fragment = Vec::with_capacity(explicit_nonce.len() + fragment.len());
            encrypted_fragment.extend_from_slice(&explicit_nonce);
            encrypted_fragment.extend_from_slice(&fragment);

            // Replace the original fragment with the nonce + encrypted data
            fragment.clear();
            fragment.extend_from_slice(&encrypted_fragment);
        }

        let record = DTLSRecord {
            content_type,
            version: ProtocolVersion::DTLS1_2,
            sequence,
            length: fragment.len() as u16,
            fragment: &mut fragment,
        };

        // Increment the sequence number for the next transmission
        self.next_sequence_tx.sequence_number += 1;

        // Serialize the record into the buffer
        let mut serialized = Vec::new();
        record.serialize(&mut serialized);

        // Copy the serialized data to the buffer
        buffer.resize(serialized.len(), 0);
        buffer.copy_from_slice(&serialized);

        // Add to the outgoing queue
        self.queue_tx.push_back(buffer);

        // We can reuse this buffer.
        self.buffers_free.push(fragment);

        Ok(())
    }

    /// Create a handshake message and wrap it in a DTLS record
    pub fn create_handshake<F>(&mut self, msg_type: MessageType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Vec<u8>),
    {
        // Create a buffer for the handshake body
        let mut body_buffer = Vec::new();

        // Let the callback fill the handshake body
        f(&mut body_buffer);

        // Create the handshake header with the next sequence number
        let handshake = Handshake {
            header: crate::message::Header {
                msg_type,
                length: body_buffer.len() as u32,
                message_seq: self.next_handshake_seq_no,
                fragment_offset: 0,
                fragment_length: body_buffer.len() as u32,
            },
            body: crate::message::Body::Fragment(&body_buffer),
            handled: Cell::new(false),
        };

        // Increment the sequence number for the next handshake message
        self.next_handshake_seq_no += 1;

        // Now create the record with the serialized handshake
        self.create_record(ContentType::Handshake, |fragment| {
            handshake.serialize(fragment);
            Some(msg_type)
        })
    }

    /// Process application data packets from the incoming queue
    pub fn process_application_data(&mut self) -> Result<(), Error> {
        // Process any incoming packets with application data
        while let Some(incoming) = self.next_incoming() {
            let records = incoming.records();

            for i in 0..records.len() {
                let record = &records[i];
                if record.record().content_type == ContentType::ApplicationData {
                    // Check if we have enough data for the explicit nonce (8 bytes) plus some content
                    if record.record().fragment.len() <= 8 {
                        return Err(Error::CryptoError(
                            "ApplicationData record too short to contain explicit nonce"
                                .to_string(),
                        ));
                    }

                    // Extract the explicit nonce from the beginning of the fragment
                    let explicit_nonce = &record.record().fragment[..8];

                    // Get the fixed part of the IV (4 bytes)
                    let iv = if self.is_client {
                        self.crypto_context.get_server_write_iv() // Server's write is client's read
                    } else {
                        self.crypto_context.get_client_write_iv() // Client's write is server's read
                    };

                    let Some(iv) = iv else {
                        return Err(Error::CryptoError(format!(
                            "{} read IV not available",
                            if self.is_client { "Server" } else { "Client" }
                        )));
                    };

                    // Create the complete nonce: 4-byte fixed IV + 8-byte explicit nonce
                    let nonce = Nonce::new(iv, explicit_nonce);

                    // Get only the encrypted data (skip the explicit nonce)
                    let ciphertext = record.record().fragment[8..].to_vec();

                    // Create AAD for decryption
                    // For decryption, the AAD length should be the ciphertext length minus the GCM tag (16 bytes)
                    // This matches the working dtls implementation
                    let payload_length = ciphertext.len().checked_sub(16).unwrap_or(0);

                    let aad = Aad::new(
                        record.record().content_type,
                        record.record().sequence,
                        payload_length as u16,
                    );

                    let mut buffer = Buffer::wrap(ciphertext);

                    // Decrypt the application data
                    self.decrypt_data(&mut buffer, aad, nonce)?;

                    let plaintext = buffer.into_inner();

                    // Push the decrypted data to the queue
                    self.queue_events
                        .push_back(Output::ApplicationData(plaintext));
                }
            }
        }
        Ok(())
    }

    /// Encrypt data appropriate for the role (client or server)
    fn encrypt_data(&self, plaintext: &mut Buffer, aad: Aad, nonce: Nonce) -> Result<(), Error> {
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
        &self,
        ciphertext: &mut Buffer,
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

    /// Should encryption be used for this message based on content type and encryption state
    fn should_encrypt(&self, content_type: ContentType) -> bool {
        // Application data is always encrypted
        if content_type == ContentType::ApplicationData {
            return true;
        }

        // For handshake messages, encryption depends on role and state
        if content_type == ContentType::Handshake {
            if self.is_client {
                return self.client_encryption_enabled;
            } else {
                return self.server_encryption_enabled;
            }
        }

        // Other message types are not encrypted
        false
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

    pub fn handshake_hash(&self, algorithm: HashAlgorithm) -> Vec<u8> {
        trace!("Handshake hash with algorithm: {:?}", algorithm);

        let mut hash = Hash::new(algorithm);
        hash.update(&self.handshakes);
        hash.clone_and_finalize()
    }

    pub fn init_cipher_suite(&mut self, cs: CipherSuite) -> Result<(), String> {
        self.crypto_context.init_cipher_suite(cs)
    }

    pub fn reset_handshake_seq_no(&mut self) {
        self.next_handshake_seq_no = 0;
    }

    pub fn handshake_data(&self) -> &[u8] {
        &self.handshakes
    }

    pub fn set_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suite = Some(cipher_suite);
    }

    pub fn enable_peer_encryption(&mut self) {
        if self.is_client {
            self.server_encryption_enabled = true;
        } else {
            self.client_encryption_enabled = true;
        }
    }

    pub fn is_peer_encryption_enabled(&self) -> bool {
        if self.is_client {
            self.server_encryption_enabled
        } else {
            self.client_encryption_enabled
        }
    }

    fn peer_iv(&self) -> Iv {
        if self.is_client {
            self.crypto_context.get_server_write_iv().unwrap()
        } else {
            self.crypto_context.get_client_write_iv().unwrap()
        }
    }

    pub fn decryption_aad_and_nonce(&self, dtls: &DTLSRecord) -> (Aad, Nonce) {
        let aad = Aad::new(dtls.content_type, dtls.sequence, dtls.length);
        let iv = self.peer_iv();
        let nonce = Nonce::new(iv, dtls.nonce());
        (aad, nonce)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Flight {
    to: MessageType,
    current: Option<MessageType>,
}
