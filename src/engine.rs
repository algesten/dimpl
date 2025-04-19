use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::buffer::{Buffer, BufferPool};
use crate::crypto::{CertVerifier, CryptoContext, Hash, KeyingMaterial, SrtpProfile};
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

    /// Hash of handshake messages.
    handshake_hash: StoreThenHash,
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
            crypto_context: CryptoContext::new(certificate, private_key, cert_verifier),
            server_encryption_enabled: false,
            client_encryption_enabled: false,
            is_client,
            peer_handshake_seq_no: 0,
            next_handshake_seq_no: 0,
            handshake_hash: StoreThenHash::new(),
        }
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
    }

    /// Enable client encryption
    pub fn enable_client_encryption(&mut self) {
        self.client_encryption_enabled = true;
    }

    pub fn parse_packet(
        &mut self,
        packet: &[u8],
        c: &mut Option<CipherSuite>,
    ) -> Result<(), Error> {
        let buffer = self.buffers_free.pop();

        let incoming = Incoming::parse_packet(packet, c, buffer)?;

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

        if let Some(h) = &first.handshake {
            match self.queue_rx.binary_search_by(|i| {
                let other = i
                    .first()
                    .handshake
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
                .binary_search_by_key(&first.record.sequence, |i| i.first().record.sequence)
            {
                Ok(_) => {
                    debug!("Dupe record with sequence: {}", first.record.sequence);
                }
                Err(index) => {
                    // Insert in order of sequence_number
                    self.queue_rx.insert(index, incoming);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn poll_packet_tx(&mut self) -> Option<&[u8]> {
        // If there is a previous packet, return it to the pool.
        if let Some(last) = self.last_packet.take() {
            self.buffers_free.push(last);
        }

        let buffer = self.queue_tx.pop_front()?;
        self.last_packet = Some(buffer);

        // unwrap is ok because we set it right now.
        let p = self.last_packet.as_ref().unwrap();

        Some(p.as_slice())
    }

    pub(crate) fn poll_output(&mut self) -> Output {
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

        let first = self.queue_rx.front().unwrap().first().handshake.as_ref()?;

        if first.header.message_seq != self.peer_handshake_seq_no {
            return None;
        }

        let mut current_seq = first.header.message_seq;
        let mut found_end = false;
        let mut last_fragment_end = 0;

        // Cap to MAX_DEFRAGMENT_PACKETS to avoid misbehaving peers
        for incoming in self.queue_rx.iter().take(MAX_DEFRAGMENT_PACKETS) {
            for record in incoming.records().iter() {
                if let Some(h) = &record.handshake {
                    // Check message sequence contiguity
                    if h.header.message_seq != current_seq {
                        // Reset fragment tracking for new message sequence
                        last_fragment_end = 0;
                        current_seq = h.header.message_seq;
                    }

                    // Check fragment contiguity
                    if h.header.fragment_offset > 0 {
                        if h.header.fragment_offset != last_fragment_end {
                            return None;
                        }
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
        cipher_suite: Option<CipherSuite>,
    ) -> Result<Option<Handshake<'b>>, Error> {
        if flight.current.is_none() {
            return Ok(None);
        }

        let iter = self
            .queue_rx
            .iter()
            .map(|i| i.records().iter().filter_map(|r| r.handshake.as_ref()))
            .flatten()
            // Handled in previous iteration
            .skip_while(|h| h.handled.get());

        let (handshake, next_type) = Handshake::defragment(
            iter,
            defragment_buffer,
            cipher_suite,
            self.is_client,
            &mut self.handshake_hash,
        )?;

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
                .filter_map(|r| r.handshake.as_ref())
                .all(|h| h.handled.get());

            if all_handled {
                let incoming = self.queue_rx.pop_front().unwrap();

                // The last handled handshake
                let last_handshake = incoming.last().handshake.as_ref().unwrap();

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

        // As long as we're handshaking, update the hash with the fragment. This
        // becomes a no-op once we consumed the hashes.
        if let Some(msg_type) = maybe_msg_type {
            self.handshake_hash
                .update(self.is_client, msg_type, &fragment);
        }

        // Create the record
        let sequence = self.next_sequence_tx.clone();
        let length = fragment.len() as u16;

        // Handle encryption if enabled and content type requires it
        if self.should_encrypt(content_type) {
            // Create proper AAD for encryption
            let aad = self.create_aad(content_type, &sequence, length);

            // Generate nonce
            let nonce = self.generate_nonce()?;

            // Encrypt the fragment in-place
            self.encrypt_data(&mut fragment, &aad, &nonce)?;
        }

        let record = DTLSRecord {
            content_type,
            version: ProtocolVersion::DTLS1_0,
            sequence,
            length: fragment.len() as u16,
            fragment: &fragment,
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

    /// Generate a nonce appropriate for the role (client or server)
    fn generate_nonce(&self) -> Result<Vec<u8>, Error> {
        if self.is_client {
            self.crypto_context
                .generate_client_nonce()
                .map_err(|e| Error::CryptoError(format!("Failed to generate client nonce: {}", e)))
        } else {
            self.crypto_context
                .generate_server_nonce()
                .map_err(|e| Error::CryptoError(format!("Failed to generate server nonce: {}", e)))
        }
    }

    /// Encrypt data appropriate for the role (client or server)
    fn encrypt_data(&self, plaintext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), Error> {
        if self.is_client {
            self.crypto_context
                .encrypt_client_to_server(plaintext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Client encryption failed: {}", e)))
        } else {
            // Server encrypting to client is equivalent to decrypting from client to server
            // For server, we're going in the opposite direction
            self.crypto_context
                .decrypt_server_to_client(plaintext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Server encryption failed: {}", e)))
        }
    }

    /// Decrypt data appropriate for the role (client or server)
    fn decrypt_data(&self, ciphertext: &mut Buffer, aad: &[u8], nonce: &[u8]) -> Result<(), Error> {
        if self.is_client {
            // Client decrypting data from server
            self.crypto_context
                .decrypt_server_to_client(ciphertext, aad, nonce)
                .map_err(|e| Error::CryptoError(format!("Client decryption failed: {}", e)))
        } else {
            // Server decrypting data from client
            self.crypto_context
                .encrypt_client_to_server(ciphertext, aad, nonce)
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

    /// Create AAD (Additional Authenticated Data) for a DTLS record
    pub fn create_aad(
        &self,
        content_type: ContentType,
        sequence: &Sequence,
        length: u16,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(13);

        // Content type (1 byte)
        aad.push(content_type.as_u8());

        // Protocol version (2 bytes)
        let version = ProtocolVersion::DTLS1_2;
        aad.extend_from_slice(&version.as_u16().to_be_bytes());

        // Epoch (2 bytes)
        aad.extend_from_slice(&sequence.epoch.to_be_bytes());

        // Sequence number (6 bytes)
        let seq_bytes = sequence.sequence_number.to_be_bytes();
        aad.extend_from_slice(&seq_bytes[2..]); // Skip first 2 bytes for 6-byte sequence

        // Length (2 bytes)
        aad.extend_from_slice(&length.to_be_bytes());

        aad
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

    /// Process application data packets from the incoming queue
    pub fn process_application_data(&mut self) -> Result<(), Error> {
        // Process any incoming packets with application data
        while let Some(incoming) = self.next_incoming() {
            let records = incoming.records();

            for i in 0..records.len() {
                let record = &records[i];
                if record.record.content_type == ContentType::ApplicationData {
                    // Create AAD for decryption
                    let aad = self.create_aad(
                        record.record.content_type,
                        &record.record.sequence,
                        record.record.length,
                    );

                    // Generate appropriate nonce for decryption
                    let nonce = self.generate_nonce()?;

                    let ciphertext = record.record.fragment.to_vec();
                    let mut buffer = Buffer::wrap(ciphertext);

                    // Decrypt the application data
                    self.decrypt_data(&mut buffer, &aad, &nonce)?;

                    let plaintext = buffer.into_inner();

                    // Push the decrypted data to the queue
                    self.queue_events
                        .push_back(Output::ApplicationData(plaintext));
                }
            }
        }
        Ok(())
    }

    pub fn handshake_hash_finalize(&self) -> Vec<u8> {
        self.handshake_hash.finalize()
    }

    pub(crate) fn init_cipher_suite(&mut self, cs: CipherSuite) -> Result<(), String> {
        // Now that we know which hash to use, convert the hashes to hash as we go.
        let algorithm = cs.hash_algorithm();
        self.handshake_hash.convert_to_hash(algorithm);

        // Initialize the cipher suite
        self.crypto_context.init_cipher_suite(cs)
    }

    pub(crate) fn reset_handshake_seq_no(&mut self) {
        self.next_handshake_seq_no = 0;
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Flight {
    to: MessageType,
    current: Option<MessageType>,
}

pub(crate) enum StoreThenHash {
    Store(Vec<u8>),
    Hash(Hash),
}

impl StoreThenHash {
    pub fn new() -> Self {
        StoreThenHash::Store(Vec::new())
    }

    pub fn update(&mut self, is_client: bool, msg_type: MessageType, data: &[u8]) {
        trace!(
            "Updating handshake hash: {}->{:?} {} bytes",
            if is_client { "Client" } else { "Server" },
            msg_type,
            data.len()
        );
        match self {
            StoreThenHash::Store(vec) => vec.extend_from_slice(data),
            StoreThenHash::Hash(hash) => hash.update(data),
        }
    }

    fn convert_to_hash(&mut self, algorithm: HashAlgorithm) {
        let StoreThenHash::Store(vec) = self else {
            panic!("StoreThenHash already converted to hash");
        };

        let mut hash = Hash::new(algorithm);

        // Update the hash with the data stored up until this point.
        hash.update(vec);

        // Convert to hash
        *self = StoreThenHash::Hash(hash);
    }

    fn finalize(&self) -> Vec<u8> {
        trace!("Finalizing handshake hash");
        let StoreThenHash::Hash(hash) = self else {
            panic!("StoreThenHash not a hash");
        };

        hash.clone_and_finalize()
    }
}
