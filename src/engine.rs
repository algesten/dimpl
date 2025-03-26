use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use std::u16;

use crate::buffer::{Buffer, BufferPool};
use crate::incoming::Incoming;
use crate::message::{
    CipherSuite, ContentType, DTLSRecord, Handshake, MessageType, ProtocolVersion, Sequence,
};
use crate::{Config, Error, Output};

#[derive(Debug)]
pub(crate) struct Engine {
    config: Arc<Config>,

    /// Pool of buffers
    buffers_free: BufferPool,

    /// Counters for sending DTLSRecord.
    next_sequence_tx: Sequence,

    /// Queue of incoming packets.
    queue_rx: VecDeque<Incoming>,

    /// Queue of outgoing packets.
    queue_tx: VecDeque<Buffer>,

    /// Holder of last packet. To be able to return a reference.
    last_packet: Option<Buffer>,
}

impl Engine {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            buffers_free: BufferPool::default(),
            next_sequence_tx: Sequence::default(),
            queue_rx: VecDeque::new(),
            queue_tx: VecDeque::new(),
            last_packet: None,
        }
    }

    pub fn config(&self) -> &Config {
        &*self.config
    }

    pub fn parse_packet(
        &mut self,
        packet: &[u8],
        c: &mut Option<CipherSuite>,
    ) -> Result<(), Error> {
        let buffer = self.buffers_free.pop();

        let incoming = Incoming::parse_packet(packet, c, buffer)?;

        self.insert_incoming(incoming);

        Ok(())
    }

    /// Insert the Incoming using the logic:
    ///
    /// 1. If it is a handshake, sort by the message_seq
    /// 2. If it is not a handshake, sort by sequence_number
    ///
    fn insert_incoming(&mut self, incoming: Incoming) {
        let first = incoming.first();

        if let Some(h) = &first.handshake {
            match self
                .queue_rx
                .binary_search_by_key(&h.header.message_seq, |i| {
                    i.first()
                        .handshake
                        .as_ref()
                        .map(|h| h.header.message_seq)
                        // Non-handshakes are sorted later.
                        .unwrap_or(u16::MAX)
                }) {
                Ok(_) => {
                    // We have already received this exact handshake packet.
                    // Ignore the new one.
                    debug!("Dupe handshake with message_seq: {}", h.header.message_seq);
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
        let next_timeout = self.poll_timeout();

        if let Some(packet) = self.poll_packet_tx() {
            return Output::Packet(packet);
        }

        Output::Timeout(next_timeout)
    }

    fn poll_timeout(&self) -> Instant {
        Instant::now()
    }

    /// Check if there are any incoming packets to process
    pub fn has_incoming(&self) -> bool {
        !self.queue_rx.is_empty()
    }

    /// Get the next incoming packet
    pub fn next_incoming(&mut self) -> Option<Incoming> {
        self.queue_rx.pop_front()
    }

    /// Create a DTLS record and serialize it into a buffer
    pub fn create_record<F>(&mut self, content_type: ContentType, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Vec<u8>),
    {
        let mut buffer = self.buffers_free.pop();
        let mut fragment = Vec::new();

        // Let the callback fill the fragment
        f(&mut fragment);

        let record = DTLSRecord {
            content_type,
            version: ProtocolVersion::DTLS1_2,
            sequence: self.next_sequence_tx.clone(),
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

        Ok(())
    }

    /// Create a handshake message and wrap it in a DTLS record
    pub fn create_handshake<F>(
        &mut self,
        msg_type: MessageType,
        message_seq: u16,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut Vec<u8>),
    {
        self.create_record(ContentType::Handshake, |fragment| {
            // Create a buffer for the handshake body
            let mut body_buffer = Vec::new();

            // Let the callback fill the handshake body
            f(&mut body_buffer);

            // Create the handshake header
            let header = Handshake {
                header: crate::message::Header {
                    msg_type,
                    length: body_buffer.len() as u32,
                    message_seq,
                    fragment_offset: 0,
                    fragment_length: body_buffer.len() as u32,
                },
                body: crate::message::Body::Fragment(&body_buffer),
            };

            // Serialize the handshake
            header.serialize(fragment);
        })
    }
}
