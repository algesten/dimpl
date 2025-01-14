use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use std::u16;

use crate::buffer::{Buffer, BufferPool};
use crate::incoming::Incoming;
use crate::message::{CipherSuite, Sequence};
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
}
