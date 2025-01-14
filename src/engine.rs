use std::collections::VecDeque;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use self_cell::self_cell;
use smallvec::SmallVec;

use crate::message::{DTLSRecord, Handshake};
use crate::MAX_MTU;

#[derive(Debug, Default)]
pub(crate) struct Engine {
    /// Pool of free buffers.
    buffers_free: VecDeque<Buffer>,

    /// Counters for sending DTLSRecord.
    record_tx: RecordCounters,

    /// Counters for receiving DTLSRecord.
    ///
    /// This is the max seen such.
    record_rx: RecordCounters,

    /// Queue of incoming packets.
    queue_rx: VecDeque<Incoming>,

    /// Queue of outgoing packets.
    queue_tx: VecDeque<Buffer>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct RecordCounters {
    /// Record level epoch.
    ///
    /// Increases each time we renegotiation the TLS (which doesn't really happen).
    epoch: u16,

    /// Record level sequence number.
    ///
    /// Increases for each new packet sent. Resends increases this counter.
    sequence_number: u64,
}

// self_cell!(
//     struct Incoming {
//         owner: Buffer,
//         #[covariant]
//         dependent: Records,
//     }

//     impl {Debug}
// );

#[derive(Debug)]
struct Incoming;

#[derive(Debug)]
pub struct Records<'a> {
    records: SmallVec<[Record<'a>; 32]>,
}

#[derive(Debug)]
pub struct Record<'a> {
    s: DTLSRecord<'a>,
    t: Handshake<'a>,
}

#[derive(Debug)]
pub(crate) struct Buffer(Vec<u8>);

impl Default for Buffer {
    fn default() -> Self {
        Buffer(Vec::with_capacity(MAX_MTU))
    }
}

impl Deref for Buffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
