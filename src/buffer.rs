use std::collections::VecDeque;
use std::fmt;
use std::ops::{Deref, DerefMut, RangeBounds};
use std::vec::Drain;

#[derive(Default)]
pub struct BufferPool {
    free: VecDeque<Buf>,
}

impl BufferPool {
    /// Take a Buffer from the pool.
    ///
    /// Creates a new buffer if none is free.
    pub fn pop(&mut self) -> Buf {
        if self.free.is_empty() {
            self.free.push_back(Buf::new());
        }
        // Unwrap is OK see above handling of empty.
        self.free.pop_front().unwrap()
    }

    /// Return a buffer to the pool.
    pub fn push(&mut self, mut buffer: Buf) {
        buffer.clear();
        self.free.push_front(buffer);
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("free", &self.free.len())
            .finish()
    }
}

#[derive(Default)]
pub struct Buf(Vec<u8>);

impl Buf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.0.extend_from_slice(other);
    }

    pub fn push(&mut self, byte: u8) {
        self.0.push(byte);
    }

    pub fn resize(&mut self, len: usize, value: u8) {
        self.0.resize(len, value);
    }

    pub fn drain(&mut self, r: impl RangeBounds<usize>) -> Drain<'_, u8> {
        self.0.drain(r)
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

// aws-lc-rs AEAD operations require Extend<&u8> for appending authentication tags
impl<'a> Extend<&'a u8> for Buf {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.0.extend(iter.into_iter().copied());
    }
}

impl Deref for Buf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Buf {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Buf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Buf").field("len", &self.0.len()).finish()
    }
}

pub trait ToBuf {
    fn to_buf(self) -> Buf;
}

impl ToBuf for Vec<u8> {
    fn to_buf(self) -> Buf {
        Buf(self)
    }
}

impl ToBuf for &[u8] {
    fn to_buf(self) -> Buf {
        self.to_vec().to_buf()
    }
}

pub struct TmpBuf<'a>(&'a mut [u8], usize);

impl<'a> TmpBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self(buf, buf.len())
    }
}

impl<'a> TmpBuf<'a> {
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.1
    }

    /// Truncate the buffer to the specified length
    pub fn truncate(&mut self, len: usize) {
        self.1 = len;
    }
}

impl<'a> AsRef<[u8]> for TmpBuf<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

impl<'a> AsMut<[u8]> for TmpBuf<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..self.1]
    }
}
