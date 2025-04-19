use core::fmt;
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

use crate::MAX_MTU;

#[derive(Default)]
pub struct BufferPool {
    free: VecDeque<Buffer>,
}

impl BufferPool {
    /// Take a Buffer from the pool.
    ///
    /// Creates a new buffer if none is free.
    pub fn pop(&mut self) -> Buffer {
        if self.free.is_empty() {
            self.free.push_back(Buffer::default());
        }
        // Unwrap is OK see above handling of empty.
        self.free.pop_front().unwrap()
    }

    /// Return a buffer to the pool.
    pub fn push(&mut self, mut buffer: Buffer) {
        buffer.reset();
        self.free.push_back(buffer);
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("free", &self.free.len())
            .finish()
    }
}

#[derive(Debug)]
pub struct Buffer(Vec<u8>);

impl Buffer {
    pub fn wrap(data: Vec<u8>) -> Self {
        Buffer(data)
    }

    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::replace(&mut self.0, Vec::new())
    }

    pub fn reset(&mut self) {
        self.zeroize();
        self.truncate(0);
    }
}

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

impl Drop for Buffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl aes_gcm::aead::Buffer for Buffer {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
