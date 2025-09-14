use std::collections::VecDeque;
use std::fmt;
use std::ops::{Deref, DerefMut};

use zeroize::Zeroize;

#[derive(Default)]
pub struct BufferPool {
    free: VecDeque<Buf<'static>>,
}

impl BufferPool {
    /// Take a Buffer from the pool.
    ///
    /// Creates a new buffer if none is free.
    pub fn pop(&mut self) -> Buf<'static> {
        if self.free.is_empty() {
            self.free.push_back(Buf::default());
        }
        // Unwrap is OK see above handling of empty.
        self.free.pop_front().unwrap()
    }

    /// Return a buffer to the pool.
    pub fn push(&mut self, mut buffer: Buf<'static>) {
        buffer.zeroize();
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("free", &self.free.len())
            .finish()
    }
}

pub struct Buf<'a>(Inner<'a>);

enum Inner<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a mut [u8]),
}

impl Buf<'static> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        let Inner::Owned(v) = &mut self.0 else {
            unreachable!();
        };
        v.clear();
    }

    pub fn extend_from_slice(&mut self, other: &[u8]) {
        let Inner::Owned(v) = &mut self.0 else {
            unreachable!();
        };
        v.extend_from_slice(other);
    }

    pub fn push(&mut self, byte: u8) {
        let Inner::Owned(v) = &mut self.0 else {
            unreachable!();
        };
        v.push(byte);
    }

    pub fn resize(&mut self, len: usize, value: u8) {
        let Inner::Owned(v) = &mut self.0 else {
            unreachable!();
        };
        v.resize(len, value);
    }

    pub fn as_vec_mut(&mut self) -> &mut Vec<u8> {
        let Inner::Owned(v) = &mut self.0 else {
            unreachable!();
        };
        v
    }
}

impl<'a> Buf<'a> {
    pub fn wrap(v: &'a mut [u8]) -> Self {
        Buf(Inner::Borrowed(v))
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        let inner = std::mem::take(&mut self.0);
        match inner {
            Inner::Owned(v) => v,
            Inner::Borrowed(v) => {
                let vec = v.to_vec();

                // The slice will be dropped, so we zero it explicitly.
                v.zeroize();

                vec
            }
        }
    }
}

impl<'a> Default for Buf<'a> {
    fn default() -> Self {
        Buf(Inner::default())
    }
}

impl<'a> Default for Inner<'a> {
    fn default() -> Self {
        Inner::Owned(vec![])
    }
}

impl<'a> Deref for Buf<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for Buf<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> Drop for Buf<'a> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'a> aes_gcm::aead::Buffer for Buf<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        let mut this = std::mem::take(self).into_vec();
        this.extend_from_slice(other);
        *self = Buf(Inner::Owned(this));
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        let mut this = std::mem::take(self).into_vec();
        this.truncate(len);
        *self = Buf(Inner::Owned(this));
    }
}

impl<'a> AsRef<[u8]> for Buf<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> AsMut<[u8]> for Buf<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for Buf<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Buf").field("len", &self.0.len()).finish()
    }
}

impl<'a> Deref for Inner<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Inner::Owned(v) => v.as_slice(),
            Inner::Borrowed(v) => v,
        }
    }
}

impl<'a> DerefMut for Inner<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Inner::Owned(v) => v.as_mut_slice(),
            Inner::Borrowed(v) => v,
        }
    }
}
