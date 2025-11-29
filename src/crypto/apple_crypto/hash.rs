//! Hash implementations using Apple CommonCrypto.

use crate::buffer::Buf;
use crate::crypto::provider::{HashContext, HashProvider};
use crate::message::HashAlgorithm;

#[repr(C)]
#[derive(Clone, Copy)]
struct CC_SHA256_CTX {
    count: [u32; 2],
    hash: [u32; 8],
    wbuf: [u32; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CC_SHA512_CTX {
    count: [u64; 2],
    hash: [u64; 8],
    wbuf: [u64; 16],
}

#[allow(non_camel_case_types)]
type CC_LONG = u32;

extern "C" {
    fn CC_SHA256_Init(c: *mut CC_SHA256_CTX) -> i32;
    fn CC_SHA256_Update(c: *mut CC_SHA256_CTX, data: *const u8, len: CC_LONG) -> i32;
    fn CC_SHA256_Final(md: *mut u8, c: *mut CC_SHA256_CTX) -> i32;

    fn CC_SHA384_Init(c: *mut CC_SHA512_CTX) -> i32;
    fn CC_SHA384_Update(c: *mut CC_SHA512_CTX, data: *const u8, len: CC_LONG) -> i32;
    fn CC_SHA384_Final(md: *mut u8, c: *mut CC_SHA512_CTX) -> i32;
}

#[derive(Debug)]
pub(super) struct AppleHashProvider;

impl HashProvider for AppleHashProvider {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn HashContext> {
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(Sha256Context::new()),
            HashAlgorithm::SHA384 => Box::new(Sha384Context::new()),
            _ => panic!("Unsupported hash algorithm: {algorithm:?}"),
        }
    }
}

pub(super) static HASH_PROVIDER: AppleHashProvider = AppleHashProvider;

struct Sha256Context {
    ctx: CC_SHA256_CTX,
}

impl Sha256Context {
    fn new() -> Self {
        let mut ctx = unsafe { std::mem::zeroed() };
        unsafe { CC_SHA256_Init(&mut ctx) };
        Self { ctx }
    }
}

impl std::fmt::Debug for Sha256Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256Context").finish_non_exhaustive()
    }
}

impl HashContext for Sha256Context {
    fn update(&mut self, data: &[u8]) {
        unsafe {
            CC_SHA256_Update(&mut self.ctx, data.as_ptr(), data.len() as CC_LONG);
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let mut ctx_copy = self.ctx;
        let mut digest = [0u8; 32];
        unsafe {
            CC_SHA256_Final(digest.as_mut_ptr(), &mut ctx_copy);
        }
        out.clear();
        out.extend_from_slice(&digest);
    }
}

struct Sha384Context {
    ctx: CC_SHA512_CTX,
}

impl Sha384Context {
    fn new() -> Self {
        let mut ctx = unsafe { std::mem::zeroed() };
        unsafe { CC_SHA384_Init(&mut ctx) };
        Self { ctx }
    }
}

impl std::fmt::Debug for Sha384Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha384Context").finish_non_exhaustive()
    }
}

impl HashContext for Sha384Context {
    fn update(&mut self, data: &[u8]) {
        unsafe {
            CC_SHA384_Update(&mut self.ctx, data.as_ptr(), data.len() as CC_LONG);
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let mut ctx_copy = self.ctx;
        let mut digest = [0u8; 48];
        unsafe {
            CC_SHA384_Final(digest.as_mut_ptr(), &mut ctx_copy);
        }
        out.clear();
        out.extend_from_slice(&digest);
    }
}

/// Compute SHA-256 hash of data and return as fixed-size array.
pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut ctx = Sha256Context::new();
    ctx.update(data);
    let mut digest = [0u8; 32];
    unsafe {
        CC_SHA256_Final(digest.as_mut_ptr(), &mut ctx.ctx);
    }
    digest
}

/// Compute SHA-384 hash of data and return as fixed-size array.
pub(super) fn sha384(data: &[u8]) -> [u8; 48] {
    let mut ctx = Sha384Context::new();
    ctx.update(data);
    let mut digest = [0u8; 48];
    unsafe {
        CC_SHA384_Final(digest.as_mut_ptr(), &mut ctx.ctx);
    }
    digest
}
