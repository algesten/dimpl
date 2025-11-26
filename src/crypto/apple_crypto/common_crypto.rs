//! Apple CommonCrypto FFI bindings.
//!
//! This module provides unsafe FFI bindings to Apple's CommonCrypto library
//! via the System framework.

use std::ffi::c_void;

// CommonCrypto constants
/// HMAC algorithm for SHA-256
pub const K_CC_HMAC_ALG_SHA256: u32 = 2;
/// HMAC algorithm for SHA-384
pub const K_CC_HMAC_ALG_SHA384: u32 = 3;

/// AES algorithm
pub const K_CC_ALGORITHM_AES: u32 = 0;
/// GCM mode
pub const K_CC_MODE_GCM: u32 = 11;
/// Encryption operation
pub const K_CC_ENCRYPT: u32 = 0;
/// Decryption operation
pub const K_CC_DECRYPT: u32 = 1;

// SHA constants
/// SHA-256 digest length
pub const CC_SHA256_DIGEST_LENGTH: usize = 32;
/// SHA-384 digest length
pub const CC_SHA384_DIGEST_LENGTH: usize = 48;

// AES key sizes
/// AES-128 key size
pub const K_CC_AES_KEY_SIZE_128: usize = 16;
/// AES-256 key size
pub const K_CC_AES_KEY_SIZE_256: usize = 32;

// SHA context sizes - these are the sizes of the internal state structures
/// Size of CC_SHA256_CTX structure
pub const CC_SHA256_CTX_SIZE: usize = 104;
/// Size of CC_SHA512_CTX structure (used for SHA-384)
pub const CC_SHA512_CTX_SIZE: usize = 208;

/// Opaque SHA-256 context structure
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct CcSha256Ctx {
    pub data: [u8; CC_SHA256_CTX_SIZE],
}

/// Opaque SHA-512 context structure (used for SHA-384)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct CcSha512Ctx {
    pub data: [u8; CC_SHA512_CTX_SIZE],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_contexts_meet_alignment_requirements() {
        assert!(std::mem::align_of::<CcSha256Ctx>() >= 16);
        assert!(std::mem::align_of::<CcSha512Ctx>() >= 16);
    }
}

// CommonCrypto function bindings
#[link(name = "System")]
extern "C" {
    /// Compute HMAC
    pub fn CCHmac(
        algorithm: u32,
        key: *const c_void,
        key_length: usize,
        data: *const c_void,
        data_length: usize,
        mac_out: *mut c_void,
    );

    // Streaming SHA-256 functions
    /// Initialize SHA-256 context
    pub fn CC_SHA256_Init(ctx: *mut CcSha256Ctx) -> i32;
    /// Update SHA-256 context with data
    pub fn CC_SHA256_Update(ctx: *mut CcSha256Ctx, data: *const c_void, len: u32) -> i32;
    /// Finalize SHA-256 and get digest
    pub fn CC_SHA256_Final(md: *mut u8, ctx: *mut CcSha256Ctx) -> i32;

    // Streaming SHA-384 functions
    /// Initialize SHA-384 context
    pub fn CC_SHA384_Init(ctx: *mut CcSha512Ctx) -> i32;
    /// Update SHA-384 context with data
    pub fn CC_SHA384_Update(ctx: *mut CcSha512Ctx, data: *const c_void, len: u32) -> i32;
    /// Finalize SHA-384 and get digest
    pub fn CC_SHA384_Final(md: *mut u8, ctx: *mut CcSha512Ctx) -> i32;

    /// Create a cryptor with specific mode
    pub fn CCCryptorCreateWithMode(
        op: u32,
        mode: u32,
        alg: u32,
        padding: u32,
        iv: *const u8,
        key: *const u8,
        key_length: usize,
        tweak: *const u8,
        tweak_length: usize,
        num_rounds: i32,
        mode_options: u32,
        cryptor_ref: *mut *mut c_void,
    ) -> i32;

    /// Release the cryptor
    pub fn CCCryptorRelease(cryptor_ref: *mut c_void) -> i32;

    /// Add IV for GCM mode
    pub fn CCCryptorGCMAddIV(cryptor_ref: *mut c_void, iv: *const u8, iv_len: usize) -> i32;

    /// Add AAD for GCM mode
    pub fn CCCryptorGCMAddAAD(cryptor_ref: *mut c_void, aad: *const u8, aad_len: usize) -> i32;

    /// Encrypt in GCM mode
    pub fn CCCryptorGCMEncrypt(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
    ) -> i32;

    /// Decrypt in GCM mode
    pub fn CCCryptorGCMDecrypt(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
    ) -> i32;

    /// Get authentication tag in GCM mode
    pub fn CCCryptorGCMFinal(cryptor_ref: *mut c_void, tag: *mut u8, tag_len: *mut usize) -> i32;
}
