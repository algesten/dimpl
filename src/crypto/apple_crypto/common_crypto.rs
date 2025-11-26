//! Apple CommonCrypto FFI bindings.
//!
//! This module provides unsafe FFI bindings to Apple's CommonCrypto library
//! via the System framework.

use std::ffi::c_void;

// CommonCrypto constants
/// HMAC algorithm for SHA-1
pub const K_CC_HMAC_ALG_SHA1: u32 = 0;
/// HMAC algorithm for SHA-256
pub const K_CC_HMAC_ALG_SHA256: u32 = 2;
/// HMAC algorithm for SHA-384
pub const K_CC_HMAC_ALG_SHA384: u32 = 3;

/// AES algorithm
pub const K_CC_ALGORITHM_AES: u32 = 0;
/// ECB mode option
pub const K_CC_OPTION_ECB_MODE: u32 = 1;
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

// HMAC SHA-1 digest length
/// SHA-1 digest length
pub const CC_SHA1_DIGEST_LENGTH: usize = 20;

// AES key sizes
/// AES-128 key size
pub const K_CC_AES_KEY_SIZE_128: usize = 16;
/// AES-192 key size
pub const K_CC_AES_KEY_SIZE_192: usize = 24;
/// AES-256 key size
pub const K_CC_AES_KEY_SIZE_256: usize = 32;

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

    /// Compute SHA-256 hash
    pub fn CC_SHA256(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;

    /// Compute SHA-384 hash
    pub fn CC_SHA384(data: *const c_void, len: u32, md: *mut u8) -> *mut u8;

    /// Create a cryptor
    pub fn CCCryptorCreate(
        op: u32,
        alg: u32,
        options: u32,
        key: *const u8,
        key_length: usize,
        iv: *const u8,
        cryptor_ref: *mut *mut c_void,
    ) -> i32;

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

    /// Process data through the cryptor
    pub fn CCCryptorUpdate(
        cryptor_ref: *mut c_void,
        data_in: *const u8,
        data_in_length: usize,
        data_out: *mut u8,
        data_out_available: usize,
        data_out_moved: *mut usize,
    ) -> i32;

    /// Finalize the cryptor
    pub fn CCCryptorFinal(
        cryptor_ref: *mut c_void,
        data_out: *mut u8,
        data_out_available: usize,
        data_out_moved: *mut usize,
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
