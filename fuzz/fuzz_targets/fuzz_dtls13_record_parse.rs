#![no_main]

//! Fuzz target for DTLS 1.3 record layer parsing.
//!
//! This target focuses on testing the record parsing logic by constructing
//! inputs that look more like valid DTLS 1.3 records but with variations to
//! find edge cases.
//!
//! DTLS 1.3 has two record formats:
//!
//! DTLSPlaintext (epoch 0, same as DTLS 1.2):
//! - ContentType: 1 byte (20-24 valid values)
//! - ProtocolVersion: 2 bytes (0xFEFD for DTLS 1.2)
//! - Epoch: 2 bytes (must be 0)
//! - Sequence Number: 6 bytes (u48)
//! - Length: 2 bytes
//! - Fragment: variable
//!
//! DTLSCiphertext (unified header, epoch >= 2):
//! - Flags: 1 byte (001CSLEE pattern)
//! - Sequence: 1 or 2 bytes (depending on S flag)
//! - Length: 0 or 2 bytes (depending on L flag)
//! - Fragment: variable

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{certificate, Config, Dtls};

/// DTLSPlaintext header length
const PLAINTEXT_HEADER_LEN: usize = 13;
/// Maximum DTLS fragment size
const MAX_FRAGMENT_SIZE: usize = 16384;

fuzz_target!(|data: &[u8]| {
    let cert = match certificate::generate_self_signed_certificate() {
        Ok(c) => c,
        Err(_) => return,
    };

    let config = Arc::new(Config::default());
    let now = Instant::now();
    let mut dtls = Dtls::new_13(Arc::clone(&config), cert, now);

    // Test the input as-is (even small inputs exercise error paths)
    let _ = dtls.handle_packet(data);

    // If input is long enough, test with DTLSPlaintext header (epoch 0)
    if !data.is_empty() {
        let frag_len = data.len().min(MAX_FRAGMENT_SIZE);

        let mut record = Vec::with_capacity(PLAINTEXT_HEADER_LEN + frag_len);
        record.push(22u8); // ContentType::Handshake
        record.extend_from_slice(&[0xFE, 0xFD]); // DTLS 1.2 version (used in 1.3 record layer)
        record.extend_from_slice(&[0, 0]); // epoch 0
        record.extend_from_slice(&[0, 0, 0, 0, 0, 1]); // sequence 1
        record.extend_from_slice(&(frag_len as u16).to_be_bytes());
        record.extend_from_slice(&data[..frag_len]);

        let _ = dtls.handle_packet(&record);
    }

    // Test with DTLSCiphertext unified header (epoch >= 2)
    if !data.is_empty() {
        let frag_len = data.len().min(MAX_FRAGMENT_SIZE);

        // Unified header with S=1 (2-byte seq), L=1 (length present), epoch=2
        let mut record = Vec::with_capacity(1 + 2 + 2 + frag_len);
        let flags: u8 = 0b0010_0000 // fixed bits
            | 0b0000_1000           // S=1 (2-byte sequence)
            | 0b0000_0100           // L=1 (length present)
            | 0b0000_0010;          // epoch low bits = 2
        record.push(flags);
        record.extend_from_slice(&[0, 1]); // sequence number 1
        record.extend_from_slice(&(frag_len as u16).to_be_bytes());
        record.extend_from_slice(&data[..frag_len]);

        let _ = dtls.handle_packet(&record);
    }
});
