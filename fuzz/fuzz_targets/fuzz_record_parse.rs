#![no_main]

//! Fuzz target for DTLS record layer parsing.
//!
//! This target focuses on testing the record parsing logic by constructing
//! inputs that look more like valid DTLS records but with variations to
//! find edge cases.
//!
//! DTLS 1.2 record format:
//! - ContentType: 1 byte (20-24 valid values)
//! - ProtocolVersion: 2 bytes (0xFEFD for DTLS 1.2, 0xFEFF for DTLS 1.0)
//! - Epoch: 2 bytes
//! - Sequence Number: 6 bytes (u48)
//! - Length: 2 bytes
//! - Fragment: variable (up to 2^14 bytes for plaintext)

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

use dimpl::{certificate, Config, Dtls};

/// DTLS record header length
const DTLS_HEADER_LEN: usize = 13;
/// Maximum DTLS fragment size
const MAX_FRAGMENT_SIZE: usize = 16384;

fuzz_target!(|data: &[u8]| {
    let cert = match certificate::generate_self_signed_certificate() {
        Ok(c) => c,
        Err(_) => return,
    };

    let config = Arc::new(Config::default());
    let mut dtls = Dtls::new(Arc::clone(&config), cert);

    // Test the input as-is (even small inputs exercise error paths)
    let _ = dtls.handle_packet(data);

    // If input is long enough, also test with DTLS-like header prefix
    if !data.is_empty() {
        // Cap fragment size to both max DTLS size and available data
        let frag_len = data.len().min(MAX_FRAGMENT_SIZE);

        // Try constructing a record with handshake content type
        let mut record = Vec::with_capacity(DTLS_HEADER_LEN + frag_len);
        record.push(22u8); // ContentType::Handshake
        record.extend_from_slice(&[0xFE, 0xFD]); // DTLS 1.2 version
        record.extend_from_slice(&[0, 0]); // epoch 0
        record.extend_from_slice(&[0, 0, 0, 0, 0, 1]); // sequence 1
        record.extend_from_slice(&(frag_len as u16).to_be_bytes());
        record.extend_from_slice(&data[..frag_len]);

        let _ = dtls.handle_packet(&record);
    }
});
