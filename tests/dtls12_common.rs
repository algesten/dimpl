//! Shared helpers for DTLS 1.2 integration tests.
//!
//! This file has no `#[test]` functions; Cargo compiles it as a no-op binary.
//! Import it from other test files via `mod dtls12_common;`.

#![allow(unused)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, Output};

/// Parsed DTLS 1.2 record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecHdr {
    pub ctype: u8,
    pub epoch: u16,
    pub seq: u64,
}

/// Handshake message types (RFC 5246 / 6347).
pub const CLIENT_HELLO: u8 = 1;
pub const SERVER_HELLO: u8 = 2;
pub const HELLO_VERIFY_REQUEST: u8 = 3;
pub const CERTIFICATE: u8 = 11;
pub const SERVER_HELLO_DONE: u8 = 14;

/// Parse DTLS 1.2 record headers from a datagram.
pub fn parse_records(datagram: &[u8]) -> Vec<RecHdr> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 13 <= datagram.len() {
        let ctype = datagram[i];
        let epoch = u16::from_be_bytes([datagram[i + 3], datagram[i + 4]]);
        let seq_bytes = [
            0u8,
            0u8,
            datagram[i + 5],
            datagram[i + 6],
            datagram[i + 7],
            datagram[i + 8],
            datagram[i + 9],
            datagram[i + 10],
        ];
        let seq = u64::from_be_bytes(seq_bytes);
        let len = u16::from_be_bytes([datagram[i + 11], datagram[i + 12]]) as usize;
        out.push(RecHdr { ctype, epoch, seq });
        i += 13 + len;
    }
    out
}

/// Collect record headers from a slice of datagrams.
pub fn collect_headers(datagrams: &[Vec<u8>]) -> Vec<RecHdr> {
    datagrams.iter().flat_map(|d| parse_records(d)).collect()
}

/// Parse handshake message types from a datagram (content_type=22).
pub fn parse_handshake_types(datagram: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 13 <= datagram.len() {
        let ctype = datagram[i];
        let len = u16::from_be_bytes([datagram[i + 11], datagram[i + 12]]) as usize;

        // Only parse handshake records (content_type=22)
        if ctype == 22 && i + 13 + 1 <= datagram.len() {
            // Handshake message type is first byte of payload
            let hs_type = datagram[i + 13];
            out.push(hs_type);
        }
        i += 13 + len;
    }
    out
}

/// Assert that retransmitted records have the same epochs but increased sequence numbers.
pub fn assert_epochs_and_seq_increased(init: &[RecHdr], resend: &[RecHdr]) {
    assert_eq!(
        init.len(),
        resend.len(),
        "record count must match between initial and resend"
    );
    for (a, b) in init.iter().zip(resend.iter()) {
        assert_eq!(
            a.epoch, b.epoch,
            "epoch must match for the same record on resend"
        );
        assert!(
            b.seq > a.seq,
            "sequence must increase on resend: {:?} -> {:?}",
            a,
            b
        );
    }
}

/// Poll until `Timeout`, collecting only packets.
pub fn collect_packets(endpoint: &mut Dtls) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 2048];
    loop {
        match endpoint.poll_output(&mut buf) {
            Output::Packet(p) => out.push(p.to_vec()),
            Output::Timeout(_) => break,
            _ => {}
        }
    }
    out
}

/// Trigger a timeout by advancing time 2 seconds.
pub fn trigger_timeout(ep: &mut Dtls, now: &mut Instant) {
    *now += Duration::from_secs(2);
    ep.handle_timeout(*now).expect("handle_timeout");
}

/// Create a DTLS 1.2 config with default settings.
pub fn dtls12_config() -> Arc<Config> {
    Arc::new(Config::default())
}

/// Create a DTLS 1.2 config with custom MTU.
pub fn dtls12_config_with_mtu(mtu: usize) -> Arc<Config> {
    Arc::new(
        Config::builder()
            .mtu(mtu)
            .build()
            .expect("Failed to build config"),
    )
}
