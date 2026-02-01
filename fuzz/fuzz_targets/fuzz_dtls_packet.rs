#![no_main]

//! Fuzz target for DTLS packet handling.
//!
//! This target exercises the main packet processing path in the DTLS engine.
//! It creates a DTLS instance and feeds it arbitrary byte sequences to find
//! parsing bugs, panics, or other issues in packet handling.

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{certificate, Config, Dtls, Output};

fuzz_target!(|data: &[u8]| {
    // Generate a certificate once for the test instance
    let cert = match certificate::generate_self_signed_certificate() {
        Ok(c) => c,
        Err(_) => return, // Skip if certificate generation fails
    };

    let config = Arc::new(Config::default());
    let now = Instant::now();

    // Test as server (default mode)
    // Servers can receive packets immediately
    {
        let mut dtls = Dtls::new(Arc::clone(&config), cert.clone(), now);
        // Ignore errors - we're looking for panics, not handling errors
        let _ = dtls.handle_packet(data);
    }

    // Test as client
    // Clients need handle_timeout called first to initialize
    {
        let mut dtls = Dtls::new(Arc::clone(&config), cert, now);
        dtls.set_active(true); // Switch to client mode

        // Initialize the client by calling handle_timeout to set up the random and other state
        let mut buf = vec![0u8; 2048];
        let _ = dtls.handle_timeout(now);

        // Drain any initial packets (ClientHello) with a limit to prevent infinite loops
        for _ in 0..10 {
            match dtls.poll_output(&mut buf) {
                Output::Timeout(_) => break,
                Output::Packet(_) => continue,
                _ => break,
            }
        }

        let _ = dtls.handle_packet(data);
    }
});
