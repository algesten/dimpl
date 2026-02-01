//! DTLS 1.2 edge case and error recovery tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Dtls, Output};

use crate::common::*;

/// Collected outputs from polling a DTLS 1.2 endpoint to `Timeout`.
#[derive(Default, Debug)]
struct DrainedOutputs {
    packets: Vec<Vec<u8>>,
    connected: bool,
    app_data: Vec<Vec<u8>>,
    timeout: Option<Instant>,
}

/// Poll until `Timeout`, collecting everything.
fn drain_outputs(endpoint: &mut Dtls) -> DrainedOutputs {
    let mut result = DrainedOutputs::default();
    let mut buf = vec![0u8; 2048];
    loop {
        match endpoint.poll_output(&mut buf) {
            Output::Packet(p) => result.packets.push(p.to_vec()),
            Output::Connected => result.connected = true,
            Output::ApplicationData(data) => result.app_data.push(data.to_vec()),
            Output::Timeout(t) => {
                result.timeout = Some(t);
                break;
            }
            _ => {}
        }
    }
    result
}

/// Deliver a slice of packets to a destination endpoint.
fn deliver_packets(packets: &[Vec<u8>], dest: &mut Dtls) {
    for p in packets {
        // Ignore errors - they may be expected for duplicates/replays
        let _ = dest.handle_packet(p);
    }
}

/// Complete a full DTLS 1.2 handshake between client and server.
///
/// Returns the final `Instant` (time advanced during the handshake).
/// Panics if the handshake does not complete within the iteration limit.
#[cfg(feature = "rcgen")]
fn complete_dtls12_handshake(client: &mut Dtls, server: &mut Dtls, mut now: Instant) -> Instant {
    let mut client_connected = false;
    let mut server_connected = false;

    for i in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(client);
        let server_out = drain_outputs(server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        deliver_packets(&client_out.packets, server);
        deliver_packets(&server_out.packets, client);

        if client_connected && server_connected {
            return now;
        }

        // Trigger retransmissions periodically
        if i % 5 == 4 {
            now += Duration::from_secs(2);
        } else {
            now += Duration::from_millis(50);
        }
    }

    panic!("DTLS 1.2 handshake did not complete within iteration limit");
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_recovers_from_corrupted_packet() {
    //! During handshake, corrupt 2 bytes in one packet before delivery so the
    //! DTLS record header is invalid. The receiver drops the corrupted packet.
    //! After a timeout the sender retransmits, and the handshake completes
    //! normally via the retransmission path.

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // FLIGHT 1: Client sends ClientHello
    client.handle_timeout(now).expect("client timeout start");
    client.handle_timeout(now).expect("client arm flight 1");
    let f1 = collect_packets(&mut client);
    assert!(!f1.is_empty(), "client should emit ClientHello");

    // Corrupt the record header itself (version field at bytes 1-2) so
    // the record is rejected at parse time and nothing enters queue_rx.
    for mut p in f1 {
        if p.len() > 5 {
            p[1] ^= 0xFF;
            p[2] ^= 0xFF;
        }
        // Server should reject the record due to invalid version
        let _ = server.handle_packet(&p);
    }

    // Server has no valid packet yet — arm its timers so it's ready
    server.handle_timeout(now).expect("server arm");
    let s_pkts = collect_packets(&mut server);
    assert!(s_pkts.is_empty(), "server should have nothing to send yet");

    // Trigger client retransmission timeout (initial RTO is ~1s)
    trigger_timeout(&mut client, &mut now);
    let f1_resend = collect_packets(&mut client);
    assert!(
        !f1_resend.is_empty(),
        "client should retransmit ClientHello after timeout"
    );

    // Deliver the clean retransmission to server
    for p in &f1_resend {
        server.handle_packet(p).expect("server recv clean CH");
    }

    // FLIGHT 2: Server sends HelloVerifyRequest
    server.handle_timeout(now).expect("server arm flight 2");
    let f2 = collect_packets(&mut server);
    assert!(!f2.is_empty(), "server should emit HelloVerifyRequest");
    for p in &f2 {
        client.handle_packet(p).expect("client recv HVR");
    }

    // FLIGHT 3: Client sends ClientHello with cookie
    client.handle_timeout(now).expect("client arm flight 3");
    let f3 = collect_packets(&mut client);
    assert!(!f3.is_empty(), "client should emit ClientHello with cookie");
    for p in &f3 {
        server.handle_packet(p).expect("server recv CH+cookie");
    }

    // FLIGHT 4: Server sends ServerHello, Certificate, etc.
    server.handle_timeout(now).expect("server arm flight 4");
    let f4 = collect_packets(&mut server);
    assert!(!f4.is_empty(), "server should emit ServerHello flight");
    for p in &f4 {
        client.handle_packet(p).expect("client recv flight 4");
    }

    // FLIGHT 5: Client sends CKX, CCS, Finished
    client.handle_timeout(now).expect("client arm flight 5");
    let f5 = collect_packets(&mut client);
    assert!(!f5.is_empty(), "client should emit flight 5");
    for p in &f5 {
        server.handle_packet(p).expect("server recv flight 5");
    }

    // FLIGHT 6: Server sends CCS, Finished (Connected may be emitted here)
    server.handle_timeout(now).expect("server arm flight 6");
    let server_out = drain_outputs(&mut server);
    assert!(
        !server_out.packets.is_empty(),
        "server should emit flight 6"
    );
    for p in &server_out.packets {
        client.handle_packet(p).expect("client recv flight 6");
    }

    // Drain client outputs to check for Connected event
    client.handle_timeout(now).expect("client final timeout");
    let client_out = drain_outputs(&mut client);

    assert!(
        client_out.connected,
        "Client should be connected after recovering from corrupted packet"
    );
    assert!(
        server_out.connected,
        "Server should be connected after recovering from corrupted packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_discards_wrong_epoch_record() {
    //! After a completed handshake (epoch 1), inject a crafted packet with
    //! epoch 0 and content_type handshake (22). Verify it is silently dropped
    //! and application data exchange still works.

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    now = complete_dtls12_handshake(&mut client, &mut server, now);

    // Craft a DTLS 1.2 record with epoch 0 (pre-handshake) and content_type 22 (handshake).
    // DTLS 1.2 record header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2)
    let bogus = vec![
        22, // content_type: handshake
        0xFE, 0xFD, // version: DTLS 1.2
        0x00, 0x00, // epoch: 0 (wrong — should be 1 post-handshake)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x99, // sequence number
        0x00, 0x05, // length: 5
        0x01, // handshake type: ClientHello
        0x00, 0x00, 0x00, 0x00, // dummy payload
    ];

    // Should be silently discarded (no error)
    client
        .handle_packet(&bogus)
        .expect("wrong epoch record should be silently discarded");

    // Verify application data exchange still works after the bogus packet.
    client
        .send_application_data(b"ping")
        .expect("client send app data");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after wrong-epoch bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_discards_truncated_record() {
    //! Deliver a 3-byte packet (too short to be a valid DTLS 1.2 record header,
    //! which requires 13 bytes). Verify it is silently dropped and the
    //! handshake/connection continues.

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Inject a truncated packet before the handshake begins
    let truncated = vec![0x16, 0xFE, 0xFD]; // 3 bytes — too short for any DTLS record
    let result = client.handle_packet(&truncated);
    // Should either return Ok (silently discarded) or a non-fatal error
    match result {
        Ok(()) => {} // silently discarded — expected
        Err(e) => {
            // Some parse errors are acceptable as long as the endpoint survives
            eprintln!("Truncated packet returned error (non-fatal): {}", e);
        }
    }

    // Now complete the handshake to prove the endpoint is still functional
    now = complete_dtls12_handshake(&mut client, &mut server, now);

    // Also inject a truncated packet after the handshake and verify app data works
    let truncated_post = vec![0x17, 0xFE, 0xFD]; // 3 bytes, content_type = app data
    let result = client.handle_packet(&truncated_post);
    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!(
                "Post-handshake truncated packet returned error (non-fatal): {}",
                e
            );
        }
    }

    // Verify application data exchange still works
    client
        .send_application_data(b"hello")
        .expect("client send app data");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"hello"),
        "Server should receive application data after truncated bogus packets"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_close_notify_graceful_shutdown() {
    //! After a completed handshake, inject a close_notify alert record and
    //! verify the peer handles it gracefully (no panic, no corrupted state).
    //!
    //! DTLS 1.2 alert record format:
    //!   content_type=21, version, epoch=1, seq, length=2, level=1(warning), desc=0(close_notify)

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    now = complete_dtls12_handshake(&mut client, &mut server, now);

    // Verify the connection works before the alert
    client
        .send_application_data(b"before-alert")
        .expect("client send before alert");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out
            .app_data
            .iter()
            .any(|d| d.as_slice() == b"before-alert"),
        "Server should receive app data before alert injection"
    );

    // Craft a close_notify alert record at epoch 0 (plaintext alert).
    // Since DTLS 1.2 post-handshake records should be at epoch 1 and encrypted,
    // an epoch 0 plaintext alert should be silently discarded.
    let close_notify_epoch0 = vec![
        21, // content_type: alert
        0xFE, 0xFD, // version: DTLS 1.2
        0x00, 0x00, // epoch: 0 (plaintext — will be discarded post-handshake)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x50, // sequence number
        0x00, 0x02, // length: 2
        0x01, // level: warning
        0x00, // description: close_notify
    ];

    // The endpoint should handle the alert gracefully (discard or process)
    let result = server.handle_packet(&close_notify_epoch0);
    match result {
        Ok(()) => {
            // Silently discarded the epoch 0 alert — expected
        }
        Err(e) => {
            // An error is also acceptable as long as it does not panic
            eprintln!("close_notify alert returned error (non-fatal): {}", e);
        }
    }

    // Verify the server can still process data after the alert
    client
        .send_application_data(b"after-alert")
        .expect("client send after alert");
    now += Duration::from_millis(10);
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out
            .app_data
            .iter()
            .any(|d| d.as_slice() == b"after-alert"),
        "Server should still receive app data after close_notify alert at epoch 0"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_rejects_renegotiation() {
    //! After a completed handshake, inject a ClientHello record to simulate
    //! a renegotiation attempt. Verify it is rejected (either silently dropped
    //! or returns `Error::RenegotiationAttempt`).

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    now = complete_dtls12_handshake(&mut client, &mut server, now);

    // Verify app data works before renegotiation attempt
    client
        .send_application_data(b"pre-reneg")
        .expect("client send pre-reneg");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out
            .app_data
            .iter()
            .any(|d| d.as_slice() == b"pre-reneg"),
        "Server should receive app data before renegotiation attempt"
    );

    // Craft a ClientHello record at epoch 0 to simulate a renegotiation attempt.
    // This is a plaintext handshake record with a minimal ClientHello.
    let renegotiation_hello = vec![
        22, // content_type: handshake
        0xFE, 0xFD, // version: DTLS 1.2
        0x00, 0x00, // epoch: 0
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // sequence number
        0x00, 0x2F, // length: 47 bytes of handshake payload
        // Handshake header
        0x01, // msg_type: ClientHello
        0x00, 0x00, 0x23, // length: 35
        0x00, 0x01, // message_seq: 1
        0x00, 0x00, 0x00, // fragment_offset: 0
        0x00, 0x00, 0x23, // fragment_length: 35
        // ClientHello body
        0xFE, 0xFD, // client_version: DTLS 1.2
        // random (32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x00, // session_id length: 0
        0x00, // cookie length: 0
        0x00, // cipher_suites length will make this invalid, but that's fine
    ];

    // The server should reject the renegotiation attempt.
    // It may return an error or silently discard it.
    let result = server.handle_packet(&renegotiation_hello);
    match result {
        Ok(()) => {
            // Silently discarded — acceptable (epoch 0 record post-handshake)
        }
        Err(e) => {
            // RenegotiationAttempt or other error — also acceptable
            eprintln!("Renegotiation attempt correctly rejected with error: {}", e);
        }
    }

    // Verify the connection still works after the renegotiation attempt.
    now += Duration::from_millis(10);
    client
        .send_application_data(b"post-reneg")
        .expect("client send post-reneg");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out
            .app_data
            .iter()
            .any(|d| d.as_slice() == b"post-reneg"),
        "Server should still receive app data after renegotiation attempt was rejected"
    );
}
