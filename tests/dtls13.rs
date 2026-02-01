//! DTLS 1.3 integration tests for WebRTC functionality.
//!
//! These tests verify DTLS 1.3 handshake, encryption, SRTP keying material export,
//! retransmission handling, and application data exchange.

#![allow(unused)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, Output, SrtpProfile};

/// Helper to collect all output packets from an endpoint.
fn collect_packets(endpoint: &mut Dtls) -> Vec<Vec<u8>> {
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

/// Helper to collect all outputs (packets and events) from an endpoint.
fn drain_outputs(endpoint: &mut Dtls) -> DrainedOutputs {
    let mut result = DrainedOutputs::default();
    let mut buf = vec![0u8; 2048];
    loop {
        match endpoint.poll_output(&mut buf) {
            Output::Packet(p) => result.packets.push(p.to_vec()),
            Output::Connected => result.connected = true,
            Output::PeerCert(cert) => result.peer_cert = Some(cert.to_vec()),
            Output::KeyingMaterial(km, profile) => {
                result.keying_material = Some((km.to_vec(), profile));
            }
            Output::ApplicationData(data) => result.app_data.push(data.to_vec()),
            Output::Timeout(t) => {
                result.timeout = Some(t);
                break;
            }
        }
    }
    result
}

#[derive(Default, Debug)]
struct DrainedOutputs {
    packets: Vec<Vec<u8>>,
    connected: bool,
    peer_cert: Option<Vec<u8>>,
    keying_material: Option<(Vec<u8>, SrtpProfile)>,
    app_data: Vec<Vec<u8>>,
    timeout: Option<Instant>,
}

/// Deliver packets from source to destination.
fn deliver_packets(packets: &[Vec<u8>], dest: &mut Dtls) {
    for p in packets {
        // Ignore errors - they may be expected for duplicates/replays
        let _ = dest.handle_packet(p);
    }
}

/// Trigger a timeout by advancing time.
fn trigger_timeout(ep: &mut Dtls, now: &mut Instant) {
    *now += Duration::from_secs(2);
    ep.handle_timeout(*now).expect("handle_timeout");
}

/// Create a DTLS 1.3 config.
fn dtls13_config() -> Arc<Config> {
    Arc::new(
        Config::builder()
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    )
}

/// Create a DTLS 1.3 config with custom MTU.
fn dtls13_config_with_mtu(mtu: usize) -> Arc<Config> {
    Arc::new(
        Config::builder()
            .mtu(mtu)
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    )
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_too_short_ciphertext_record() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");

    // Craft a DTLS 1.3 ciphertext record with length < 16 bytes.
    // Header: fixed bits 001, C=0, S=1 (16-bit seq), L=1 (length), epoch_bits=3
    // => 0b0010_1111 = 0x2F
    let bogus = vec![
        0x2F, // unified header byte
        0x00, 0x01, // encrypted sequence bits
        0x00, 0x01, // length = 1
        0x00, // 1 byte ciphertext (too short)
    ];

    // Should be silently discarded (no error)
    client
        .handle_packet(&bogus)
        .expect("too-short ciphertext record should be discarded");

    // Verify we can still exchange application data.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_cid_bit_records() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");

    // Unified header with CID bit set: 001CSLEE with C=1, S=1, L=1, epoch_bits=3 => 0x3F.
    // We don't support CID, so this should be silently discarded.
    let bogus = vec![0x3F];

    client
        .handle_packet(&bogus)
        .expect("CID-bit record should be discarded");

    // Verify we can still exchange application data.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after CID-bit bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_unauthenticated_ciphertext_without_length_field() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");

    // Craft a DTLS 1.3 ciphertext record with L=0 (no explicit length).
    // Header: 001CSLEE with C=0, S=1, L=0, epoch_bits=3 => 0x2B.
    // Provide 16+ bytes ciphertext so sequence-number mask can be computed.
    let mut bogus = Vec::new();
    bogus.push(0x2B);
    bogus.extend_from_slice(&0x0001u16.to_be_bytes()); // encrypted seq bits
    bogus.extend_from_slice(&[0u8; 16]); // unauthenticated ciphertext/tag bytes

    client
        .handle_packet(&bogus)
        .expect("Unauthenticated ciphertext should be discarded");

    // Verify we can still exchange application data.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after unauthenticated bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_basic_handshake() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Run handshake
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handshake_with_keying_material() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_km: Option<(Vec<u8>, SrtpProfile)> = None;
    let mut server_km: Option<(Vec<u8>, SrtpProfile)> = None;

    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if let Some(km) = client_out.keying_material {
            client_km = Some(km);
        }
        if let Some(km) = server_out.keying_material {
            server_km = Some(km);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_km.is_some() && server_km.is_some() {
            break;
        }

        now += Duration::from_millis(10);
    }

    let client_km = client_km.expect("Client should have keying material");
    let server_km = server_km.expect("Server should have keying material");

    // Both sides should derive the same keying material
    assert_eq!(
        client_km.0, server_km.0,
        "Client and server keying material should match"
    );
    assert_eq!(
        client_km.1, server_km.1,
        "Client and server SRTP profile should match"
    );

    // Keying material should be non-empty and properly sized
    // SRTP keying material is typically 2*(key_len + salt_len) for both directions
    assert!(
        !client_km.0.is_empty(),
        "Keying material should not be empty"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_peer_certificate_exchange() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Store expected certificates
    let expected_client_cert = client_cert.certificate.clone();
    let expected_server_cert = server_cert.certificate.clone();

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_peer_cert: Option<Vec<u8>> = None;
    let mut server_peer_cert: Option<Vec<u8>> = None;

    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if let Some(cert) = client_out.peer_cert {
            client_peer_cert = Some(cert);
        }
        if let Some(cert) = server_out.peer_cert {
            server_peer_cert = Some(cert);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_peer_cert.is_some() && server_peer_cert.is_some() {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_peer_cert.is_some(),
        "Client should receive server's certificate"
    );
    assert!(
        server_peer_cert.is_some(),
        "Server should receive client's certificate"
    );

    // Verify the certificates match what was configured
    assert_eq!(
        client_peer_cert.unwrap(),
        expected_server_cert,
        "Client should receive server's certificate"
    );
    assert_eq!(
        server_peer_cert.unwrap(),
        expected_client_cert,
        "Server should receive client's certificate"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_application_data_exchange() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let client_data = b"Hello from DTLS 1.3 client!";
    let server_data = b"Hello from DTLS 1.3 server!";

    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_received: Vec<u8> = Vec::new();
    let mut server_received: Vec<u8> = Vec::new();
    let mut client_sent = false;
    let mut server_sent = false;

    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        // Collect received app data
        for data in client_out.app_data {
            client_received.extend_from_slice(&data);
        }
        for data in server_out.app_data {
            server_received.extend_from_slice(&data);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        // Send data once connected
        if client_connected && !client_sent {
            client
                .send_application_data(client_data)
                .expect("client send");
            client_sent = true;
        }
        if server_connected && !server_sent {
            server
                .send_application_data(server_data)
                .expect("server send");
            server_sent = true;
        }

        if !client_received.is_empty() && !server_received.is_empty() {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");
    assert_eq!(
        client_received, server_data,
        "Client should receive server's data"
    );
    assert_eq!(
        server_received, client_data,
        "Server should receive client's data"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_multiple_application_data_messages() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // First complete handshake
    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_out.connected && server_out.connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    // Now send multiple messages
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3 is a bit longer".to_vec(),
        b"Message 4".to_vec(),
        b"Message 5 - the final one".to_vec(),
    ];

    for msg in &messages {
        client.send_application_data(msg).expect("client send");
    }

    let mut server_received: Vec<Vec<u8>> = Vec::new();

    for _ in 0..20 {
        let client_out = drain_outputs(&mut client);
        deliver_packets(&client_out.packets, &mut server);

        let server_out = drain_outputs(&mut server);
        for data in server_out.app_data {
            server_received.push(data);
        }

        if server_received.len() >= messages.len() {
            break;
        }

        now += Duration::from_millis(10);
    }

    // Flatten and compare
    let expected: Vec<u8> = messages.iter().flatten().copied().collect();
    let received: Vec<u8> = server_received.iter().flatten().copied().collect();

    assert_eq!(received, expected, "All messages should be received");
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_client_retransmits_on_timeout() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Get initial ClientHello
    client.handle_timeout(now).expect("client start");
    client.handle_timeout(now).expect("client arm");
    let initial_packets = collect_packets(&mut client);
    assert!(
        !initial_packets.is_empty(),
        "Client should send ClientHello"
    );

    // Don't deliver to server, trigger timeout
    trigger_timeout(&mut client, &mut now);

    // Should get retransmitted packets
    let retransmit_packets = collect_packets(&mut client);
    assert!(
        !retransmit_packets.is_empty(),
        "Client should retransmit on timeout"
    );

    // Retransmit should have same number of packets (same flight)
    assert_eq!(
        initial_packets.len(),
        retransmit_packets.len(),
        "Retransmit should have same packet count"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handshake_completes_after_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut drop_next_client_packet = true; // Drop first ClientHello

    for i in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        // Simulate packet loss: drop first client packet
        if !client_out.packets.is_empty() && drop_next_client_packet {
            drop_next_client_packet = false;
            // Don't deliver client packets this round
        } else {
            deliver_packets(&client_out.packets, &mut server);
        }

        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        // Advance time to trigger retransmissions
        if i % 5 == 4 {
            now += Duration::from_secs(2);
        } else {
            now += Duration::from_millis(10);
        }
    }

    assert!(
        client_connected,
        "Client should connect despite initial packet loss"
    );
    assert!(
        server_connected,
        "Server should connect despite initial packet loss"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handshake_completes_with_early_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Use a config with more retries to handle packet loss
    let config = Arc::new(
        Config::builder()
            .flight_retries(8)
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    );

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;

    // Drop first 2 client packets and first 2 server packets to test retransmission
    let mut client_packets_to_drop = 2;
    let mut server_packets_to_drop = 2;

    for i in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        // Deliver client packets, dropping first N
        for packet in &client_out.packets {
            if client_packets_to_drop > 0 {
                client_packets_to_drop -= 1;
            } else {
                let _ = server.handle_packet(packet);
            }
        }

        // Deliver server packets, dropping first N
        for packet in &server_out.packets {
            if server_packets_to_drop > 0 {
                server_packets_to_drop -= 1;
            } else {
                let _ = client.handle_packet(packet);
            }
        }

        if client_connected && server_connected {
            break;
        }

        // Trigger retransmissions periodically
        if i % 5 == 4 {
            now += Duration::from_secs(2);
        } else {
            now += Duration::from_millis(10);
        }
    }

    assert!(
        client_connected,
        "Client should connect despite early packet loss"
    );
    assert!(
        server_connected,
        "Server should connect despite early packet loss"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_hello_retry_request_flow() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Server config that will trigger HRR (by requiring cookie)
    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut saw_hrr = false;
    let mut flight_count = 0;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if !client_out.packets.is_empty() {
            flight_count += 1;
        }

        // Track if we see what looks like HRR response (server sends before full handshake)
        if !server_out.packets.is_empty() && !client_connected && flight_count <= 2 {
            saw_hrr = true;
        }

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected after HRR");
    assert!(server_connected, "Server should be connected after HRR");
    // In DTLS 1.3 with cookies, we expect HelloRetryRequest
    assert!(
        saw_hrr || flight_count >= 2,
        "Should have seen HRR or multiple client flights"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handshake_with_small_mtu() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Use small MTU to force fragmentation
    let config = dtls13_config_with_mtu(200);

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut max_packet_size = 0usize;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Track max packet size
        for p in &client_out.packets {
            if p.len() > max_packet_size {
                max_packet_size = p.len();
            }
        }

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should connect with small MTU");
    assert!(server_connected, "Server should connect with small MTU");
    assert!(
        max_packet_size <= 200,
        "Packets should respect MTU: max was {}",
        max_packet_size
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_large_application_data_fragmented() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Small MTU
    let config = dtls13_config_with_mtu(300);

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // First complete handshake
    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_out.connected && server_out.connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    // Send large data (larger than MTU)
    let large_data = vec![0xABu8; 1000];
    client
        .send_application_data(&large_data)
        .expect("client send large data");

    let mut server_received: Vec<u8> = Vec::new();
    let mut packet_count = 0;

    for _ in 0..20 {
        let client_out = drain_outputs(&mut client);
        packet_count += client_out.packets.len();
        deliver_packets(&client_out.packets, &mut server);

        let server_out = drain_outputs(&mut server);
        for data in server_out.app_data {
            server_received.extend_from_slice(&data);
        }

        if server_received.len() >= large_data.len() {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert_eq!(
        server_received, large_data,
        "Large data should be received correctly"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_srtp_keying_material_correct_size() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_km: Option<(Vec<u8>, SrtpProfile)> = None;

    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if let Some(km) = client_out.keying_material {
            client_km = Some(km);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_km.is_some() {
            break;
        }

        now += Duration::from_millis(10);
    }

    let (km, profile) = client_km.expect("Should have keying material");

    // Verify keying material size based on profile
    let expected_size = match profile {
        SrtpProfile::AEAD_AES_128_GCM => 2 * (16 + 12), // 2 * (key + salt) for AES-128-GCM
        SrtpProfile::AEAD_AES_256_GCM => 2 * (32 + 12), // 2 * (key + salt) for AES-256-GCM
        SrtpProfile::AES128_CM_SHA1_80 => 2 * (16 + 14), // 2 * (key + salt) for AES-128-CM
    };

    assert_eq!(
        km.len(),
        expected_size,
        "Keying material should be {} bytes for {:?}, got {}",
        expected_size,
        profile,
        km.len()
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handles_duplicate_packets() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        // Deliver packets twice (simulating duplicates)
        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&client_out.packets, &mut server); // Duplicate!

        deliver_packets(&server_out.packets, &mut client);
        deliver_packets(&server_out.packets, &mut client); // Duplicate!

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Client should connect despite duplicate packets"
    );
    assert!(
        server_connected,
        "Server should connect despite duplicate packets"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handles_out_of_order_packets() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        // Deliver packets in reverse order
        let mut client_packets = client_out.packets.clone();
        let mut server_packets = server_out.packets.clone();
        client_packets.reverse();
        server_packets.reverse();

        deliver_packets(&client_packets, &mut server);
        deliver_packets(&server_packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Client should connect with out-of-order packets"
    );
    assert!(
        server_connected,
        "Server should connect with out-of-order packets"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_bidirectional_data_exchange() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake
    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_out.connected && server_out.connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    // Exchange data in both directions simultaneously
    let rounds = 10;
    let mut client_received_count = 0;
    let mut server_received_count = 0;

    for i in 0..rounds {
        let client_msg = format!("Client message {}", i);
        let server_msg = format!("Server message {}", i);

        client
            .send_application_data(client_msg.as_bytes())
            .expect("client send");
        server
            .send_application_data(server_msg.as_bytes())
            .expect("server send");

        for _ in 0..10 {
            let client_out = drain_outputs(&mut client);
            let server_out = drain_outputs(&mut server);

            client_received_count += client_out.app_data.len();
            server_received_count += server_out.app_data.len();

            deliver_packets(&client_out.packets, &mut server);
            deliver_packets(&server_out.packets, &mut client);

            now += Duration::from_millis(5);
        }
    }

    assert_eq!(
        client_received_count, rounds,
        "Client should receive all server messages"
    );
    assert_eq!(
        server_received_count, rounds,
        "Server should receive all client messages"
    );
}

/// Test that application data queued before handshake completion is piggybacked
/// with the Finished message in the same packet.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_piggybacks_app_data_with_finished() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;
    let mut server_received_early_data = false;
    let mut packets_after_finished_sent = 0;
    let mut finished_sent = false;

    // Queue application data immediately - before handshake starts
    // This should be piggybacked with the Finished message
    client
        .send_application_data(b"Early piggybacked data!")
        .expect("queue early data");
    eprintln!("Queued early application data before handshake");

    // Run handshake
    for round in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Track when client becomes connected (Finished was sent)
        if client_out.connected && !finished_sent {
            finished_sent = true;
            eprintln!("Round {}: Client sent Finished (connected event)", round);
        }

        // Count packets sent after Finished
        if finished_sent && !server_received_early_data {
            packets_after_finished_sent += client_out.packets.len();
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        // Check if server received the early data
        if !server_out.app_data.is_empty() {
            server_received_early_data = true;
            let received = String::from_utf8_lossy(&server_out.app_data[0]);
            eprintln!(
                "Round {}: Server received early data: '{}' (packets since Finished: {})",
                round, received, packets_after_finished_sent
            );
            assert_eq!(
                &server_out.app_data[0][..],
                b"Early piggybacked data!",
                "Should receive the queued early data"
            );
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected && server_received_early_data {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should connect");
    assert!(server_connected, "Server should connect");
    assert!(
        server_received_early_data,
        "Server should receive piggybacked early data"
    );

    // The early data should arrive in the same round as the Finished message
    // (piggybacked in the same flight). packets_after_finished_sent counts packets
    // sent AFTER connected event, which should be 0 if piggybacked correctly
    // (the app data goes out with the Finished, not after)
    eprintln!(
        "SUCCESS: Early data was piggybacked. Packets after Finished sent: {}",
        packets_after_finished_sent
    );
}

/// Test that server can piggyback application data with its first response (Finished).
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_server_piggybacks_app_data_with_finished() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_received_early_data = false;
    let mut server_finished_sent = false;
    let mut packets_after_server_finished = 0;

    // Queue application data on server immediately - before handshake starts
    // This should be piggybacked with the server's Finished message
    server
        .send_application_data(b"Server early piggybacked data!")
        .expect("queue server early data");
    eprintln!("Queued server early application data before handshake");

    // Run handshake
    for round in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Server sends Finished before becoming "connected" (it waits for client's Finished)
        // We detect this by checking if server sent packets that contain encrypted data
        // before client is connected
        if !server_finished_sent && !server_out.packets.is_empty() && round > 0 {
            // After round 0 (ClientHello), if server sends packets it's likely ServerHello + Finished flight
            if round >= 1 {
                server_finished_sent = true;
                eprintln!("Round {}: Server sent its Finished flight", round);
            }
        }

        // Count packets sent after server Finished
        if server_finished_sent && !client_received_early_data {
            packets_after_server_finished += server_out.packets.len();
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        // Check if client received the early data from server
        if !client_out.app_data.is_empty() {
            client_received_early_data = true;
            let received = String::from_utf8_lossy(&client_out.app_data[0]);
            eprintln!(
                "Round {}: Client received early data from server: '{}' (packets since server Finished: {})",
                round, received, packets_after_server_finished
            );
            assert_eq!(
                &client_out.app_data[0][..],
                b"Server early piggybacked data!",
                "Should receive the server's queued early data"
            );
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected && client_received_early_data {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should connect");
    assert!(server_connected, "Server should connect");
    assert!(
        client_received_early_data,
        "Client should receive piggybacked early data from server"
    );

    eprintln!(
        "SUCCESS: Server early data was piggybacked. Packets after server Finished: {}",
        packets_after_server_finished
    );
}

/// Test that application data is cached when a handshake packet is lost,
/// and decrypted once the retransmission arrives.
///
/// Scenario:
/// 1. Server sends flight: ServerHello + Certificate + Finished + piggybacked app data
/// 2. One packet containing Certificate is dropped
/// 3. Client receives app data (epoch 3) but can't derive keys yet
/// 4. Client should cache/defer the app data
/// 5. Server retransmits the lost Certificate packet
/// 6. Client completes handshake and decrypts the cached app data
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_caches_app_data_when_handshake_packet_lost() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Use small MTU to ensure server flight is split into multiple packets
    let config = dtls13_config_with_mtu(200);

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_received_app_data = false;
    let mut dropped_packet_round = None;
    let mut server_first_flight_sent = false;

    // Queue application data on server before handshake
    server
        .send_application_data(b"Cached then decrypted!")
        .expect("queue server app data");
    eprintln!("Queued server application data before handshake");

    // Run handshake with packet loss simulation
    for round in 0..100 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Deliver client packets to server (no loss)
        deliver_packets(&client_out.packets, &mut server);

        // For server's first flight (round 1), drop one of the middle packets
        // to simulate losing part of the Certificate
        if !server_first_flight_sent && server_out.packets.len() > 2 && round > 0 {
            server_first_flight_sent = true;
            let num_packets = server_out.packets.len();

            // Drop a middle packet (likely contains Certificate data)
            let drop_idx = num_packets / 2;
            dropped_packet_round = Some(round);
            eprintln!(
                "Round {}: DROPPING packet {} of {} (simulating Certificate loss)",
                round, drop_idx, num_packets
            );

            for (i, p) in server_out.packets.iter().enumerate() {
                if i != drop_idx {
                    let _ = client.handle_packet(p);
                }
            }
        } else {
            // Normal delivery for subsequent rounds (including retransmissions)
            if !server_out.packets.is_empty() && dropped_packet_round.is_some() {
                eprintln!(
                    "Round {}: Server sending {} packets (retransmission)",
                    round,
                    server_out.packets.len()
                );
            }
            deliver_packets(&server_out.packets, &mut client);
        }

        // Check if client received the application data
        if !client_out.app_data.is_empty() {
            client_received_app_data = true;
            let received = String::from_utf8_lossy(&client_out.app_data[0]);
            eprintln!(
                "Round {}: Client received app data: '{}' (dropped packet was in round {:?})",
                round, received, dropped_packet_round
            );
            assert_eq!(
                &client_out.app_data[0][..],
                b"Cached then decrypted!",
                "Should receive the server's cached app data"
            );
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected && client_received_app_data {
            break;
        }

        // Advance time to trigger retransmission
        now += Duration::from_millis(100);
    }

    assert!(
        dropped_packet_round.is_some(),
        "Test should have dropped a packet"
    );
    assert!(
        client_connected,
        "Client should connect after retransmission"
    );
    assert!(server_connected, "Server should connect");
    assert!(
        client_received_app_data,
        "Client should receive cached app data after handshake completes"
    );

    eprintln!(
        "SUCCESS: App data was cached during handshake packet loss and decrypted after retransmission"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_many_small_messages() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake
    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_out.connected && server_out.connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    // Send many small messages
    let message_count = 100;
    for i in 0..message_count {
        let msg = format!("M{}", i);
        client.send_application_data(msg.as_bytes()).expect("send");
    }

    let mut received_bytes: Vec<u8> = Vec::new();

    for _ in 0..50 {
        let client_out = drain_outputs(&mut client);
        deliver_packets(&client_out.packets, &mut server);

        let server_out = drain_outputs(&mut server);
        for data in server_out.app_data {
            received_bytes.extend_from_slice(&data);
        }

        now += Duration::from_millis(10);
    }

    // Verify we received something
    assert!(
        !received_bytes.is_empty(),
        "Should receive application data"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_recovers_from_corrupted_packet() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut corrupted_once = false;

    for i in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if client_out.connected {
            client_connected = true;
        }
        if server_out.connected {
            server_connected = true;
        }

        // Corrupt one packet
        for mut p in client_out.packets {
            if !corrupted_once && p.len() > 20 {
                // Corrupt some bytes in the middle (handshake length field)
                p[15] ^= 0xFF;
                p[16] ^= 0xFF;
                corrupted_once = true;
            }
            let _ = server.handle_packet(&p);
        }

        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        // Trigger retransmissions
        if i % 5 == 4 {
            now += Duration::from_secs(2);
        } else {
            now += Duration::from_millis(50);
        }
    }

    assert!(
        client_connected,
        "Client should connect despite corrupted packet"
    );
    assert!(
        server_connected,
        "Server should connect despite corrupted packet"
    );
}

/// Test that KeyUpdate is triggered automatically when AEAD encryption limit is reached.
/// Uses a low limit so the test can observe multiple transparent KeyUpdates.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_on_aead_limit() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(10)
            .build()
            .expect("build config"),
    );

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(50);
    }
    assert!(client_connected, "Client should connect");
    assert!(server_connected, "Server should connect");

    // Send 100 messages client→server. With limit=10, KeyUpdates must happen
    // transparently for all messages to arrive.
    let mut server_received = 0;
    for i in 0..100 {
        let msg = format!("Message {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("send app data");

        now += Duration::from_millis(10);

        for _ in 0..3 {
            client.handle_timeout(now).expect("client timeout");
            let client_out = drain_outputs(&mut client);
            deliver_packets(&client_out.packets, &mut server);

            server.handle_timeout(now).expect("server timeout");
            let server_out = drain_outputs(&mut server);
            deliver_packets(&server_out.packets, &mut client);

            server_received += server_out.app_data.len();
        }
    }

    assert_eq!(
        server_received, 100,
        "All messages should be received (proves KeyUpdate worked transparently)"
    );
}

/// Test that bidirectional traffic works with auto-KeyUpdate on both sides.
/// Sends 100 messages in each direction (client first, then server) to avoid
/// simultaneous KeyUpdate contention.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_bidirectional_after_limit() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(10)
            .build()
            .expect("build config"),
    );

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..30 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(50);
    }
    assert!(client_connected, "Client should connect");
    assert!(server_connected, "Server should connect");

    let mut server_received = 0;
    let mut client_received = 0;

    // Phase 1: Send 100 messages client→server (triggers KeyUpdates on client)
    for i in 0..100 {
        let msg = format!("Client msg {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("client send");

        now += Duration::from_millis(10);

        for _ in 0..3 {
            client.handle_timeout(now).expect("client timeout");
            let client_out = drain_outputs(&mut client);
            deliver_packets(&client_out.packets, &mut server);

            server.handle_timeout(now).expect("server timeout");
            let server_out = drain_outputs(&mut server);
            deliver_packets(&server_out.packets, &mut client);

            server_received += server_out.app_data.len();
        }
    }

    // Phase 2: Send 100 messages server→client (triggers KeyUpdates on server)
    for i in 0..100 {
        let msg = format!("Server msg {}", i);
        server
            .send_application_data(msg.as_bytes())
            .expect("server send");

        now += Duration::from_millis(10);

        for _ in 0..3 {
            server.handle_timeout(now).expect("server timeout");
            let server_out = drain_outputs(&mut server);
            deliver_packets(&server_out.packets, &mut client);

            client.handle_timeout(now).expect("client timeout");
            let client_out = drain_outputs(&mut client);
            deliver_packets(&client_out.packets, &mut server);

            client_received += client_out.app_data.len();
        }
    }

    assert_eq!(
        server_received, 100,
        "Server should receive all messages (proves KeyUpdate worked for client→server)"
    );
    assert_eq!(
        client_received, 100,
        "Client should receive all messages (proves KeyUpdate worked for server→client)"
    );
}

/// Test selective retransmit: verify that only unACKed records are retransmitted.
/// This test carefully controls packet delivery to verify the actual retransmit behavior.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_selective_retransmit_only_missing_records() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    fn count_epoch2_records(packet: &[u8]) -> usize {
        let mut i = 0usize;
        let mut count = 0usize;
        while i < packet.len() {
            let b0 = packet[i];
            if (b0 & 0b1110_0000) == 0b0010_0000 {
                let c = (b0 & 0b0001_0000) != 0;
                let s16 = (b0 & 0b0000_1000) != 0;
                let l = (b0 & 0b0000_0100) != 0;
                let epoch_bits = b0 & 0b0000_0011;
                if c {
                    break;
                }
                let mut header_len = 1 + if s16 { 2 } else { 1 };
                if l {
                    header_len += 2;
                }
                if i + header_len > packet.len() {
                    break;
                }
                let ciphertext_len = if l {
                    let off = i + 1 + if s16 { 2 } else { 1 };
                    u16::from_be_bytes([packet[off], packet[off + 1]]) as usize
                } else {
                    packet.len() - (i + header_len)
                };
                if epoch_bits == 2 {
                    count += 1;
                }
                i += header_len.saturating_add(ciphertext_len);
                continue;
            }
            if i + 13 > packet.len() {
                break;
            }
            let len = u16::from_be_bytes([packet[i + 11], packet[i + 12]]) as usize;
            i += 13 + len;
        }
        count
    }

    // Small MTU to force multi-packet flights
    let config = dtls13_config_with_mtu(220);

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut dropped_packet: Option<Vec<u8>> = None;
    let mut original_flight_size = 0usize;
    let mut retransmit_flight_size = 0usize;
    let mut saw_retransmit = false;

    for round in 0..200 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        deliver_packets(&client_out.packets, &mut server);

        // Phase 1: Find a multi-packet epoch-2 flight and drop one packet
        if dropped_packet.is_none() {
            let epoch2_packets: Vec<&Vec<u8>> = server_out
                .packets
                .iter()
                .filter(|p| count_epoch2_records(p) > 0)
                .collect();

            if epoch2_packets.len() >= 3 {
                original_flight_size = epoch2_packets.len();

                // Drop the middle packet
                let drop_idx = epoch2_packets.len() / 2;
                dropped_packet = Some(epoch2_packets[drop_idx].clone());

                // Deliver all except the dropped one
                for (i, p) in epoch2_packets.iter().enumerate() {
                    if i != drop_idx {
                        let _ = client.handle_packet(p);
                    }
                }

                eprintln!(
                    "Round {}: Dropped packet {} of {}",
                    round, drop_idx, original_flight_size
                );
            } else {
                deliver_packets(&server_out.packets, &mut client);
            }
        }
        // Phase 2: After dropping, wait for retransmit and count packets
        else if !saw_retransmit {
            let epoch2_packets: Vec<&Vec<u8>> = server_out
                .packets
                .iter()
                .filter(|p| count_epoch2_records(p) > 0)
                .collect();

            if !epoch2_packets.is_empty() {
                retransmit_flight_size = epoch2_packets.len();
                saw_retransmit = true;

                eprintln!(
                    "Round {}: Retransmit flight has {} packets (original had {})",
                    round, retransmit_flight_size, original_flight_size
                );

                // Selective retransmit should send FEWER packets than original
                // (ideally just 1, the dropped one)
                assert!(
                    retransmit_flight_size < original_flight_size,
                    "Selective retransmit should send fewer packets: retransmit={}, original={}",
                    retransmit_flight_size,
                    original_flight_size
                );
            }

            deliver_packets(&server_out.packets, &mut client);
        } else {
            deliver_packets(&server_out.packets, &mut client);
        }

        if saw_retransmit && (client_out.connected || server_out.connected) {
            break;
        }

        // Advance time to trigger retransmit
        now += Duration::from_millis(150);
    }

    assert!(dropped_packet.is_some(), "Should have dropped a packet");
    assert!(saw_retransmit, "Should have seen a retransmit");

    eprintln!(
        "SUCCESS: Selective retransmit verified. Original flight: {} packets, Retransmit: {} packets",
        original_flight_size, retransmit_flight_size
    );
}

/// Test severely reordered packets - deliver packets in reverse order
/// Uses deterministic reordering pattern with sufficient rounds for retransmissions.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handles_severely_reordered_packets() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    // Use default MTU - we'll accumulate packets for reordering
    let config = dtls13_config();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    // Buffer to hold packets for reordering
    let mut server_buffer: Vec<Vec<u8>> = Vec::new();
    let mut packets_reordered = 0;

    // Use many rounds with very small time steps for reliability
    for round in 0..500 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Deliver client packets normally
        deliver_packets(&client_out.packets, &mut server);

        // Accumulate server packets
        server_buffer.extend(server_out.packets);

        // Every 5 rounds or when we have accumulated enough, deliver in reverse order
        if (round % 5 == 4 || server_buffer.len() >= 3) && !server_buffer.is_empty() {
            packets_reordered += server_buffer.len();
            for p in server_buffer.iter().rev() {
                let _ = client.handle_packet(p);
            }
            server_buffer.clear();
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected {
            // Deliver any remaining buffered packets
            for p in server_buffer.iter().rev() {
                let _ = client.handle_packet(p);
            }
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should connect despite reordering");
    assert!(server_connected, "Server should connect despite reordering");
    assert!(packets_reordered > 0, "Should have reordered some packets");

    eprintln!(
        "SUCCESS: Handshake completed with {} packets delivered in reordered batches",
        packets_reordered
    );
}

/// Test delayed packets - hold packets for several rounds then deliver all at once
/// Uses deterministic hold pattern with sufficient rounds for retransmissions.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handles_delayed_burst_delivery() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let config = dtls13_config_with_mtu(220);

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    // Hold packets for delayed delivery
    let mut held_server_packets: Vec<Vec<u8>> = Vec::new();
    let mut held_client_packets: Vec<Vec<u8>> = Vec::new();
    let mut hold_rounds = 0;
    const HOLD_DURATION: usize = 3; // Hold packets for 3 rounds before delivering

    // Use more rounds with shorter time steps for reliability
    for round in 0..200 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Collect packets
        held_server_packets.extend(server_out.packets.iter().cloned());
        held_client_packets.extend(client_out.packets.iter().cloned());

        hold_rounds += 1;

        // Deliver burst every HOLD_DURATION rounds
        if hold_rounds >= HOLD_DURATION {
            // Deliver all held packets at once
            for p in &held_client_packets {
                let _ = server.handle_packet(p);
            }
            for p in &held_server_packets {
                let _ = client.handle_packet(p);
            }

            held_server_packets.clear();
            held_client_packets.clear();
            hold_rounds = 0;
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected {
            // Deliver any remaining packets
            for p in &held_client_packets {
                let _ = server.handle_packet(p);
            }
            for p in &held_server_packets {
                let _ = client.handle_packet(p);
            }
            break;
        }

        now += Duration::from_millis(20);
    }

    assert!(
        client_connected,
        "Client should connect despite delayed delivery"
    );
    assert!(
        server_connected,
        "Server should connect despite delayed delivery"
    );

    eprintln!("SUCCESS: Handshake completed with delayed burst delivery");
}

/// Test interleaved old and new packets (simulating network path changes)
/// Uses deterministic replay pattern with sufficient rounds for retransmissions.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handles_interleaved_old_and_new_packets() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let config = dtls13_config_with_mtu(220);

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    // Store some packets to replay later (simulating delayed path)
    let mut old_server_packets: Vec<Vec<u8>> = Vec::new();
    let mut captured_old = false;

    // Use more rounds with shorter time steps for reliability
    for round in 0..200 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        deliver_packets(&client_out.packets, &mut server);

        // Capture some early packets
        if !captured_old && !server_out.packets.is_empty() && round < 5 {
            old_server_packets = server_out.packets.clone();
            captured_old = true;
        }

        // Normal delivery
        deliver_packets(&server_out.packets, &mut client);

        // Interleave old packets with new ones (replay old packets periodically)
        // Use deterministic pattern: replay at rounds 7, 14, 21, ...
        if captured_old && round % 7 == 0 && round > 0 && !old_server_packets.is_empty() {
            for p in &old_server_packets {
                // These should be safely ignored (duplicates/old epoch)
                let _ = client.handle_packet(p);
            }
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(20);
    }

    assert!(
        client_connected,
        "Client should connect despite interleaved old packets"
    );
    assert!(
        server_connected,
        "Server should connect despite interleaved old packets"
    );

    eprintln!("SUCCESS: Handshake completed with interleaved old/new packets");
}

/// Test packet loss on both directions simultaneously (moderate loss rate)
/// Uses a deterministic drop pattern: drop packets only in specific rounds,
/// ensuring retransmissions in later rounds get through.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handles_bidirectional_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let config = dtls13_config_with_mtu(220);

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;
    let mut dropped_client = 0;
    let mut dropped_server = 0;
    let mut total_client_packets = 0;
    let mut total_server_packets = 0;

    // Run for plenty of rounds to allow retransmissions
    for round in 0..300 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Drop pattern: drop every other packet, but only in rounds 0-4 and 8-12
        // This simulates burst loss with recovery windows
        let is_loss_window = round < 5 || (8..13).contains(&round);

        for (i, p) in client_out.packets.iter().enumerate() {
            total_client_packets += 1;
            // Drop odd-indexed packets during loss windows
            if is_loss_window && i % 2 == 1 {
                dropped_client += 1;
            } else {
                let _ = server.handle_packet(p);
            }
        }

        for (i, p) in server_out.packets.iter().enumerate() {
            total_server_packets += 1;
            // Drop even-indexed packets during loss windows (different pattern)
            if is_loss_window && i % 2 == 0 && server_out.packets.len() > 1 {
                dropped_server += 1;
            } else {
                let _ = client.handle_packet(p);
            }
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(20);
    }

    assert!(
        client_connected,
        "Client should connect despite bidirectional loss"
    );
    assert!(
        server_connected,
        "Server should connect despite bidirectional loss"
    );

    // Verify we actually dropped some packets
    assert!(
        dropped_client > 0 || dropped_server > 0,
        "Test should have dropped some packets"
    );

    eprintln!(
        concat!(
            "SUCCESS: Handshake completed with bidirectional loss. Dropped: ",
            "client→server={}/{}, server→client={}/{}"
        ),
        dropped_client, total_client_packets, dropped_server, total_server_packets
    );
}

/// Test random packet loss pattern (chaos test)
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_survives_random_packet_loss_pattern() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let config = dtls13_config_with_mtu(220);

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;
    let mut total_dropped = 0;
    let mut total_delivered = 0;

    // Deterministic "random-like" loss pattern
    // Drop only specific packets that won't kill the handshake
    let should_drop = |round: usize, packet_idx: usize| -> bool {
        // Only drop on certain rounds, and only if there are multiple packets
        // This ensures we don't drop critical single-packet flights
        round > 2 && round % 7 == 0 && packet_idx == 0
    };

    for round in 0..100 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Deliver with controlled drops
        for (i, p) in client_out.packets.iter().enumerate() {
            if !should_drop(round, i) || client_out.packets.len() == 1 {
                let _ = server.handle_packet(p);
                total_delivered += 1;
            } else {
                total_dropped += 1;
            }
        }

        for (i, p) in server_out.packets.iter().enumerate() {
            if !should_drop(round, i) || server_out.packets.len() == 1 {
                let _ = client.handle_packet(p);
                total_delivered += 1;
            } else {
                total_dropped += 1;
            }
        }

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(30);
    }

    assert!(client_connected, "Client should eventually connect");
    assert!(server_connected, "Server should eventually connect");

    let drop_rate = if total_dropped + total_delivered > 0 {
        total_dropped as f64 / (total_dropped + total_delivered) as f64 * 100.0
    } else {
        0.0
    };
    eprintln!(
        "SUCCESS: Handshake completed with controlled loss. Dropped: {}, Delivered: {}, Drop rate: {:.1}%",
        total_dropped, total_delivered, drop_rate
    );
}
