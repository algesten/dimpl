//! DTLS 1.3 interop test: WolfSSL client <-> dimpl server
//!
//! These tests verify that dimpl (as server) can interoperate with WolfSSL (as client)
//! for DTLS 1.3 connections.

#![allow(unused, dead_code)]
// wolfssl-sys doesn't build on Windows
#![cfg(not(windows))]

mod wolfssl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, DtlsVersion, Output};
use wolfssl::{DtlsEvent, WolfDtlsCert};

/// Helper struct to collect all outputs from a dimpl endpoint
struct DrainedOutputs {
    packets: Vec<Vec<u8>>,
    connected: bool,
    app_data: Vec<Vec<u8>>,
}

/// Helper to drain all outputs from a dimpl endpoint.
fn drain_dimpl_outputs(endpoint: &mut Dtls) -> DrainedOutputs {
    let mut result = DrainedOutputs {
        packets: Vec::new(),
        connected: false,
        app_data: Vec::new(),
    };
    let mut buf = vec![0u8; 2048];

    loop {
        match endpoint.poll_output(&mut buf) {
            Output::Packet(p) => result.packets.push(p.to_vec()),
            Output::Connected => result.connected = true,
            Output::ApplicationData(data) => result.app_data.push(data.to_vec()),
            Output::Timeout(_) => break,
            _ => {}
        }
    }

    result
}

/// Create a standard DTLS 1.3 server config
fn dtls13_config() -> Arc<Config> {
    Arc::new(
        Config::builder()
            .dtls_version(DtlsVersion::Dtls13)
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    )
}

// =============================================================================
// Basic Handshake Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_handshake() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..50 {
        dimpl_server.handle_timeout(now).expect("server timeout");

        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }

        dimpl_server.handle_timeout(now).expect("server timeout");

        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        if server_out.connected {
            server_connected = true;
        }

        for packet in &server_out.packets {
            wolf_client
                .handle_receive(packet, &mut wolf_events)
                .expect("wolf client handle receive");
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                client_connected = true;
            }
        }

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(server_connected, "dimpl server should be connected");
    assert!(client_connected, "WolfSSL client should be connected");
}

// =============================================================================
// Application Data Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_data_exchange() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_server.handle_timeout(now).expect("server timeout");
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }
        dimpl_server.handle_timeout(now).expect("server timeout");
        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for packet in &server_out.packets {
            wolf_client
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        if server_out.connected && wolf_client.is_connected() {
            wolf_events.clear();
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send data from WolfSSL client to dimpl server
    let test_data = b"Hello from WolfSSL client!";
    wolf_client
        .write(test_data)
        .expect("write from wolf client");

    while let Some(packet) = wolf_client.poll_datagram() {
        let _ = dimpl_server.handle_packet(&packet);
    }

    let server_out = drain_dimpl_outputs(&mut dimpl_server);
    let received: Vec<u8> = server_out.app_data.into_iter().flatten().collect();

    assert_eq!(
        received, test_data,
        "dimpl server should receive the data from WolfSSL client"
    );
}

// NOTE: This test is commented out due to WolfSSL state machine quirks
// WolfSSL returns error -441 "Application data is available for reading"
// when trying to receive new data after a bidirectional exchange.
// The data_exchange test verifies one-way data transfer works.
/*
#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_bidirectional_data() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_server.handle_timeout(now).expect("server timeout");
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }
        dimpl_server.handle_timeout(now).expect("server timeout");
        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for packet in &server_out.packets {
            wolf_client.handle_receive(packet, &mut wolf_events).unwrap();
        }
        if server_out.connected && wolf_client.is_connected() {
            wolf_events.clear();
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send data from client to server
    let client_data = b"Hello from WolfSSL!";
    wolf_client.write(client_data).expect("client write");

    // Send data from server to client
    let server_data = b"Hello from dimpl!";
    dimpl_server.send_application_data(server_data).expect("server send");

    // Drain any pending data in WolfSSL before sending new packets
    wolf_client.drain_pending_data(&mut wolf_events);
    while let Some(event) = wolf_events.pop_front() {
        eprintln!("Drained pending event: {:?}", std::mem::discriminant(&event));
    }

    // Immediately drain and deliver server packets
    let initial_out = drain_dimpl_outputs(&mut dimpl_server);
    for packet in &initial_out.packets {
        // Drain before each receive
        wolf_client.drain_pending_data(&mut wolf_events);
        match wolf_client.handle_receive(packet, &mut wolf_events) {
            Ok(()) => (),
            Err(e) => eprintln!("handle_receive error: {:?}", e),
        }
    }

    let mut client_received: Vec<u8> = Vec::new();
    let mut server_received: Vec<u8> = Vec::new();

    // Collect events from initial delivery
    while let Some(event) = wolf_events.pop_front() {
        if let DtlsEvent::Data(data) = event {
            client_received.extend_from_slice(&data);
        }
    }

    for _ in 0..100 {
        // Client -> Server: drain WolfSSL output first
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }

        // Process server and get outputs
        dimpl_server.handle_timeout(now).expect("server timeout");
        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for data in server_out.app_data {
            server_received.extend_from_slice(&data);
        }

        // Drain any pending events from previous iteration
        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                client_received.extend_from_slice(&data);
            }
        }

        // Server -> Client
        for packet in &server_out.packets {
            let _ = wolf_client.handle_receive(packet, &mut wolf_events);
        }

        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                client_received.extend_from_slice(&data);
            }
        }

        if !client_received.is_empty() && !server_received.is_empty() {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert_eq!(client_received, server_data, "Client should receive server data");
    assert_eq!(server_received, client_data, "Server should receive client data");
}
*/

#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_multiple_messages() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_server.handle_timeout(now).expect("server timeout");
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }
        dimpl_server.handle_timeout(now).expect("server timeout");
        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for packet in &server_out.packets {
            wolf_client
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        if server_out.connected && wolf_client.is_connected() {
            wolf_events.clear();
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send multiple messages from WolfSSL client
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3 is a bit longer".to_vec(),
        b"Message 4".to_vec(),
        b"Message 5 - the final one".to_vec(),
    ];

    let mut server_received: Vec<Vec<u8>> = Vec::new();

    for msg in &messages {
        wolf_client.write(msg).expect("client write");

        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }

        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for data in server_out.app_data {
            server_received.push(data);
        }
    }

    let expected: Vec<u8> = messages.iter().flatten().copied().collect();
    let total_received: Vec<u8> = server_received.iter().flatten().copied().collect();
    assert_eq!(total_received, expected, "All messages should be received");
}

// =============================================================================
// Packet Loss and Retransmission Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_handshake_after_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut drop_next_server_packet = true;

    for i in 0..60 {
        dimpl_server.handle_timeout(now).expect("server timeout");

        // Always deliver client packets to server
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }

        dimpl_server.handle_timeout(now).expect("server timeout");

        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        if server_out.connected {
            server_connected = true;
        }

        // Drop first server packet (drop server->client)
        for packet in &server_out.packets {
            if drop_next_server_packet && !server_out.packets.is_empty() {
                drop_next_server_packet = false;
                continue;
            }
            let _ = wolf_client.handle_receive(packet, &mut wolf_events);
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                client_connected = true;
            }
        }

        if client_connected && server_connected {
            break;
        }

        // Trigger server retransmissions
        if i % 5 == 4 {
            now += Duration::from_secs(2);
        } else {
            now += Duration::from_millis(10);
        }
    }

    assert!(
        server_connected,
        "Server should connect despite packet loss"
    );
    assert!(
        client_connected,
        "Client should connect despite packet loss"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_handshake_with_early_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    // Use more retries for lossy conditions
    let config = Arc::new(
        Config::builder()
            .dtls_version(DtlsVersion::Dtls13)
            .flight_retries(8)
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    );
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;

    // Drop first 3 server packets to test retransmission recovery
    let mut packets_to_drop = 3;

    for i in 0..60 {
        let _ = dimpl_server.handle_timeout(now);

        // Always deliver client packets to server
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }

        let _ = dimpl_server.handle_timeout(now);

        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        if server_out.connected {
            server_connected = true;
        }

        // Drop first N server packets, then deliver all
        for packet in &server_out.packets {
            if packets_to_drop > 0 {
                packets_to_drop -= 1;
            } else {
                let _ = wolf_client.handle_receive(packet, &mut wolf_events);
            }
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                client_connected = true;
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
        server_connected,
        "Server should connect despite early packet loss"
    );
    assert!(
        client_connected,
        "Client should connect despite early packet loss"
    );
}

// =============================================================================
// Duplicate and Corruption Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_handles_duplicates() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..50 {
        dimpl_server.handle_timeout(now).expect("server timeout");

        // Send client packets twice (duplicates)
        let mut client_packets = Vec::new();
        while let Some(packet) = wolf_client.poll_datagram() {
            client_packets.push(packet);
        }
        for packet in &client_packets {
            let _ = dimpl_server.handle_packet(packet);
            let _ = dimpl_server.handle_packet(packet); // Duplicate
        }

        dimpl_server.handle_timeout(now).expect("server timeout");

        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        if server_out.connected {
            server_connected = true;
        }

        // Send server packets twice too
        for packet in &server_out.packets {
            wolf_client
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
            wolf_client
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                client_connected = true;
            }
        }

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(server_connected, "Server should connect despite duplicates");
    assert!(client_connected, "Client should connect despite duplicates");
}

// NOTE: This test is skipped because WolfSSL doesn't recover well from corruption
// during handshake - the corrupted server packet causes the handshake to stall
// without proper retransmission from the WolfSSL client side.
// The client-wolfssl tests verify corruption recovery from dimpl's perspective.
/*
#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_recovers_from_corruption() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut corrupt_next_server_packet = true;

    for i in 0..100 {
        let _ = dimpl_server.handle_timeout(now);

        // Always deliver client packets normally
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }

        let _ = dimpl_server.handle_timeout(now);

        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        if server_out.connected {
            server_connected = true;
        }

        for packet in &server_out.packets {
            if corrupt_next_server_packet && !packet.is_empty() {
                // Corrupt first server packet - dimpl should retransmit on timeout
                let mut corrupted = packet.clone();
                let idx = corrupted.len() / 2;
                corrupted[idx] ^= 0xFF;
                corrupt_next_server_packet = false;
                // WolfSSL will reject this, but we continue anyway
                let _ = wolf_client.handle_receive(&corrupted, &mut wolf_events);
            } else {
                let _ = wolf_client.handle_receive(packet, &mut wolf_events);
            }
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                client_connected = true;
            }
        }

        if client_connected && server_connected {
            break;
        }

        // Trigger retransmissions more frequently
        if i % 3 == 2 {
            now += Duration::from_millis(500);
        } else {
            now += Duration::from_millis(20);
        }
    }

    assert!(server_connected, "Server should connect despite corruption");
    assert!(client_connected, "Client should connect despite corruption");
}
*/

// =============================================================================
// Large Data Tests
// =============================================================================

// NOTE: This test is skipped because WolfSSL's wrapper has issues with
// receiving large fragmented data - error -441 "Application data is available"
// occurs after receiving partial data. The client-wolfssl tests verify
// large data handling from dimpl's perspective.
/*
#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_large_data_fragmented() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_server.handle_timeout(now).expect("server timeout");
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }
        dimpl_server.handle_timeout(now).expect("server timeout");
        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for packet in &server_out.packets {
            wolf_client.handle_receive(packet, &mut wolf_events).unwrap();
        }
        if server_out.connected && wolf_client.is_connected() {
            wolf_events.clear();
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send large data from dimpl server to WolfSSL client
    let large_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    dimpl_server.send_application_data(&large_data).expect("server send large data");

    let mut client_received: Vec<u8> = Vec::new();

    for _ in 0..500 {
        let server_out = drain_dimpl_outputs(&mut dimpl_server);

        // Drain events before calling handle_receive
        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                client_received.extend_from_slice(&data);
            }
        }

        for packet in &server_out.packets {
            let _ = wolf_client.handle_receive(packet, &mut wolf_events);
        }

        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                client_received.extend_from_slice(&data);
            }
        }

        if client_received.len() >= large_data.len() {
            break;
        }

        now += Duration::from_millis(1);
    }

    assert_eq!(
        client_received.len(),
        large_data.len(),
        "Client should receive all large data"
    );
    assert_eq!(client_received, large_data, "Data should match");
}
*/

#[test]
#[cfg(feature = "rcgen")]
fn server_wolfssl_dtls13_many_small_messages() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_dimpl_cert = generate_self_signed_certificate().expect("gen client cert");

    let wolf_client_cert = WolfDtlsCert::new(
        client_dimpl_cert.certificate.clone(),
        client_dimpl_cert.private_key.clone(),
    );

    let mut wolf_client = wolf_client_cert
        .new_dtls13_impl(false)
        .expect("Failed to create WolfSSL client");

    wolf_client.initiate().expect("initiate wolf client");

    let config = dtls13_config();
    let mut dimpl_server = Dtls::new(config, server_cert);
    dimpl_server.set_active(false);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_server.handle_timeout(now).expect("server timeout");
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }
        dimpl_server.handle_timeout(now).expect("server timeout");
        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for packet in &server_out.packets {
            wolf_client
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        if server_out.connected && wolf_client.is_connected() {
            wolf_events.clear();
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send many small messages from WolfSSL client
    let message_count = 100;
    for i in 0..message_count {
        let msg = format!("M{}", i);
        wolf_client.write(msg.as_bytes()).expect("send");
    }

    let mut received_bytes: Vec<u8> = Vec::new();

    for _ in 0..100 {
        while let Some(packet) = wolf_client.poll_datagram() {
            let _ = dimpl_server.handle_packet(&packet);
        }

        let server_out = drain_dimpl_outputs(&mut dimpl_server);
        for data in server_out.app_data {
            received_bytes.extend_from_slice(&data);
        }

        now += Duration::from_millis(10);
    }

    assert!(
        !received_bytes.is_empty(),
        "Should receive application data"
    );
}
