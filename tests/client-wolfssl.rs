//! DTLS 1.3 interop tests: dimpl client <-> WolfSSL server
//!
//! These tests verify DTLS 1.3 interoperability between dimpl (as client)
//! and WolfSSL (as server).

#![allow(unused, dead_code)]
// wolfssl-sys doesn't build on Windows
#![cfg(not(windows))]

mod wolfssl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, DtlsVersion, Output, SrtpProfile};
use wolfssl::{DtlsEvent, WolfDtlsCert};

/// Helper to drain all outputs from a dimpl endpoint.
fn drain_dimpl_outputs(endpoint: &mut Dtls) -> DrainedOutputs {
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

/// Create a DTLS 1.3 config.
fn dtls13_config() -> Arc<Config> {
    Arc::new(
        Config::builder()
            .dtls_version(DtlsVersion::Dtls13)
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    )
}

/// Create a DTLS 1.3 config with custom MTU.
fn dtls13_config_with_mtu(mtu: usize) -> Arc<Config> {
    Arc::new(
        Config::builder()
            .dtls_version(DtlsVersion::Dtls13)
            .mtu(mtu)
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    )
}

// =============================================================================
// Basic Handshake Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_handshake() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");

        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        if client_out.connected {
            client_connected = true;
        }

        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .expect("wolf server handle receive");
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                server_connected = true;
            }
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "dimpl client should be connected");
    assert!(server_connected, "WolfSSL server should be connected");
}

// NOTE: Keying material test skipped for WolfSSL interop.
// WolfSSL DTLS 1.3 server doesn't appear to support SRTP extension by default,
// so keying material export won't work without additional WolfSSL configuration.

// =============================================================================
// Application Data Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_data_exchange() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake first
    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");

        let client_out = drain_dimpl_outputs(&mut dimpl_client);

        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .expect("wolf server handle receive");
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }

        if client_out.connected && wolf_server.is_connected() {
            break;
        }

        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send data from client to server
    let test_data = b"Hello from dimpl client!";
    dimpl_client
        .send_application_data(test_data)
        .expect("write app data");

    let client_out = drain_dimpl_outputs(&mut dimpl_client);

    let mut received_data = Vec::new();
    for packet in &client_out.packets {
        wolf_server
            .handle_receive(packet, &mut wolf_events)
            .expect("wolf server handle receive");
    }

    while let Some(event) = wolf_events.pop_front() {
        if let DtlsEvent::Data(data) = event {
            received_data.extend_from_slice(&data);
        }
    }

    assert_eq!(
        received_data, test_data,
        "WolfSSL server should receive the data from dimpl client"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_bidirectional_data() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }
        if client_out.connected && wolf_server.is_connected() {
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send data both directions
    let client_data = b"Hello from dimpl client!";
    let server_data = b"Hello from WolfSSL server!";

    dimpl_client
        .send_application_data(client_data)
        .expect("client send");
    wolf_server.write(server_data).expect("server send");

    let mut client_received = Vec::new();
    let mut server_received = Vec::new();

    for _ in 0..20 {
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for data in client_out.app_data {
            client_received.extend_from_slice(&data);
        }
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }

        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                server_received.extend_from_slice(&data);
            }
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }

        if !client_received.is_empty() && !server_received.is_empty() {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert_eq!(
        client_received, server_data,
        "Client should receive server data"
    );
    assert_eq!(
        server_received, client_data,
        "Server should receive client data"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_multiple_messages() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }
        if client_out.connected && wolf_server.is_connected() {
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send multiple messages - send each one and let it be processed
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3 is a bit longer".to_vec(),
        b"Message 4".to_vec(),
        b"Message 5 - the final one".to_vec(),
    ];

    let mut server_received: Vec<Vec<u8>> = Vec::new();

    for msg in &messages {
        dimpl_client
            .send_application_data(msg)
            .expect("client send");

        // Drain and deliver each message immediately
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }

        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                server_received.push(data);
            }
        }
    }

    let expected: Vec<u8> = messages.iter().flatten().copied().collect();
    let total_received: Vec<u8> = server_received.iter().flatten().copied().collect();
    assert_eq!(total_received, expected, "All messages should be received");
}

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_many_small_messages() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }
        if client_out.connected && wolf_server.is_connected() {
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send many small messages
    let message_count = 100;
    for i in 0..message_count {
        let msg = format!("M{}", i);
        dimpl_client
            .send_application_data(msg.as_bytes())
            .expect("send");
    }

    let mut received_bytes: Vec<u8> = Vec::new();

    for _ in 0..50 {
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }

        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                received_bytes.extend_from_slice(&data);
            }
        }

        now += Duration::from_millis(10);
    }

    assert!(
        !received_bytes.is_empty(),
        "Should receive application data"
    );
}

// =============================================================================
// Packet Loss and Retransmission Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_retransmit_on_timeout() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();

    // Get initial ClientHello
    dimpl_client.handle_timeout(now).expect("client start");
    dimpl_client.handle_timeout(now).expect("client arm");
    let initial_out = drain_dimpl_outputs(&mut dimpl_client);
    assert!(
        !initial_out.packets.is_empty(),
        "Client should send ClientHello"
    );

    // Don't deliver to server, trigger timeout
    now += Duration::from_secs(2);
    dimpl_client.handle_timeout(now).expect("client timeout");

    // Should get retransmitted packets
    let retransmit_out = drain_dimpl_outputs(&mut dimpl_client);
    assert!(
        !retransmit_out.packets.is_empty(),
        "Client should retransmit on timeout"
    );

    assert_eq!(
        initial_out.packets.len(),
        retransmit_out.packets.len(),
        "Retransmit should have same packet count"
    );

    // Now actually complete the handshake to verify everything works
    let wolf_events = &mut VecDeque::new();

    // First, deliver the retransmitted packets we already have
    for packet in &retransmit_out.packets {
        wolf_server.handle_receive(packet, wolf_events).unwrap();
    }
    while let Some(packet) = wolf_server.poll_datagram() {
        let _ = dimpl_client.handle_packet(&packet);
    }
    wolf_events.clear();

    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server.handle_receive(packet, wolf_events).unwrap();
        }
        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }
        if client_out.connected && wolf_server.is_connected() {
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    assert!(wolf_server.is_connected(), "Should eventually connect");
}

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_handshake_after_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut drop_next_packet = true;

    for i in 0..60 {
        dimpl_client.handle_timeout(now).expect("client timeout");

        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        if client_out.connected {
            client_connected = true;
        }

        // Drop first packet
        if !client_out.packets.is_empty() && drop_next_packet {
            drop_next_packet = false;
        } else {
            for packet in &client_out.packets {
                wolf_server
                    .handle_receive(packet, &mut wolf_events)
                    .unwrap();
            }
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                server_connected = true;
            }
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
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
        "Client should connect despite packet loss"
    );
    assert!(
        server_connected,
        "Server should connect despite packet loss"
    );
}

// =============================================================================
// Duplicate and Out-of-Order Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_handles_duplicates() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");

        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        if client_out.connected {
            client_connected = true;
        }

        // Send packets twice (duplicates)
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                server_connected = true;
            }
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
            let _ = dimpl_client.handle_packet(&packet); // Duplicate
        }

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should connect despite duplicates");
    assert!(server_connected, "Server should connect despite duplicates");
}

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_handles_out_of_order() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // First complete handshake normally
    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }
        if client_out.connected && wolf_server.is_connected() {
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    assert!(wolf_server.is_connected(), "Handshake should complete");

    // Now test out-of-order application data delivery
    // Send multiple messages from client, deliver to server in reverse order
    dimpl_client
        .send_application_data(b"First")
        .expect("send 1");
    dimpl_client
        .send_application_data(b"Second")
        .expect("send 2");
    dimpl_client
        .send_application_data(b"Third")
        .expect("send 3");

    let client_out = drain_dimpl_outputs(&mut dimpl_client);

    // Deliver packets in reverse order (if there are multiple)
    let mut packets = client_out.packets.clone();
    packets.reverse();
    for packet in &packets {
        wolf_server
            .handle_receive(packet, &mut wolf_events)
            .unwrap();
    }

    let mut server_received: Vec<u8> = Vec::new();
    while let Some(event) = wolf_events.pop_front() {
        if let DtlsEvent::Data(data) = event {
            server_received.extend_from_slice(&data);
        }
    }

    // DTLS should handle reordering - all data should arrive
    assert!(
        !server_received.is_empty(),
        "Server should receive data despite reordering"
    );
}

// =============================================================================
// MTU and Fragmentation Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_small_mtu() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    // Use 600 MTU - large enough for handshake but smaller than default
    let config = dtls13_config_with_mtu(600);

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut max_client_packet_size = 0usize;

    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");

        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        if client_out.connected {
            client_connected = true;
        }

        for p in &client_out.packets {
            if p.len() > max_client_packet_size {
                max_client_packet_size = p.len();
            }
        }

        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                server_connected = true;
            }
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should connect with small MTU");
    assert!(server_connected, "Server should connect with small MTU");
    // Only check that dimpl client respects MTU (WolfSSL may not)
    assert!(
        max_client_packet_size <= 600,
        "Client packets should respect MTU: max was {}",
        max_client_packet_size
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_large_data_fragmented() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config_with_mtu(300);

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    // Complete handshake
    for _ in 0..50 {
        dimpl_client.handle_timeout(now).expect("client timeout");
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }
        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }
        if client_out.connected && wolf_server.is_connected() {
            break;
        }
        wolf_events.clear();
        now += Duration::from_millis(10);
    }

    // Send large data
    let large_data = vec![0xABu8; 1000];
    dimpl_client
        .send_application_data(&large_data)
        .expect("send large data");

    let mut server_received: Vec<u8> = Vec::new();
    let mut packet_count = 0;

    for _ in 0..20 {
        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        packet_count += client_out.packets.len();
        for packet in &client_out.packets {
            wolf_server
                .handle_receive(packet, &mut wolf_events)
                .unwrap();
        }

        while let Some(event) = wolf_events.pop_front() {
            if let DtlsEvent::Data(data) = event {
                server_received.extend_from_slice(&data);
            }
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
    assert!(
        packet_count >= 2,
        "Large data should be split into multiple packets: {}",
        packet_count
    );
}

// =============================================================================
// Error Recovery Tests
// =============================================================================

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_recovers_from_corruption() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    let config = dtls13_config();

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut corrupted_once = false;

    for i in 0..60 {
        dimpl_client.handle_timeout(now).expect("client timeout");

        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        if client_out.connected {
            client_connected = true;
        }

        // Corrupt one packet
        for mut p in client_out.packets {
            if !corrupted_once && p.len() > 20 {
                p[15] ^= 0xFF;
                p[16] ^= 0xFF;
                corrupted_once = true;
            }
            let _ = wolf_server.handle_receive(&p, &mut wolf_events);
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                server_connected = true;
            }
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
        }

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

    assert!(client_connected, "Client should connect despite corruption");
    assert!(server_connected, "Server should connect despite corruption");
}

#[test]
#[cfg(feature = "rcgen")]
fn client_wolfssl_dtls13_handshake_with_early_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_dimpl_cert = generate_self_signed_certificate().expect("gen server cert");

    let wolf_server_cert = WolfDtlsCert::new(
        server_dimpl_cert.certificate.clone(),
        server_dimpl_cert.private_key.clone(),
    );

    let mut wolf_server = wolf_server_cert
        .new_dtls13_impl(true)
        .expect("Failed to create WolfSSL server");

    // Use more retries for lossy conditions
    let config = Arc::new(
        Config::builder()
            .dtls_version(DtlsVersion::Dtls13)
            .flight_retries(8)
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    );

    let mut dimpl_client = Dtls::new(config, client_cert);
    dimpl_client.set_active(true);

    let mut now = Instant::now();
    let mut wolf_events = VecDeque::new();

    let mut client_connected = false;
    let mut server_connected = false;

    // Drop first 3 packets to test retransmission recovery
    let mut packets_to_drop = 3;

    for i in 0..60 {
        let _ = dimpl_client.handle_timeout(now);

        let client_out = drain_dimpl_outputs(&mut dimpl_client);
        if client_out.connected {
            client_connected = true;
        }

        // Drop first N packets, then deliver all
        for packet in &client_out.packets {
            if packets_to_drop > 0 {
                packets_to_drop -= 1;
            } else {
                wolf_server
                    .handle_receive(packet, &mut wolf_events)
                    .unwrap();
            }
        }

        while let Some(event) = wolf_events.pop_front() {
            if matches!(event, DtlsEvent::Connected) {
                server_connected = true;
            }
        }

        while let Some(packet) = wolf_server.poll_datagram() {
            let _ = dimpl_client.handle_packet(&packet);
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
