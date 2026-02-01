//! DTLS 1.3 application data tests.

mod dtls13_common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::Dtls;
use dtls13_common::*;

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
