//! DTLS 1.3 fragmentation tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls};

use crate::common::*;

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_handshake_with_small_mtu() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Use small MTU to force fragmentation
    let config = dtls13_config_with_mtu(200);

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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
    let mut _packet_count = 0;

    for _ in 0..20 {
        let client_out = drain_outputs(&mut client);
        _packet_count += client_out.packets.len();
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
fn dtls13_fragmentation_during_hrr() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Small MTU to force fragmentation during HRR handshake
    let config = dtls13_config_with_mtu(200);

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut max_packet_size = 0usize;
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

        // Track max packet size
        for p in &client_out.packets {
            if p.len() > max_packet_size {
                max_packet_size = p.len();
            }
        }
        for p in &server_out.packets {
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

    assert!(
        client_connected,
        "Client should connect with HRR and small MTU"
    );
    assert!(
        server_connected,
        "Server should connect with HRR and small MTU"
    );
    assert!(
        max_packet_size <= 200,
        "Packets should respect MTU: max was {}",
        max_packet_size
    );
    assert!(
        saw_hrr || flight_count >= 2,
        "Should have seen HRR or multiple client flights"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_fragmented_handshake_with_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Small MTU to force fragmentation, extra retries and longer handshake timeout
    // to survive loss and retransmission delays
    let config = Arc::new(
        Config::builder()
            .mtu(200)
            .flight_retries(8)
            .handshake_timeout(Duration::from_secs(120))
            .build()
            .expect("Failed to build DTLS 1.3 config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut dropped_client = 0;
    let mut dropped_server = 0;

    // Track the packet count of the last flight from each side.
    // When the count changes, it's a new flight (different protocol step).
    // We drop the first packet only on the first transmission of each new flight;
    // retransmissions (same packet count) are delivered in full.
    let mut prev_client_count = 0usize;
    let mut client_drop_armed = false;
    let mut prev_server_count = 0usize;
    let mut server_drop_armed = false;

    for i in 0..120 {
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

        // Detect new flight from client: packet count changed from previous
        if !client_out.packets.is_empty() && client_out.packets.len() != prev_client_count {
            client_drop_armed = true;
            prev_client_count = client_out.packets.len();
        }

        // Deliver client packets, dropping the first of each new flight
        if !client_out.packets.is_empty() && client_drop_armed && client_out.packets.len() > 1 {
            client_drop_armed = false;
            dropped_client += 1;
            for p in &client_out.packets[1..] {
                let _ = server.handle_packet(p);
            }
        } else {
            deliver_packets(&client_out.packets, &mut server);
        }

        // Detect new flight from server: packet count changed from previous
        if !server_out.packets.is_empty() && server_out.packets.len() != prev_server_count {
            server_drop_armed = true;
            prev_server_count = server_out.packets.len();
        }

        // Deliver server packets, dropping the first of each new flight
        if !server_out.packets.is_empty() && server_drop_armed && server_out.packets.len() > 1 {
            server_drop_armed = false;
            dropped_server += 1;
            for p in &server_out.packets[1..] {
                let _ = client.handle_packet(p);
            }
        } else {
            deliver_packets(&server_out.packets, &mut client);
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
        "Client should connect despite fragmented packet loss"
    );
    assert!(
        server_connected,
        "Server should connect despite fragmented packet loss"
    );
    assert!(
        dropped_client > 0,
        "Should have dropped at least one client packet"
    );
    assert!(
        dropped_server > 0,
        "Should have dropped at least one server packet"
    );
}
