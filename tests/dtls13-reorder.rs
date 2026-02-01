//! DTLS 1.3 packet reordering and duplicate tests.

mod dtls13_common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::Dtls;
use dtls13_common::*;

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
    for _round in 0..200 {
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
