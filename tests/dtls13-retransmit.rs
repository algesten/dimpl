//! DTLS 1.3 retransmission tests.

mod dtls13_common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls};
use dtls13_common::*;

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
