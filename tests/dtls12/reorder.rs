//! DTLS 1.2 packet reordering, replay, and duplicate tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::Dtls;

use crate::common::*;

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_handles_duplicate_packets() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..80 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        // Deliver originals first
        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        // Drain any events triggered by the original delivery before
        // injecting duplicates, so the state machine has advanced past
        // the flight boundary.
        let server_mid = drain_outputs(&mut server);
        let client_mid = drain_outputs(&mut client);
        server_connected |= server_mid.connected;
        client_connected |= client_mid.connected;

        // Now deliver duplicates -- these should be tolerated
        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(20);
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
fn dtls12_handles_out_of_order_packets() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

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
fn dtls12_replay_window_rejects_old_app_data() {
    //! After handshake, send 100 app data messages from client to server.
    //! Then replay the very first encrypted packet. The replayed packet
    //! should be silently dropped (not delivered as application data again).

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

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

    // Send the first message and capture its encrypted packet
    client
        .send_application_data(b"message 1")
        .expect("send message 1");
    let first_out = drain_outputs(&mut client);
    assert!(
        !first_out.packets.is_empty(),
        "Should have packets for message 1"
    );
    let early_packet = first_out.packets[0].clone();

    // Deliver and verify it arrives
    deliver_packets(&first_out.packets, &mut server);
    let server_out = drain_outputs(&mut server);
    assert_eq!(
        server_out.app_data.len(),
        1,
        "Server should receive message 1"
    );

    // Send 99 more messages to advance the replay window well past the first
    for i in 2..=100 {
        let msg = format!("message {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("send message");

        let client_out = drain_outputs(&mut client);
        deliver_packets(&client_out.packets, &mut server);
        let server_out = drain_outputs(&mut server);
        assert!(
            !server_out.app_data.is_empty(),
            "Server should receive message {}",
            i
        );
    }

    // Now replay the very first encrypted packet
    let _ = server.handle_packet(&early_packet);
    let replay_out = drain_outputs(&mut server);

    assert!(
        replay_out.app_data.is_empty(),
        "Replayed old packet should NOT produce application data (replay protection)"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_replay_window_rejects_duplicate_app_data() {
    //! After handshake, send one app data message. Deliver it, then deliver
    //! the exact same encrypted packet again. Only one copy should be received.

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

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

    // Send a single app data message
    client
        .send_application_data(b"only once")
        .expect("send app data");
    let client_out = drain_outputs(&mut client);
    assert!(
        !client_out.packets.is_empty(),
        "Should have packets for app data"
    );

    // Save the encrypted packet for replay
    let encrypted_packet = client_out.packets[0].clone();

    // First delivery -- should produce app data
    let _ = server.handle_packet(&encrypted_packet);
    let first_out = drain_outputs(&mut server);
    assert_eq!(
        first_out.app_data.len(),
        1,
        "First delivery should produce exactly one app data"
    );
    assert_eq!(first_out.app_data[0], b"only once");

    // Second delivery of exact same packet -- should be silently dropped
    let _ = server.handle_packet(&encrypted_packet);
    let dup_out = drain_outputs(&mut server);
    assert!(
        dup_out.app_data.is_empty(),
        "Duplicate packet should NOT produce application data (replay protection)"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_handles_delayed_burst_delivery() {
    //! During handshake, hold all packets for 3 rounds of timeouts, then
    //! deliver them all at once in a burst. Verify handshake still completes.

    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = dtls12_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);
    let mut client_connected = false;
    let mut server_connected = false;

    // Hold packets for delayed delivery
    let mut held_server_packets: Vec<Vec<u8>> = Vec::new();
    let mut held_client_packets: Vec<Vec<u8>> = Vec::new();
    let mut hold_rounds = 0;
    const HOLD_DURATION: usize = 3; // Hold packets for 3 rounds before delivering

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
}

/// Reverse the order of the records in a DTLS 1.2 datagram (whole records only).
#[cfg(feature = "rcgen")]
fn reverse_records(datagram: &[u8]) -> Vec<u8> {
    let mut records = Vec::new();
    let mut i = 0usize;
    while i + 13 <= datagram.len() {
        let len = u16::from_be_bytes([datagram[i + 11], datagram[i + 12]]) as usize;
        let end = (i + 13 + len).min(datagram.len());
        records.push(&datagram[i..end]);
        i = end;
    }
    records.into_iter().rev().flatten().copied().collect()
}

/// The most datagrams one side may send in [`run_reversed_final_flight`]'s 3 s.
///
/// A side sends at most 3 flights, and each flight goes out once, plus at most one early
/// resend per retransmission timer period when duplicates arrive (two periods fit in 3 s),
/// plus a resend of the final flight for each duplicate of the peer's final flight. At
/// MTU 300 a flight is at most 5 datagrams. A resend storm sends one flight per round trip
/// (here one per 10 ms step, so hundreds).
#[cfg(feature = "rcgen")]
const MAX_DATAGRAMS_PER_SIDE: usize = 30;

/// Run a handshake where the first client datagram carrying ChangeCipherSpec has its
/// records reversed (Finished before ChangeCipherSpec, and the flight's handshake
/// messages in reverse order). With `duplicate`, every datagram is also delivered twice.
///
/// Asserts that neither side sends more than [`MAX_DATAGRAMS_PER_SIDE`] datagrams over
/// 3 s, and returns the time until both sides are connected.
#[cfg(feature = "rcgen")]
fn run_reversed_final_flight(config: Arc<dimpl::Config>, duplicate: bool) -> Duration {
    use dimpl::certificate::generate_self_signed_certificate;

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mtu = config.mtu();
    let cookie = config.use_server_cookie();

    let start = Instant::now();
    let mut now = start;

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut reversed = false;
    let mut client_connected = false;
    let mut server_connected = false;
    let mut connected_after = None;
    let mut client_sent = 0;
    let mut server_sent = 0;

    // 3 s: past the first retransmission timer, so a resend storm cannot hide.
    for _ in 0..300 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;
        if client_connected && server_connected && connected_after.is_none() {
            connected_after = Some(now - start);
        }

        client_sent += client_out.packets.len();
        server_sent += server_out.packets.len();

        let copies = if duplicate { 2 } else { 1 };

        for p in &client_out.packets {
            let has_ccs = parse_records(p).iter().any(|r| r.ctype == 20);
            let p = if has_ccs && !reversed {
                reversed = true;
                reverse_records(p)
            } else {
                p.clone()
            };
            for _ in 0..copies {
                let _ = server.handle_packet(&p);
            }
        }
        for p in &server_out.packets {
            for _ in 0..copies {
                let _ = client.handle_packet(p);
            }
        }

        now += Duration::from_millis(10);
    }

    println!(
        "mtu {mtu} cookie {cookie} duplicate {duplicate}: client sent {client_sent}, \
         server sent {server_sent} datagrams, connected after {connected_after:?}"
    );

    assert!(
        reversed,
        "the client's final flight should have been reversed"
    );
    assert!(
        client_sent <= MAX_DATAGRAMS_PER_SIDE && server_sent <= MAX_DATAGRAMS_PER_SIDE,
        "mtu {mtu} cookie {cookie} duplicate {duplicate}: resend storm: client sent \
         {client_sent}, server sent {server_sent} datagrams in 3 s (at most \
         {MAX_DATAGRAMS_PER_SIDE} each)"
    );

    connected_after.unwrap_or_else(|| {
        panic!(
            "mtu {mtu} cookie {cookie} duplicate {duplicate}: handshake should complete \
             with a reversed final flight (client sent {client_sent}, server sent \
             {server_sent} datagrams)"
        )
    })
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_reversed_final_flight_completes_without_resend_storm() {
    //! RFC 6347 §4.2.2: handshake messages are processed in message_seq order whatever
    //! order their records arrive in, and a record of the next epoch (Finished) that
    //! arrives before the ChangeCipherSpec starting that epoch waits for it. One
    //! reordered copy of the final flight must complete the handshake on its own: no
    //! retransmission, and (RFC 6347 §4.2.4) no flights bounced between the peers, also
    //! when the network duplicates datagrams.

    let _ = env_logger::try_init();

    let configs = [
        // As WebRTC stacks use it (ICE has already proved return routability).
        Arc::new(
            dimpl::Config::builder()
                .use_server_cookie(false)
                .build()
                .expect("Failed to build config"),
        ),
        dtls12_config(),
        // Small MTU: the final flight spans several datagrams and fragments.
        dtls12_config_with_mtu(300),
    ];

    for config in configs {
        for duplicate in [false, true] {
            let mtu = config.mtu();
            let connected_after = run_reversed_final_flight(Arc::clone(&config), duplicate);

            // Below the 1 s initial retransmission timer (less its jitter): the reordered
            // copy alone completed the handshake.
            assert!(
                connected_after < Duration::from_millis(500),
                "mtu {mtu} duplicate {duplicate}: handshake should complete without a \
                 retransmission, took {connected_after:?}"
            );
        }
    }
}
