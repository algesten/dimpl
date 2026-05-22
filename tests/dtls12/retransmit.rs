//! DTLS 1.2 retransmission and duplicate handling tests.

#![allow(unused)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, Output};

use crate::common::*;

#[cfg(feature = "rcgen")]
struct FinalFlightResend {
    client: Dtls,
    server: Dtls,
    f6_init: Vec<Vec<u8>>,
    f6_resend: Vec<Vec<u8>>,
    stale_epoch0_handshake: Vec<u8>,
}

#[cfg(feature = "rcgen")]
fn prepare_server_final_flight_resend(max_queue_rx: usize) -> FinalFlightResend {
    use dimpl::certificate::generate_self_signed_certificate;

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config_client = Arc::new(
        Config::builder()
            .mtu(115)
            .max_queue_rx(max_queue_rx)
            .build()
            .expect("Failed to build config"),
    );
    let config_server = Arc::new(
        Config::builder()
            .mtu(115)
            .max_queue_rx(max_queue_rx)
            .build()
            .expect("Failed to build config"),
    );

    let mut client = Dtls::new_12(config_client, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config_server, server_cert, now);
    server.set_active(false);

    client.handle_timeout(now).expect("client timeout start");
    client.handle_timeout(now).expect("client arm flight 1");
    let f1 = collect_packets(&mut client);
    for packet in f1 {
        server.handle_packet(&packet).expect("server recv f1");
    }

    server.handle_timeout(now).expect("server arm flight 2");
    let f2 = collect_packets(&mut server);
    assert!(!f2.is_empty(), "server should emit flight 2 after CH");
    for packet in f2 {
        client.handle_packet(&packet).expect("client recv f2");
    }

    client.handle_timeout(now).expect("client arm flight 3");
    let f3 = collect_packets(&mut client);
    assert!(!f3.is_empty(), "client should emit flight 3 after HVR");
    let stale_epoch0_handshake = first_record_matching(&f3, 22, 0)
        .expect("flight 3 should contain a plaintext ClientHello record");
    for packet in f3 {
        server.handle_packet(&packet).expect("server recv f3");
    }

    server.handle_timeout(now).expect("server arm flight 4");
    let f4 = collect_packets(&mut server);
    assert!(
        !f4.is_empty(),
        "server should emit flight 4 after CH+cookie"
    );
    for packet in f4 {
        client.handle_packet(&packet).expect("client recv f4");
    }

    client.handle_timeout(now).expect("client arm flight 5");
    let f5_init = collect_packets(&mut client);
    assert!(
        !f5_init.is_empty(),
        "client should emit flight 5 after server flight"
    );
    for packet in &f5_init {
        server.handle_packet(packet).expect("server recv f5");
    }

    server.handle_timeout(now).expect("server arm flight 6");
    let f6_init = collect_packets(&mut server);
    assert!(!f6_init.is_empty(), "server should emit initial flight 6");
    let f6_init_hdrs = collect_headers(&f6_init);
    assert!(
        f6_init_hdrs.iter().any(|h| h.ctype == 20 && h.epoch == 0),
        "server flight 6 should include epoch 0 CCS"
    );
    assert!(
        f6_init_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "server flight 6 should include epoch 1 Finished"
    );

    trigger_timeout(&mut client, &mut now);
    let f5_resend = collect_packets(&mut client);
    assert!(!f5_resend.is_empty(), "client should resend flight 5");
    for packet in &f5_resend {
        server.handle_packet(packet).expect("server recv f5 resend");
    }

    let f6_resend = collect_packets(&mut server);
    assert!(
        !f6_resend.is_empty(),
        "server should resend flight 6 upon receiving duplicate Finished"
    );
    let f6_resend_hdrs = collect_headers(&f6_resend);
    assert!(
        f6_resend_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "resend flight 6 should include epoch 1 Finished"
    );
    assert_epochs_and_seq_increased(&f6_init_hdrs, &f6_resend_hdrs);

    FinalFlightResend {
        client,
        server,
        f6_init,
        f6_resend,
        stale_epoch0_handshake,
    }
}

#[cfg(feature = "rcgen")]
fn first_record_matching(datagrams: &[Vec<u8>], content_type: u8, epoch: u16) -> Option<Vec<u8>> {
    for datagram in datagrams {
        let mut offset = 0usize;
        while offset + 13 <= datagram.len() {
            let len = u16::from_be_bytes([datagram[offset + 11], datagram[offset + 12]]) as usize;
            let end = offset + 13 + len;
            if end > datagram.len() {
                break;
            }

            let record_epoch = u16::from_be_bytes([datagram[offset + 3], datagram[offset + 4]]);
            if datagram[offset] == content_type && record_epoch == epoch {
                return Some(datagram[offset..end].to_vec());
            }

            offset = end;
        }
    }

    None
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_resends_each_flight_epoch_and_sequence_increase() {
    let now0 = Instant::now();
    let mut now = now0;

    use dimpl::certificate::generate_self_signed_certificate;

    // Certificates for client and server
    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config_client = Arc::new(Config::default());
    let config_server = Arc::new(Config::default());

    // Client
    let mut client = Dtls::new_12(config_client, client_cert.clone(), now);
    client.set_active(true);

    // Server
    let mut server = Dtls::new_12(config_server, server_cert.clone(), now);
    server.set_active(false);

    // FLIGHT 1 (ClientHello): block initial, deliver resend
    client.handle_timeout(now).expect("client timeout start");
    // flight_begin reset the flight timer; arm it again so poll_output yields packets
    client.handle_timeout(now).expect("client arm flight 1");
    let init1_pkts = collect_packets(&mut client);
    let init1_hdrs = collect_headers(&init1_pkts);
    trigger_timeout(&mut client, &mut now);
    let resend1_pkts = collect_packets(&mut client);
    let resend1_hdrs = collect_headers(&resend1_pkts);
    assert_epochs_and_seq_increased(&init1_hdrs, &resend1_hdrs);
    for p in resend1_pkts {
        server.handle_packet(&p).expect("server recv f1");
    }

    // FLIGHT 2 (HelloVerifyRequest): capture initial from server, block, deliver resend
    server.handle_timeout(now).expect("server arm flight 2");
    let init2_pkts = collect_packets(&mut server);
    assert!(
        !init2_pkts.is_empty(),
        "server should emit flight 2 after CH"
    );
    let init2_hdrs = collect_headers(&init2_pkts);
    trigger_timeout(&mut server, &mut now);
    let resend2_pkts = collect_packets(&mut server);
    let resend2_hdrs = collect_headers(&resend2_pkts);
    assert_epochs_and_seq_increased(&init2_hdrs, &resend2_hdrs);
    for p in resend2_pkts {
        client.handle_packet(&p).expect("client recv f2");
    }

    // FLIGHT 3 (ClientHello with cookie): block initial, deliver resend
    client.handle_timeout(now).expect("client arm flight 3");
    let init3_pkts = collect_packets(&mut client);
    assert!(
        !init3_pkts.is_empty(),
        "client should emit flight 3 after HVR"
    );
    let init3_hdrs = collect_headers(&init3_pkts);
    trigger_timeout(&mut client, &mut now);
    let resend3_pkts = collect_packets(&mut client);
    let resend3_hdrs = collect_headers(&resend3_pkts);
    assert_epochs_and_seq_increased(&init3_hdrs, &resend3_hdrs);
    for p in resend3_pkts {
        server.handle_packet(&p).expect("server recv f3");
    }

    // FLIGHT 4 (ServerHello, Certificate, SKE, CR, SHD): block initial, deliver resend
    server.handle_timeout(now).expect("server arm flight 4");
    let init4_pkts = collect_packets(&mut server);
    assert!(
        !init4_pkts.is_empty(),
        "server should emit flight 4 after CH+cookie"
    );
    let init4_hdrs = collect_headers(&init4_pkts);
    trigger_timeout(&mut server, &mut now);
    let resend4_pkts = collect_packets(&mut server);
    let resend4_hdrs = collect_headers(&resend4_pkts);
    assert_epochs_and_seq_increased(&init4_hdrs, &resend4_hdrs);
    for p in resend4_pkts {
        client.handle_packet(&p).expect("client recv f4");
    }

    // FLIGHT 5 (Client cert?, CKX, CV?, CCS, Finished): block initial, deliver resend
    client.handle_timeout(now).expect("client arm flight 5");
    let init5_pkts = collect_packets(&mut client);
    assert!(
        !init5_pkts.is_empty(),
        "client should emit flight 5 after server flight"
    );
    let init5_hdrs = collect_headers(&init5_pkts);
    trigger_timeout(&mut client, &mut now);
    let resend5_pkts = collect_packets(&mut client);
    let resend5_hdrs = collect_headers(&resend5_pkts);
    assert_epochs_and_seq_increased(&init5_hdrs, &resend5_hdrs);
    // Additionally, ensure Finished is epoch 1 is present in the set
    assert!(
        resend5_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "client flight 5 should include epoch 1 Finished"
    );
    for p in resend5_pkts {
        server.handle_packet(&p).expect("server recv f5");
    }

    // FLIGHT 6 (Server CCS, Finished): no resend timer after final flight
    server.handle_timeout(now).expect("server arm flight 6");
    let init6_pkts = collect_packets(&mut server);
    assert!(
        !init6_pkts.is_empty(),
        "server should emit flight 6 after client flight 5"
    );
    let init6_hdrs = collect_headers(&init6_pkts);
    // Final flight should include epoch 1 Finished in the initial transmission
    assert!(
        init6_hdrs.iter().any(|h| h.ctype == 22 && h.epoch == 1),
        "server flight 6 should include epoch 1 Finished"
    );
    // Ensure no timer-driven resend occurs after final flight
    trigger_timeout(&mut server, &mut now);
    let resend6_pkts = collect_packets(&mut server);
    assert!(resend6_pkts.is_empty(), "no resend after final flight");
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_duplicate_triggers_server_resend_of_final_flight() {
    let result = prepare_server_final_flight_resend(Config::default().max_queue_rx());
    assert!(
        !result.f6_init.is_empty(),
        "server should emit initial flight 6"
    );
    assert!(
        !result.f6_resend.is_empty(),
        "server should resend flight 6 upon receiving duplicate Finished"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_resend_replaces_pending_handshake_flight_tail() {
    let now0 = Instant::now();
    let mut now = now0;

    use dimpl::certificate::generate_self_signed_certificate;

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config_client = Arc::new(
        Config::builder()
            .mtu(115)
            .build()
            .expect("Failed to build config"),
    );
    let config_server = Arc::new(
        Config::builder()
            .mtu(115)
            .build()
            .expect("Failed to build config"),
    );

    let expected_initial_headers = {
        let mut client = Dtls::new_12(Arc::clone(&config_client), client_cert.clone(), now0);
        client.set_active(true);

        let mut server = Dtls::new_12(Arc::clone(&config_server), server_cert.clone(), now0);
        server.set_active(false);

        client.handle_timeout(now0).expect("client timeout start");
        client.handle_timeout(now0).expect("client arm flight 1");
        for p in collect_packets(&mut client) {
            server.handle_packet(&p).expect("control server recv f1");
        }

        server
            .handle_timeout(now0)
            .expect("control server arm flight 2");
        for p in collect_packets(&mut server) {
            client.handle_packet(&p).expect("control client recv f2");
        }

        client
            .handle_timeout(now0)
            .expect("control client arm flight 3");
        for p in collect_packets(&mut client) {
            server.handle_packet(&p).expect("control server recv f3");
        }

        server
            .handle_timeout(now0)
            .expect("control server arm flight 4");
        collect_headers(&collect_packets(&mut server))
    };
    assert!(
        !expected_initial_headers.is_empty(),
        "control flight 4 should contain records"
    );

    let mut client = Dtls::new_12(config_client, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config_server, server_cert, now);
    server.set_active(false);

    client.handle_timeout(now).expect("client timeout start");
    client.handle_timeout(now).expect("client arm flight 1");
    let f1 = collect_packets(&mut client);
    for p in f1 {
        server.handle_packet(&p).expect("server recv f1");
    }

    server.handle_timeout(now).expect("server arm flight 2");
    let f2 = collect_packets(&mut server);
    for p in f2 {
        client.handle_packet(&p).expect("client recv f2");
    }

    client.handle_timeout(now).expect("client arm flight 3");
    let f3 = collect_packets(&mut client);
    for p in f3 {
        server.handle_packet(&p).expect("server recv f3");
    }

    server.handle_timeout(now).expect("server arm flight 4");
    let first_initial = poll_one_packet(&mut server);
    let first_initial_headers = parse_records(&first_initial);
    assert!(
        !first_initial_headers.is_empty(),
        "first initial flight 4 packet should contain records"
    );

    trigger_timeout(&mut server, &mut now);
    let pending = collect_packets(&mut server);
    assert!(
        !pending.is_empty(),
        "server should emit flight 4 resend after timeout"
    );
    let pending_headers = collect_headers(&pending);
    assert_eq!(
        pending_headers.len(),
        expected_initial_headers.len(),
        "resend should replace the undrained original flight tail instead of appending to it; \
         expected initial {expected_initial_headers:?}, pending {pending_headers:?}"
    );
    assert!(
        pending_headers
            .iter()
            .zip(expected_initial_headers.iter())
            .all(|(resend, initial)| resend.ctype == initial.ctype
                && resend.epoch == initial.epoch
                && resend.seq > initial.seq),
        "resend should contain only a fresh copy of the flight, got expected initial \
         {expected_initial_headers:?}, first polled {first_initial_headers:?}, pending \
         {pending_headers:?}"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_final_flight_resend_can_share_post_release_appdata_tail() {
    let FinalFlightResend {
        mut server,
        stale_epoch0_handshake,
        ..
    } = prepare_server_final_flight_resend(Config::default().max_queue_rx());

    let filler = vec![0x55; 50];
    for i in 0..9 {
        server
            .send_application_data(&filler)
            .unwrap_or_else(|err| panic!("queue filler app data {i}: {err:?}"));
    }
    server
        .send_application_data(b"x")
        .expect("queue final small app data");

    server
        .handle_packet(&stale_epoch0_handshake)
        .expect("post-release duplicate should trigger final-flight resend");

    let pending_headers = collect_headers(&collect_packets(&mut server));
    let app_data_records = pending_headers
        .iter()
        .filter(|header| header.ctype == 23 && header.epoch == 1)
        .count();
    assert_eq!(
        app_data_records, 10,
        "post-release final-flight resend must preserve queued app-data records, got \
         {pending_headers:?}"
    );
    assert!(
        pending_headers
            .iter()
            .any(|header| header.ctype == 22 && header.epoch == 1),
        "server should retain and resend encrypted final-flight Finished, got \
         {pending_headers:?}"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_late_retransmitted_ccs_does_not_pin_receive_queue() {
    //! After the handshake, a peer can still retransmit its final flight. The
    //! epoch-0 ChangeCipherSpec in that flight must be ignored; otherwise it
    //! remains unhandled and prevents handled app-data records behind it from
    //! being purged.

    const RX_QUEUE_LIMIT: usize = 8;

    let FinalFlightResend {
        mut client,
        mut server,
        f6_init,
        f6_resend,
        stale_epoch0_handshake: _,
    } = prepare_server_final_flight_resend(RX_QUEUE_LIMIT);

    deliver_packets(&f6_init, &mut client);
    let client_connected = drain_outputs(&mut client).connected;
    assert!(
        client_connected,
        "client should connect after initial flight 6"
    );

    for packet in &f6_resend {
        client
            .handle_packet(packet)
            .expect("late final-flight resend should be tolerated");
    }

    for i in 0..=RX_QUEUE_LIMIT {
        let msg = format!("post-ccs app data {i}");
        server
            .send_application_data(msg.as_bytes())
            .expect("send app data");

        let server_out = drain_outputs(&mut server);
        assert!(
            !server_out.packets.is_empty(),
            "server should emit app-data packets"
        );

        for packet in &server_out.packets {
            client
                .handle_packet(packet)
                .expect("late CCS must not make receive queue fill");
        }

        let client_out = drain_outputs(&mut client);
        assert!(
            client_out
                .app_data
                .iter()
                .any(|received| received == msg.as_bytes()),
            "client should receive app data after late CCS"
        );
    }
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_late_epoch0_handshake_does_not_pin_receive_queue() {
    //! After peer encryption is enabled, plaintext epoch-0 handshake records are
    //! unauthenticated and no longer actionable. They must be ignored for the
    //! same queue-pinning reason as late CCS records.

    const RX_QUEUE_LIMIT: usize = 8;

    let FinalFlightResend {
        mut client,
        mut server,
        f6_init,
        f6_resend: _,
        stale_epoch0_handshake: _,
    } = prepare_server_final_flight_resend(RX_QUEUE_LIMIT);

    deliver_packets(&f6_init, &mut client);
    let client_connected = drain_outputs(&mut client).connected;
    assert!(
        client_connected,
        "client should connect after initial flight 6"
    );

    client
        .handle_packet(&malformed_epoch0_handshake_packet(0x7fff))
        .expect("late epoch-0 handshake should be tolerated");

    for i in 0..=RX_QUEUE_LIMIT {
        let msg = format!("post-handshake app data {i}");
        server
            .send_application_data(msg.as_bytes())
            .expect("send app data");

        let server_out = drain_outputs(&mut server);
        assert!(
            !server_out.packets.is_empty(),
            "server should emit app-data packets"
        );

        for packet in &server_out.packets {
            client
                .handle_packet(packet)
                .expect("late epoch-0 handshake must not make receive queue fill");
        }

        let client_out = drain_outputs(&mut client);
        assert!(
            client_out
                .app_data
                .iter()
                .any(|received| received == msg.as_bytes()),
            "client should receive app data after late epoch-0 handshake"
        );
    }
}

fn malformed_epoch0_handshake_packet(sequence_number: u64) -> Vec<u8> {
    let sequence_bytes = sequence_number.to_be_bytes();
    let mut packet = Vec::with_capacity(14);
    packet.push(22);
    packet.extend_from_slice(&[0xfe, 0xfd]);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&sequence_bytes[2..]);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.push(0xff);
    packet
}

fn append_record(mut packet: Vec<u8>, record: &[u8]) -> Vec<u8> {
    packet.extend_from_slice(record);
    packet
}

#[cfg(feature = "rcgen")]
fn poll_one_packet(endpoint: &mut Dtls) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    loop {
        match endpoint.poll_output(&mut buf) {
            Output::Packet(packet) => return packet.to_vec(),
            Output::Timeout(_) => panic!("expected queued packet"),
            _ => {}
        }
    }
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_late_epoch0_handshake_trailing_app_data_does_not_pin_receive_queue() {
    //! A stale epoch-0 handshake can arrive behind a valid encrypted record in
    //! the same datagram. The encrypted app data should still be delivered, and
    //! the stale plaintext handshake must not keep that datagram in the queue.

    const RX_QUEUE_LIMIT: usize = 8;

    let FinalFlightResend {
        mut client,
        mut server,
        f6_init,
        f6_resend: _,
        stale_epoch0_handshake,
    } = prepare_server_final_flight_resend(RX_QUEUE_LIMIT);

    deliver_packets(&f6_init, &mut client);
    let client_connected = drain_outputs(&mut client).connected;
    assert!(
        client_connected,
        "client should connect after initial flight 6"
    );

    for i in 0..=RX_QUEUE_LIMIT {
        let msg = format!("post-handshake app data {i}");
        server
            .send_application_data(msg.as_bytes())
            .expect("send app data");

        let server_out = drain_outputs(&mut server);
        assert!(
            !server_out.packets.is_empty(),
            "server should emit app-data packets"
        );

        for packet in server_out.packets {
            let packet = if i == 0 {
                append_record(packet, &stale_epoch0_handshake)
            } else {
                packet
            };
            client
                .handle_packet(&packet)
                .expect("trailing late epoch-0 handshake must not make receive queue fill");
        }

        let client_out = drain_outputs(&mut client);
        assert!(
            client_out
                .app_data
                .iter()
                .any(|received| received == msg.as_bytes()),
            "client should receive app data after trailing late epoch-0 handshake"
        );
    }
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_handshake_completes_after_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

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

        // Simulate packet loss: drop first client packet batch
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

        // Advance time to trigger retransmissions periodically
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
fn dtls12_handshake_completes_with_early_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Use a config with more retries to handle packet loss
    let config = Arc::new(
        Config::builder()
            .flight_retries(8)
            .build()
            .expect("Failed to build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

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
fn dtls12_survives_random_packet_loss_pattern() {
    use dimpl::certificate::generate_self_signed_certificate;

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .flight_retries(8)
            .build()
            .expect("Failed to build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut total_dropped = 0;
    let mut total_delivered = 0;

    // Deterministic pattern: drop every 3rd packet across both directions
    let mut global_packet_index = 0usize;

    for i in 0..100 {
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

        for packet in &client_out.packets {
            if global_packet_index % 3 == 2 {
                total_dropped += 1;
            } else {
                let _ = server.handle_packet(packet);
                total_delivered += 1;
            }
            global_packet_index += 1;
        }

        for packet in &server_out.packets {
            if global_packet_index % 3 == 2 {
                total_dropped += 1;
            } else {
                let _ = client.handle_packet(packet);
                total_delivered += 1;
            }
            global_packet_index += 1;
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
        "Client should connect despite every-3rd-packet loss"
    );
    assert!(
        server_connected,
        "Server should connect despite every-3rd-packet loss"
    );
    assert!(
        total_dropped > 0,
        "Test should have dropped at least one packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_retransmit_exponential_backoff() {
    use dimpl::certificate::generate_self_signed_certificate;

    let client_cert = generate_self_signed_certificate().expect("gen client cert");

    // Use a known start RTO and enough retries to observe backoff
    let config = Arc::new(
        Config::builder()
            .flight_start_rto(Duration::from_secs(1))
            .flight_retries(4)
            .handshake_timeout(Duration::from_secs(120))
            .build()
            .expect("Failed to build config"),
    );

    let mut now = Instant::now();
    let mut client = Dtls::new_12(config, client_cert, now);
    client.set_active(true);

    // No server -- we never deliver packets.
    // Start the handshake.
    client.handle_timeout(now).expect("client timeout start");
    client.handle_timeout(now).expect("client arm flight 1");
    let _ = collect_packets(&mut client);

    // Record successive timeout values returned by poll_output.
    // Each handle_timeout that fires the flight timer should produce a new,
    // larger timeout.
    let mut timeouts: Vec<Instant> = Vec::new();

    // Collect the first timeout
    let mut buf = vec![0u8; 2048];
    loop {
        if let Output::Timeout(t) = client.poll_output(&mut buf) {
            timeouts.push(t);
            break;
        }
    }

    // Fire successive timeouts, never delivering packets
    for _ in 0..3 {
        // Advance past the reported timeout
        now = *timeouts.last().expect("should have a timeout") + Duration::from_millis(1);
        client.handle_timeout(now).expect("client handle_timeout");
        let _ = collect_packets(&mut client);

        // Collect the next timeout
        loop {
            if let Output::Timeout(t) = client.poll_output(&mut buf) {
                timeouts.push(t);
                break;
            }
        }
    }

    // Verify we collected multiple timeout values
    assert!(
        timeouts.len() >= 4,
        "Should have at least 4 timeout values, got {}",
        timeouts.len()
    );

    // Verify each successive interval is strictly larger (exponential backoff).
    // Interval[i] = timeout[i+1] - timeout[i] should be increasing.
    let mut intervals: Vec<Duration> = Vec::new();
    for pair in timeouts.windows(2) {
        let interval = pair[1].duration_since(pair[0]);
        intervals.push(interval);
    }

    for pair in intervals.windows(2) {
        assert!(
            pair[1] > pair[0],
            "Backoff intervals should increase: {:?} should be > {:?}",
            pair[1],
            pair[0]
        );
    }
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_handshake_timeout_aborts() {
    use dimpl::certificate::generate_self_signed_certificate;

    let client_cert = generate_self_signed_certificate().expect("gen client cert");

    // Configure a very short handshake timeout so we hit it quickly
    let config = Arc::new(
        Config::builder()
            .handshake_timeout(Duration::from_secs(5))
            .flight_start_rto(Duration::from_secs(1))
            .flight_retries(10) // Many retries, but the handshake timeout will fire first
            .build()
            .expect("Failed to build config"),
    );

    let mut now = Instant::now();
    let mut client = Dtls::new_12(config, client_cert, now);
    client.set_active(true);

    // Start the handshake
    client.handle_timeout(now).expect("client timeout start");
    client.handle_timeout(now).expect("client arm flight 1");
    let _ = collect_packets(&mut client);

    // Keep triggering timeouts without ever delivering packets.
    // The handshake_timeout (5s) should eventually cause handle_timeout to return an error.
    let mut got_timeout_error = false;
    for _ in 0..100 {
        now += Duration::from_secs(1);
        match client.handle_timeout(now) {
            Ok(()) => {
                // Drain any packets to keep the state machine consistent
                let _ = collect_packets(&mut client);
            }
            Err(e) => {
                let msg = format!("{}", e);
                assert!(
                    msg.contains("timeout"),
                    "Expected timeout error, got: {}",
                    msg
                );
                got_timeout_error = true;
                break;
            }
        }
    }

    assert!(
        got_timeout_error,
        "Client should report a timeout error when handshake_timeout is exceeded"
    );
}
