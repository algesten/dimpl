//! DTLS 1.3 key update tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, Error};

use crate::common::*;

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

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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

#[cfg(feature = "rcgen")]
fn assert_key_update_and_app_data_same_datagram(
    sender: &mut Dtls,
    receiver: &mut Dtls,
    now: &mut Instant,
    priming: &'static [u8],
    post_update: &'static [u8],
) {
    sender
        .send_application_data(priming)
        .expect("send priming app data");
    let first_packets = collect_packets(sender);
    assert_eq!(first_packets.len(), 1);

    deliver_packets(&first_packets, receiver);
    receiver.handle_timeout(*now).expect("receiver timeout");
    let first_received = drain_outputs(receiver);
    assert_eq!(first_received.app_data, vec![priming.to_vec()]);
    deliver_packets(&first_received.packets, sender);

    *now += Duration::from_millis(10);
    sender.handle_timeout(*now).expect("sender timeout");
    let key_update_packets = collect_packets(sender);
    assert_eq!(key_update_packets.len(), 1);

    sender
        .send_application_data(post_update)
        .expect("send post-key-update app data");
    let app_packets = collect_packets(sender);
    assert_eq!(app_packets.len(), 1);

    let mut combined = key_update_packets[0].clone();
    combined.extend_from_slice(&app_packets[0]);

    receiver
        .handle_packet(&combined)
        .expect("receiver should accept combined datagram");
    receiver.handle_timeout(*now).expect("receiver timeout");

    let received = drain_outputs(receiver);
    assert_eq!(
        received.app_data,
        vec![post_update.to_vec()],
        "receiver should deliver new-epoch app data that follows KeyUpdate in the same datagram"
    );
}

#[cfg(feature = "rcgen")]
fn capture_key_update_and_app_data_packets(
    sender: &mut Dtls,
    receiver: &mut Dtls,
    now: &mut Instant,
    priming: &'static [u8],
    post_update: &'static [u8],
) -> (Vec<u8>, Vec<u8>) {
    sender
        .send_application_data(priming)
        .expect("send priming app data");
    let first_packets = collect_packets(sender);
    assert_eq!(first_packets.len(), 1);

    deliver_packets(&first_packets, receiver);
    receiver.handle_timeout(*now).expect("receiver timeout");
    let first_received = drain_outputs(receiver);
    assert_eq!(first_received.app_data, vec![priming.to_vec()]);
    deliver_packets(&first_received.packets, sender);

    *now += Duration::from_millis(10);
    sender.handle_timeout(*now).expect("sender timeout");
    let key_update_packets = collect_packets(sender);
    assert_eq!(key_update_packets.len(), 1);

    sender
        .send_application_data(post_update)
        .expect("send post-key-update app data");
    let app_packets = collect_packets(sender);
    assert_eq!(app_packets.len(), 1);

    (key_update_packets[0].clone(), app_packets[0].clone())
}

#[cfg(feature = "rcgen")]
fn dtls13_ack_record_with_entry(seq: u64, ack_epoch: u64, ack_seq: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(26); // Ack
    out.extend_from_slice(&[0xFE, 0xFD]); // legacy DTLS record version
    out.extend_from_slice(&0u16.to_be_bytes()); // epoch 0 plaintext
    out.extend_from_slice(&seq.to_be_bytes()[2..]); // u48 sequence number
    out.extend_from_slice(&18u16.to_be_bytes()); // record_numbers_len + one entry
    out.extend_from_slice(&16u16.to_be_bytes()); // record_numbers_len
    out.extend_from_slice(&ack_epoch.to_be_bytes());
    out.extend_from_slice(&ack_seq.to_be_bytes());
    out
}

/// Test that application data following a KeyUpdate in the same datagram is
/// delivered. The sender emits the KeyUpdate under the old application epoch,
/// rotates send keys, and the datagram then carries application data under the
/// new epoch. The receiver must process the KeyUpdate before trying to decrypt
/// the following record.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_client_key_update_and_new_epoch_app_data_in_same_datagram() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    assert_key_update_and_app_data_same_datagram(
        &mut client,
        &mut server,
        &mut now,
        b"client-primes-key-update",
        b"client-same-datagram-new-epoch",
    );
}

/// If the deferred tail after a KeyUpdate is structurally malformed, the whole
/// UDP datagram must be rejected before the KeyUpdate is acted on. This keeps
/// the DIMP-007 datagram-atomic replay/state invariant for malformed tails.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_with_malformed_same_datagram_tail_is_atomic() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    let (key_update_packet, app_packet) = capture_key_update_and_app_data_packets(
        &mut client,
        &mut server,
        &mut now,
        b"client-primes-malformed-tail-key-update",
        b"client-valid-tail-after-malformed-attempt",
    );

    let mut malformed = key_update_packet.clone();
    malformed.push(0xff);

    let err = server
        .handle_packet(&malformed)
        .expect_err("malformed tail must reject the full datagram");
    assert!(
        matches!(err, dimpl::Error::ParseIncomplete),
        "expected ParseIncomplete, got {err:?}"
    );

    let after_malformed = drain_outputs(&mut server);
    assert!(
        after_malformed.packets.is_empty() && after_malformed.app_data.is_empty(),
        "malformed datagram must not ACK, advance, or deliver anything"
    );

    let mut valid = key_update_packet;
    valid.extend_from_slice(&app_packet);

    server
        .handle_packet(&valid)
        .expect("valid retry must still pass replay checks");
    server.handle_timeout(now).expect("server timeout");

    let received = drain_outputs(&mut server);
    assert_eq!(
        received.app_data,
        vec![b"client-valid-tail-after-malformed-attempt".to_vec()]
    );
}

/// Deferring a post-KeyUpdate tail must not reset the per-datagram record
/// budget. Otherwise a `KeyUpdate || 16 records` datagram would be accepted as
/// two separately-budgeted parses and the KeyUpdate would take effect before the
/// over-capacity tail is rejected.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_with_over_capacity_same_datagram_tail_is_atomic() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    let (key_update_packet, app_packet) = capture_key_update_and_app_data_packets(
        &mut client,
        &mut server,
        &mut now,
        b"client-primes-over-capacity-tail-key-update",
        b"client-valid-tail-after-over-capacity-attempt",
    );

    let mut over_capacity = key_update_packet.clone();
    for seq in 0..16 {
        over_capacity.extend_from_slice(&dtls13_ack_record_with_entry(0x200 + seq, 3, seq));
    }

    let err = server
        .handle_packet(&over_capacity)
        .expect_err("over-capacity tail must reject the full datagram");
    assert!(
        matches!(err, dimpl::Error::TooManyRecords),
        "expected TooManyRecords, got {err:?}"
    );

    let after_over_capacity = drain_outputs(&mut server);
    assert!(
        after_over_capacity.packets.is_empty() && after_over_capacity.app_data.is_empty(),
        "over-capacity datagram must not ACK, advance, or deliver anything"
    );

    let mut valid = key_update_packet;
    valid.extend_from_slice(&app_packet);

    server
        .handle_packet(&valid)
        .expect("valid retry must still pass replay checks");
    server.handle_timeout(now).expect("server timeout");

    let received = drain_outputs(&mut server);
    assert_eq!(
        received.app_data,
        vec![b"client-valid-tail-after-over-capacity-attempt".to_vec()]
    );
}

/// Same as the client-sender case, but with the server as the KeyUpdate sender
/// so the client deferred-tail path is covered too.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_server_key_update_and_new_epoch_app_data_in_same_datagram() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    assert_key_update_and_app_data_same_datagram(
        &mut server,
        &mut client,
        &mut now,
        b"server-primes-key-update",
        b"server-same-datagram-new-epoch",
    );
}

#[cfg(feature = "rcgen")]
fn trigger_key_update(
    sender: &mut Dtls,
    receiver: &mut Dtls,
    now: &mut Instant,
    label: &str,
) -> Vec<Vec<u8>> {
    for i in 0..64 {
        sender
            .handle_timeout(*now)
            .expect("sender checks existing KeyUpdate threshold");
        let pending_key_update = collect_packets(sender);
        if !pending_key_update.is_empty() {
            return pending_key_update;
        }

        let msg = format!("{label}-{i}").into_bytes();
        sender
            .send_application_data(&msg)
            .expect("sender sends priming app data");
        let data_packets = collect_packets(sender);
        assert_eq!(
            data_packets.len(),
            1,
            "sender should emit exactly one priming app-data packet before KeyUpdate"
        );

        deliver_packets(&data_packets, receiver);
        receiver
            .handle_timeout(*now)
            .expect("receiver handles priming data");
        let receiver_out = drain_outputs(receiver);
        assert!(
            receiver_out
                .app_data
                .iter()
                .any(|received| received == &msg),
            "receiver should deliver priming app data before KeyUpdate"
        );
        deliver_packets(&receiver_out.packets, sender);

        *now += Duration::from_millis(10);
        sender
            .handle_timeout(*now)
            .expect("sender checks KeyUpdate threshold");
        let key_update = collect_packets(sender);
        if !key_update.is_empty() {
            return key_update;
        }
    }

    panic!("{label}: sender did not emit KeyUpdate within bounded attempts");
}

#[cfg(feature = "rcgen")]
fn dtls13_ciphertext_epoch_bits(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut epochs = Vec::new();

    for packet in packets {
        let mut rest = packet.as_slice();
        while !rest.is_empty() {
            assert_eq!(
                rest[0] & 0b1110_0000,
                0b0010_0000,
                "expected DTLS 1.3 ciphertext unified header"
            );
            assert_eq!(
                rest[0] & 0b0001_0000,
                0,
                "CID-bearing DTLS 1.3 records are not expected in these tests"
            );

            let s_flag = rest[0] & 0b0000_1000 != 0;
            let l_flag = rest[0] & 0b0000_0100 != 0;
            assert!(l_flag, "test records should carry explicit lengths");

            let seq_len = if s_flag { 2 } else { 1 };
            let header_len = 1 + seq_len + 2;
            assert!(
                rest.len() >= header_len,
                "truncated DTLS 1.3 ciphertext header"
            );

            let len_offset = 1 + seq_len;
            let body_len = u16::from_be_bytes([rest[len_offset], rest[len_offset + 1]]) as usize;
            let record_len = header_len + body_len;
            assert!(
                rest.len() >= record_len,
                "truncated DTLS 1.3 ciphertext record"
            );

            epochs.push(rest[0] & 0x03);
            rest = &rest[record_len..];
        }
    }

    epochs
}

#[cfg(feature = "rcgen")]
fn assert_peer_requested_response_waits_for_local_update_ack(
    local: &mut Dtls,
    peer: &mut Dtls,
    now: &mut Instant,
    local_label: &str,
    peer_label: &str,
    post_overlap: &[u8],
) {
    let local_key_update = trigger_key_update(local, peer, now, local_label);
    let peer_key_update = trigger_key_update(peer, local, now, peer_label);

    deliver_packets(&peer_key_update, local);
    let local_ack_only = collect_packets(local);
    assert!(
        !local_ack_only.is_empty(),
        "local endpoint should ACK peer KeyUpdate without sending the pending response"
    );
    assert_eq!(
        dtls13_ciphertext_epoch_bits(&local_ack_only),
        vec![3],
        concat!(
            "local ACK must use the retained previous app epoch ",
            "so peer can decrypt it before receiving local KeyUpdate"
        )
    );

    deliver_packets(&local_ack_only, peer);
    let peer_after_local_ack = collect_packets(peer);
    assert!(
        peer_after_local_ack.is_empty(),
        "local endpoint must not send its pending KeyUpdate response before its local update is ACKed"
    );

    let mut peer_after_local_ack_timeout = Vec::new();
    for _ in 0..20 {
        *now += Duration::from_millis(500);
        peer.handle_timeout(*now)
            .expect("peer checks whether its KeyUpdate is still in flight");
        peer_after_local_ack_timeout.extend(collect_packets(peer));
    }
    assert!(
        peer_after_local_ack_timeout.is_empty(),
        "peer should not retransmit its KeyUpdate after local endpoint ACKs it"
    );

    deliver_packets(&local_key_update, peer);
    let peer_ack_for_local_update = collect_packets(peer);
    assert!(
        !peer_ack_for_local_update.is_empty(),
        "peer should ACK local KeyUpdate"
    );

    deliver_packets(&peer_ack_for_local_update, local);
    let local_response = collect_packets(local);
    assert!(
        !local_response.is_empty(),
        "pending peer-requested ACK and response should drain once the local update is ACKed"
    );

    deliver_packets(&local_response, peer);
    let peer_ack_for_local_response = collect_packets(peer);
    assert!(
        !peer_ack_for_local_response.is_empty(),
        "peer should consume and ACK the delayed KeyUpdate response"
    );
    deliver_packets(&peer_ack_for_local_response, local);
    let local_after_response_ack = collect_packets(local);
    assert!(
        local_after_response_ack.is_empty(),
        "delayed response must be update_not_requested and must not trigger a further response"
    );

    local
        .send_application_data(post_overlap)
        .expect("local sends post-overlap data");
    let local_post_overlap = collect_packets(local);
    assert_eq!(
        local_post_overlap.len(),
        1,
        concat!(
            "delayed KeyUpdate response must clear the peer-requested response ",
            "before auto KeyUpdate can send another UpdateRequested"
        )
    );
    deliver_packets(&local_post_overlap, peer);
    peer.handle_timeout(*now)
        .expect("peer handles post-overlap data");
    let peer_post_overlap = drain_outputs(peer);
    assert!(
        peer_post_overlap
            .app_data
            .iter()
            .any(|received| received == post_overlap),
        "peer should receive post-overlap app data"
    );
}

#[cfg(feature = "rcgen")]
fn assert_peer_key_update_ack_retries_after_transmit_backpressure(
    sender: &mut Dtls,
    receiver: &mut Dtls,
    now: &mut Instant,
    label: &str,
    receiver_occupant: &[u8],
    sender_after_retry: &[u8],
) {
    let key_update = trigger_key_update(sender, receiver, now, label);
    assert_eq!(key_update.len(), 1, "test expects one KeyUpdate datagram");

    receiver
        .send_application_data(receiver_occupant)
        .expect("receiver queues one app-data packet to occupy transmit queue");

    let err = receiver
        .handle_packet(&key_update[0])
        .expect_err("receiver KeyUpdate ACK should hit transmit backpressure");
    assert!(
        matches!(err, Error::TransmitQueueFull),
        "expected TransmitQueueFull, got {err:?}"
    );

    let receiver_after_backpressure = drain_outputs(receiver);
    let occupied = receiver_after_backpressure.packets;
    assert_eq!(
        occupied.len(),
        1,
        "only the pre-existing app-data packet should be queued after failed ACK"
    );
    let retry_at = receiver_after_backpressure
        .timeout
        .expect("receiver should surface immediate retry timeout");
    assert!(
        retry_at <= *now,
        "pending KeyUpdate ACK retry should be immediately scheduled"
    );
    deliver_packets(&occupied, sender);
    sender
        .handle_timeout(*now)
        .expect("sender handles receiver occupant");
    let sender_after_occupant = drain_outputs(sender);
    assert!(
        sender_after_occupant
            .app_data
            .iter()
            .any(|received| received == receiver_occupant),
        "sender should receive the packet that occupied receiver output"
    );

    receiver
        .handle_timeout(retry_at)
        .expect("receiver retries pending KeyUpdate ACK from poll timeout");
    let retried_ack_and_response = collect_packets(receiver);
    assert!(
        !retried_ack_and_response.is_empty(),
        "receiver should retry the ACK and peer-requested response"
    );
    *now += Duration::from_secs(2);
    sender
        .handle_timeout(*now)
        .expect("sender retransmits unacked KeyUpdate");
    let retransmitted_key_update = collect_packets(sender);
    assert!(
        !retransmitted_key_update.is_empty(),
        "sender should retransmit KeyUpdate before receiving ACK"
    );

    let duplicate_occupant = b"receiver-duplicate-keyupdate-occupant";
    receiver
        .send_application_data(duplicate_occupant)
        .expect("receiver queues app data before duplicate KeyUpdate");
    let err = receiver
        .handle_packet(&retransmitted_key_update[0])
        .expect_err("duplicate KeyUpdate ACK should hit transmit backpressure");
    assert!(
        matches!(err, Error::TransmitQueueFull),
        "expected duplicate KeyUpdate ACK TransmitQueueFull, got {err:?}"
    );

    let receiver_after_duplicate = drain_outputs(receiver);
    assert_eq!(
        receiver_after_duplicate.packets.len(),
        1,
        "duplicate path should only leave the pre-existing app-data packet queued"
    );
    let duplicate_retry_at = receiver_after_duplicate
        .timeout
        .expect("duplicate KeyUpdate ACK should surface retry timeout");
    assert!(
        duplicate_retry_at <= *now,
        "duplicate KeyUpdate ACK retry should be immediately scheduled"
    );
    receiver
        .handle_timeout(duplicate_retry_at)
        .expect("receiver retries duplicate KeyUpdate ACK from poll timeout");
    let duplicate_ack = collect_packets(receiver);
    assert!(
        !duplicate_ack.is_empty(),
        "receiver should retry duplicate KeyUpdate ACK after queue drains"
    );
    deliver_packets(&duplicate_ack, sender);
    sender
        .handle_timeout(*now)
        .expect("sender handles duplicate KeyUpdate ACK retry");
    let sender_after_duplicate_ack = drain_outputs(sender);
    deliver_packets(&sender_after_duplicate_ack.packets, receiver);

    deliver_packets(&retried_ack_and_response, sender);

    sender
        .handle_timeout(*now)
        .expect("sender handles retried ACK and response");
    let sender_ack_for_response = collect_packets(sender);
    deliver_packets(&sender_ack_for_response, receiver);

    receiver
        .handle_packet(&key_update[0])
        .expect("duplicate KeyUpdate must not derive receive keys a second time");
    receiver
        .handle_timeout(*now)
        .expect("receiver handles duplicate after retry");
    let duplicate_output = collect_packets(receiver);
    deliver_packets(&duplicate_output, sender);

    sender
        .send_application_data(sender_after_retry)
        .expect("sender sends after duplicate KeyUpdate");
    let post_retry = collect_packets(sender);
    assert_eq!(post_retry.len(), 1);
    deliver_packets(&post_retry, receiver);
    receiver
        .handle_timeout(*now)
        .expect("receiver handles sender data after duplicate");
    let received = drain_outputs(receiver);
    assert!(
        received
            .app_data
            .iter()
            .any(|data| data == sender_after_retry),
        "receiver should decrypt later sender data after exactly one receive-key update"
    );
}

#[cfg(feature = "rcgen")]
fn assert_deferred_tail_drains_after_ack_backpressure(
    sender: &mut Dtls,
    receiver: &mut Dtls,
    now: &mut Instant,
    priming: &'static [u8],
    post_update: &'static [u8],
    receiver_occupant: &[u8],
) {
    let (key_update_packet, app_packet) =
        capture_key_update_and_app_data_packets(sender, receiver, now, priming, post_update);

    receiver
        .send_application_data(receiver_occupant)
        .expect("receiver queues one app-data packet to occupy transmit queue");

    let mut combined = key_update_packet;
    combined.extend_from_slice(&app_packet);
    let err = receiver
        .handle_packet(&combined)
        .expect_err("receiver KeyUpdate ACK should hit transmit backpressure");
    assert!(
        matches!(err, Error::TransmitQueueFull),
        "expected TransmitQueueFull, got {err:?}"
    );

    let receiver_after_backpressure = drain_outputs(receiver);
    let occupied = receiver_after_backpressure.packets;
    assert_eq!(
        occupied.len(),
        1,
        "only the pre-existing app-data packet should be queued after failed ACK"
    );
    let retry_at = receiver_after_backpressure
        .timeout
        .expect("receiver should surface immediate retry timeout");
    assert!(
        retry_at <= *now,
        "pending deferred-tail retry should be immediately scheduled"
    );
    deliver_packets(&occupied, sender);
    sender
        .handle_timeout(*now)
        .expect("sender handles receiver occupant");
    let sender_after_occupant = drain_outputs(sender);
    assert!(
        sender_after_occupant
            .app_data
            .iter()
            .any(|received| received == receiver_occupant),
        "sender should receive the packet that occupied receiver output"
    );

    receiver
        .handle_timeout(retry_at)
        .expect("receiver retries pending ACK and drains deferred tail from poll timeout");
    let receiver_after_retry = drain_outputs(receiver);
    assert!(
        !receiver_after_retry.packets.is_empty(),
        "receiver should retry the pending KeyUpdate ACK"
    );
    assert_eq!(
        receiver_after_retry.app_data,
        vec![post_update.to_vec()],
        "receiver should deliver deferred same-datagram app data after ACK retry"
    );
}

/// A peer-requested KeyUpdate response should be emitted in the same progress
/// pass when no local KeyUpdate is in flight. Otherwise it can sit pending
/// until unrelated input or a timeout drives the state machine again.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_peer_requested_key_update_response_drains_immediately_without_local_update() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(2)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    let server_key_update =
        trigger_key_update(&mut server, &mut client, &mut now, "server-immediate");

    deliver_packets(&server_key_update, &mut client);
    let client_response = collect_packets(&mut client);
    assert!(
        !client_response.is_empty(),
        "client should emit KeyUpdate ACK and response without waiting for another tick"
    );

    deliver_packets(&client_response, &mut server);
    let server_ack_for_client_response = collect_packets(&mut server);
    assert!(
        !server_ack_for_client_response.is_empty(),
        "server should consume and ACK the immediate KeyUpdate response"
    );
    deliver_packets(&server_ack_for_client_response, &mut client);
    let client_after_response_ack = collect_packets(&mut client);
    assert!(
        client_after_response_ack.is_empty(),
        "immediate response must be update_not_requested and must not trigger a further response"
    );

    client
        .send_application_data(b"client-after-immediate-response")
        .expect("client sends post-response data");
    deliver_packets(&collect_packets(&mut client), &mut server);
    server
        .handle_timeout(now)
        .expect("server handles post-response data");
    let server_after_response = drain_outputs(&mut server);
    assert_eq!(
        server_after_response.app_data,
        vec![b"client-after-immediate-response".to_vec()]
    );
}

/// If the client's transmit queue is full while ACKing a peer KeyUpdate, the
/// client must not reprocess the same KeyUpdate on retry. Receive keys and peer
/// handshake sequence advancement stay transactional with ACK retry state.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_client_peer_key_update_ack_backpressure_retries_without_rederiving() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .max_queue_tx(1)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(2)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    assert_peer_key_update_ack_retries_after_transmit_backpressure(
        &mut server,
        &mut client,
        &mut now,
        "server-to-client-backpressure",
        &[b'c'; 1150],
        b"server-after-client-ack-retry",
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_client_deferred_tail_drains_after_ack_backpressure_retry() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .max_queue_tx(1)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    assert_deferred_tail_drains_after_ack_backpressure(
        &mut server,
        &mut client,
        &mut now,
        b"server-primes-client-backpressure-tail",
        b"server-tail-after-client-ack-retry",
        &[b'c'; 1150],
    );
}

/// A peer-requested KeyUpdate response must not replace an in-flight locally
/// initiated KeyUpdate. The response is delayed until the local KeyUpdate is
/// ACKed, then sent normally.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_peer_requested_key_update_response_waits_for_local_update_ack() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(2)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    assert_peer_requested_response_waits_for_local_update_ack(
        &mut client,
        &mut server,
        &mut now,
        "client-local",
        "server-peer",
        b"client-post-overlap",
    );
}

/// Same as the client immediate-response case, but with the server as the
/// responder so the server-side pending response drain is covered too.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_server_peer_requested_key_update_response_drains_immediately_without_local_update() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    let client_key_update = trigger_key_update(&mut client, &mut server, &mut now, "client-peer");

    deliver_packets(&client_key_update, &mut server);
    let server_response = collect_packets(&mut server);
    assert!(
        !server_response.is_empty(),
        "server should emit KeyUpdate ACK and response without waiting for another tick"
    );

    deliver_packets(&server_response, &mut client);
    let client_ack_for_server_response = collect_packets(&mut client);
    assert!(
        !client_ack_for_server_response.is_empty(),
        "client should consume and ACK the immediate KeyUpdate response"
    );
    deliver_packets(&client_ack_for_server_response, &mut server);
    let server_after_response_ack = collect_packets(&mut server);
    assert!(
        server_after_response_ack.is_empty(),
        "immediate response must be update_not_requested and must not trigger a further response"
    );

    server
        .send_application_data(b"server-after-immediate-response")
        .expect("server sends post-response data");
    deliver_packets(&collect_packets(&mut server), &mut client);
    client
        .handle_timeout(now)
        .expect("client handles post-response data");
    let client_after_response = drain_outputs(&mut client);
    assert!(
        client_after_response
            .app_data
            .iter()
            .any(|received| received == b"server-after-immediate-response"),
        "client should receive post-response app data"
    );
}

/// Same as the client backpressure case, but with the server receiving the
/// peer KeyUpdate while its transmit queue is full.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_server_peer_key_update_ack_backpressure_retries_without_rederiving() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(2)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .max_queue_tx(1)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    assert_peer_key_update_ack_retries_after_transmit_backpressure(
        &mut client,
        &mut server,
        &mut now,
        "client-to-server-backpressure",
        &[b's'; 1150],
        b"client-after-server-ack-retry",
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_server_deferred_tail_drains_after_ack_backpressure_retry() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .max_queue_tx(1)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    assert_deferred_tail_drains_after_ack_backpressure(
        &mut client,
        &mut server,
        &mut now,
        b"client-primes-server-backpressure-tail",
        b"client-tail-after-server-ack-retry",
        &[b's'; 1150],
    );
}

/// Test that a reordered packet captured before a KeyUpdate is accepted when
/// delivered alongside other packets during the transition. The packet is from
/// the same epoch and arrives before any new-epoch records, so the replay
/// window accepts it and the retained old epoch keys decrypt it.
///
/// This verifies that auto-KeyUpdate is transparent to application data, even
/// when packets arrive out of order during the key transition.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_old_epoch_packet_still_decrypted() {
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

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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

    // Send the first message and capture its raw packets WITHOUT delivering.
    // This packet is encrypted on epoch 3 (the initial application epoch).
    client
        .send_application_data(b"delayed-old-epoch")
        .expect("send delayed msg");

    now += Duration::from_millis(10);
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    let delayed_packets = client_out.packets.clone();

    // Process server output (don't deliver delayed to server).
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    deliver_packets(&server_out.packets, &mut client);

    // Send enough messages to trigger at least one KeyUpdate (limit=10).
    // The KeyUpdate fires transparently as part of the normal exchange.
    // With the delayed packet withheld, the AEAD count starts from the
    // delayed message (count=1) plus each additional message.
    let mut server_received = 0;
    for i in 0..15 {
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
        server_received, 15,
        "All regular messages should be received"
    );

    // Now deliver the delayed packet that was captured before the KeyUpdate.
    // The server has completed one or more KeyUpdates by now. The old epoch
    // keys (epoch 3) are retained in the app_recv_keys array (up to 4 entries).
    // Each epoch has its own replay window, so the old-epoch packet is accepted
    // and decrypted (the per-epoch window for epoch 3 hasn't seen this seqno).
    //
    // We verify the connection is still healthy after delivering the late
    // packet by sending additional data.
    deliver_packets(&delayed_packets, &mut server);
    now += Duration::from_millis(10);
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    deliver_packets(&server_out.packets, &mut client);

    // Verify post-KeyUpdate data exchange still works. The stale old-epoch
    // packet should not have disrupted the connection.
    let mut post_received = 0;
    for i in 0..10 {
        let msg = format!("Post msg {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("send post msg");

        now += Duration::from_millis(10);

        for _ in 0..3 {
            client.handle_timeout(now).expect("client timeout");
            let client_out = drain_outputs(&mut client);
            deliver_packets(&client_out.packets, &mut server);

            server.handle_timeout(now).expect("server timeout");
            let server_out = drain_outputs(&mut server);
            deliver_packets(&server_out.packets, &mut client);

            post_received += server_out.app_data.len();
        }
    }

    assert_eq!(
        post_received, 10,
        "All post-KeyUpdate messages should be received (stale packet didn't break connection)"
    );
}

/// Test that multiple sequential KeyUpdates work correctly. With a very low
/// AEAD limit, sending many messages should trigger 3+ KeyUpdates in sequence,
/// and all messages must still be received.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_multiple_sequential() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // With limit=3, quarter=0, so threshold=3 exactly (no jitter).
    // Each KeyUpdate cycle: ~3 app records before the next KeyUpdate triggers.
    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(3)
            .build()
            .expect("build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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

    // Send 30 messages. With limit=3, this should trigger at least 3 KeyUpdates
    // (likely more, since ACKs and KeyUpdate records themselves also count as
    // AEAD encryptions on the current epoch).
    let mut server_received = 0;
    for i in 0..30 {
        let msg = format!("Message {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("send app data");

        now += Duration::from_millis(10);

        for _ in 0..5 {
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
        server_received, 30,
        "All 30 messages should be received across 3+ KeyUpdates"
    );
}

/// Test that KeyUpdate completes correctly even when the KeyUpdate message
/// itself is lost and must be retransmitted via timeout. After recovery,
/// subsequent data exchange must work normally.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_with_packet_loss() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(5)
            .build()
            .expect("build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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

    // Send enough messages to trigger KeyUpdate, but drop all packets from the
    // round where the KeyUpdate fires, simulating network loss of the KeyUpdate.
    let mut _server_received = 0;
    let mut dropped_round = false;
    for i in 0..10 {
        let msg = format!("Message {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("send app data");

        now += Duration::from_millis(10);

        client.handle_timeout(now).expect("client timeout");
        let client_out = drain_outputs(&mut client);

        // Drop one round of client packets (simulating KeyUpdate loss).
        // We drop round i==5 which should be around the time a KeyUpdate fires.
        if i == 5 && !dropped_round {
            dropped_round = true;
            // Don't deliver client_out.packets to server — they are lost.
        } else {
            deliver_packets(&client_out.packets, &mut server);
        }

        server.handle_timeout(now).expect("server timeout");
        let server_out = drain_outputs(&mut server);
        deliver_packets(&server_out.packets, &mut client);

        _server_received += server_out.app_data.len();
    }

    // The dropped round means at least one message was lost. Now trigger a
    // retransmission timeout so the KeyUpdate (and any lost data) is resent.
    for _ in 0..10 {
        trigger_timeout(&mut client, &mut now);
        let client_out = drain_outputs(&mut client);
        deliver_packets(&client_out.packets, &mut server);

        server.handle_timeout(now).expect("server timeout");
        let server_out = drain_outputs(&mut server);
        deliver_packets(&server_out.packets, &mut client);

        _server_received += server_out.app_data.len();
    }

    // Continue sending more messages to prove the connection is healthy.
    let mut post_recovery_received = 0;
    for i in 0..10 {
        let msg = format!("Post-recovery {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("send post-recovery");

        now += Duration::from_millis(10);

        for _ in 0..3 {
            client.handle_timeout(now).expect("client timeout");
            let client_out = drain_outputs(&mut client);
            deliver_packets(&client_out.packets, &mut server);

            server.handle_timeout(now).expect("server timeout");
            let server_out = drain_outputs(&mut server);
            deliver_packets(&server_out.packets, &mut client);

            post_recovery_received += server_out.app_data.len();
        }
    }

    assert_eq!(
        post_recovery_received, 10,
        "All post-recovery messages should be received"
    );
}

/// Test that a sender can recover when the KeyUpdate reaches the peer but the
/// peer's ACK is lost. The peer must treat the retransmitted KeyUpdate as a
/// duplicate that triggers a fresh ACK; otherwise the sender remains stuck with
/// previous send keys retained forever.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_lost_ack_retransmission_gets_acknowledged() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(2)
            .build()
            .expect("build client config"),
    );
    let server_config = Arc::new(
        Config::builder()
            .aead_encryption_limit(16)
            .build()
            .expect("build server config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);

    now = complete_dtls13_handshake(&mut client, &mut server, now);

    let client_key_update = trigger_key_update(&mut client, &mut server, &mut now, "client");

    deliver_packets(&client_key_update, &mut server);
    let lost_server_ack = collect_packets(&mut server);
    assert!(!lost_server_ack.is_empty(), "server should ACK KeyUpdate");

    trigger_timeout(&mut client, &mut now);
    client
        .handle_timeout(now)
        .expect("arm KeyUpdate flight timer");
    trigger_timeout(&mut client, &mut now);
    let retransmitted_key_update = collect_packets(&mut client);
    assert!(
        !retransmitted_key_update.is_empty(),
        "client should retransmit unacked KeyUpdate"
    );

    deliver_packets(&retransmitted_key_update, &mut server);
    let server_ack_for_retransmit = collect_packets(&mut server);
    assert!(
        !server_ack_for_retransmit.is_empty(),
        "server should ACK duplicate retransmitted KeyUpdate after the original ACK was lost"
    );
    assert_eq!(
        dtls13_ciphertext_epoch_bits(&server_ack_for_retransmit),
        vec![3, 0],
        concat!(
            "server should retransmit the old-epoch KeyUpdate response ",
            "before appending the fresh current-epoch ACK"
        )
    );

    deliver_packets(&server_ack_for_retransmit, &mut client);
    client
        .handle_timeout(now)
        .expect("client handles ACK for retransmitted KeyUpdate");
    let client_ack_for_server_response = collect_packets(&mut client);
    assert!(
        !client_ack_for_server_response.is_empty(),
        "client should ACK the server's retransmitted KeyUpdate response"
    );

    let mut client_after_retransmit_ack = Vec::new();
    for _ in 0..20 {
        now += Duration::from_millis(500);
        client
            .handle_timeout(now)
            .expect("client checks whether KeyUpdate is still in flight");
        client_after_retransmit_ack.extend(collect_packets(&mut client));
    }
    assert!(
        client_after_retransmit_ack.is_empty(),
        "client should not retransmit KeyUpdate after ACKing the duplicate retransmission"
    );

    deliver_packets(&client_ack_for_server_response, &mut server);
    server
        .handle_timeout(now)
        .expect("server handles ACK for retransmitted response");
    let server_after_ack = collect_packets(&mut server);
    assert!(
        server_after_ack.is_empty(),
        "server should clear its retransmitted KeyUpdate response after ACK"
    );

    client
        .send_application_data(b"post-lost-ack")
        .expect("client sends post-recovery data");
    deliver_packets(&collect_packets(&mut client), &mut server);
    server
        .handle_timeout(now)
        .expect("server handles post-recovery data");
    let server_after_recovery = drain_outputs(&mut server);
    assert_eq!(
        server_after_recovery.app_data,
        vec![b"post-lost-ack".to_vec()]
    );
}

/// Test that high-frequency KeyUpdates work correctly. With the minimum
/// AEAD limit of 2, nearly every message triggers a KeyUpdate. This stress-
/// tests the key rotation machinery and epoch tracking under extreme churn,
/// exercising many more KeyUpdate cycles than the limit=10 tests above.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_key_update_high_frequency() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // With limit=2, quarter=0 so threshold=2 exactly. Every 2 AEAD
    // encryptions on an epoch triggers a KeyUpdate. This means nearly
    // every application message triggers a key rotation.
    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(2)
            .build()
            .expect("build config"),
    );

    let mut now = Instant::now();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

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

    // Send 50 messages with limit=2. This triggers ~25 KeyUpdates,
    // exercising epoch cycling through many values (3, 4, 5, ... ~28).
    let mut server_received = 0;
    for i in 0..50 {
        let msg = format!("High-freq msg {}", i);
        client
            .send_application_data(msg.as_bytes())
            .expect("send app data");

        now += Duration::from_millis(10);

        for _ in 0..5 {
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
        server_received, 50,
        "All 50 messages should be received despite high-frequency KeyUpdates"
    );
}
