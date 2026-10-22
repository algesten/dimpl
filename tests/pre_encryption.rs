#![cfg(feature = "rcgen")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::{Config, Dtls, Error, Output};

const UNAUTHENTICATED_INPUT: &[u8] = b"unauthenticated input";

#[derive(Default)]
struct Observed {
    packets: Vec<Vec<u8>>,
    connected: bool,
    app_data: Vec<Vec<u8>>,
}

fn drain(endpoint: &mut Dtls, observed: &mut Observed) {
    let mut buffer = [0; 2048];
    loop {
        match endpoint.poll_output(&mut buffer) {
            Output::Packet(packet) => observed.packets.push(packet.to_vec()),
            Output::Connected => observed.connected = true,
            Output::ApplicationData(data) => observed.app_data.push(data.to_vec()),
            Output::Timeout(_) => return,
            _ => {}
        }
    }
}

fn deliver_packets(
    source: &mut Observed,
    destination: &mut Dtls,
    observed: &mut Observed,
    dtls13: bool,
) {
    for packet in std::mem::take(&mut source.packets) {
        if dtls13 {
            destination.handle_packet(&packet).expect("receive packet");
            drain(destination, observed);
        } else {
            // A peer may send CCS and Finished in separate UDP datagrams. Keep
            // that legal ordering so CCS enables encryption before Finished is
            // queued, rather than both arriving in one coalesced datagram.
            let mut remaining = packet.as_slice();
            while !remaining.is_empty() {
                let length = 13 + u16::from_be_bytes([remaining[11], remaining[12]]) as usize;
                destination
                    .handle_packet(&remaining[..length])
                    .expect("receive record");
                drain(destination, observed);
                remaining = &remaining[length..];
            }
        }
    }
}

fn split_records(packets: &[Vec<u8>], dtls13: bool) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    for packet in packets {
        let mut remaining = packet.as_slice();
        while !remaining.is_empty() {
            let length = if dtls13 && remaining[0] & 0xe0 == 0x20 {
                assert_eq!(remaining[0] & 0x1c, 0x0c, "two-byte sequence and length");
                5 + u16::from_be_bytes([remaining[3], remaining[4]]) as usize
            } else {
                13 + u16::from_be_bytes([remaining[11], remaining[12]]) as usize
            };
            records.push(remaining[..length].to_vec());
            remaining = &remaining[length..];
        }
    }
    records
}

fn pre_encryption_record(dtls13: bool, epoch: u16, sequence: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    if dtls13 {
        packet.push(0x2c | (epoch as u8 & 3)); // unified header, S=1, L=1
        packet.extend_from_slice(&sequence.to_be_bytes());
    } else {
        packet.push(23); // ApplicationData
        packet.extend_from_slice(&[0xfe, 0xfd]);
        packet.extend_from_slice(&epoch.to_be_bytes());
        packet.extend_from_slice(&(sequence as u64).to_be_bytes()[2..]);
    }
    packet.extend_from_slice(&(UNAUTHENTICATED_INPUT.len() as u16).to_be_bytes());
    packet.extend_from_slice(UNAUTHENTICATED_INPUT);
    packet
}

fn assert_pre_encryption_record_is_not_delivered(dtls13: bool, epoch: u16) {
    let mut now = Instant::now();
    let config = Arc::new(Config::builder().build().expect("config"));
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = if dtls13 {
        Dtls::new_13(Arc::clone(&config), client_cert, now)
    } else {
        Dtls::new_12(Arc::clone(&config), client_cert, now)
    };
    client.set_active(true);
    let mut server = if dtls13 {
        Dtls::new_13(config, server_cert, now)
    } else {
        Dtls::new_12(config, server_cert, now)
    };
    server.set_active(false);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();

    let packet = pre_encryption_record(dtls13, epoch, 0x1234);
    let mut record_injected = false;
    if dtls13 {
        server.handle_packet(&packet).expect("receive before keys");
        drain(&mut server, &mut server_out);
        assert!(server_out.app_data.is_empty());
        record_injected = true;
    }

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        drain(&mut client, &mut client_out);
        server.handle_timeout(now).expect("server timeout");
        drain(&mut server, &mut server_out);
        deliver_packets(&mut client_out, &mut server, &mut server_out, dtls13);
        if !record_injected
            && server_out
                .packets
                .iter()
                .any(|packet| packet.first() == Some(&22) && packet.get(13) == Some(&2))
        {
            // Inject after ServerHello: DTLS 1.2's HelloVerifyRequest resets
            // the receive queue, so input before the cookie retry is discarded.
            server.handle_packet(&packet).expect("receive before CCS");
            drain(&mut server, &mut server_out);
            assert!(server_out.app_data.is_empty());
            record_injected = true;
        }
        deliver_packets(&mut server_out, &mut client, &mut client_out, dtls13);
        if client_out.connected && server_out.connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(record_injected, "input must reach the pre-encryption queue");
    assert!(
        client_out.connected && server_out.connected,
        "handshake completes"
    );
    assert_eq!(
        server_out.app_data,
        Vec::<Vec<u8>>::new(),
        "pre-encryption epoch {epoch} bytes must be authenticated before delivery"
    );

    client
        .send_application_data(b"authenticated")
        .expect("send");
    drain(&mut client, &mut client_out);
    deliver_packets(&mut client_out, &mut server, &mut server_out, dtls13);
    assert_eq!(server_out.app_data, [b"authenticated".to_vec()]);
}

fn assert_pre_encryption_duplicate_needs_no_queue_slot(dtls13: bool) {
    let now = Instant::now();
    let config = Arc::new(Config::builder().max_queue_rx(1).build().expect("config"));
    let certificate = generate_self_signed_certificate().expect("certificate");
    let mut server = if dtls13 {
        Dtls::new_13(config, certificate, now)
    } else {
        Dtls::new_12(config, certificate, now)
    };
    server.set_active(false);
    let mut observed = Observed::default();
    let epoch = if dtls13 { 2 } else { 1 };
    let packet = pre_encryption_record(dtls13, epoch, 0x1234);
    server.handle_packet(&packet).expect("fill receive queue");
    drain(&mut server, &mut observed);

    let duplicate = server.handle_packet(&packet);
    drain(&mut server, &mut observed);
    let distinct = server.handle_packet(&pre_encryption_record(dtls13, epoch, 0x1235));
    drain(&mut server, &mut observed);

    assert_eq!(distinct, Err(Error::ReceiveQueueFull));
    assert_eq!(duplicate, Ok(()), "duplicate requires no additional slot");
}

#[test]
fn dtls12_pre_encryption_unknown_epoch_is_not_application_data() {
    assert_pre_encryption_record_is_not_delivered(false, 2);
}

#[test]
fn dtls13_pre_encryption_epoch_bits_zero_is_not_application_data() {
    assert_pre_encryption_record_is_not_delivered(true, 0);
}

#[test]
fn dtls13_pre_encryption_epoch_bits_one_is_not_application_data() {
    assert_pre_encryption_record_is_not_delivered(true, 1);
}

#[test]
fn dtls12_pre_encryption_duplicate_at_queue_capacity_is_dropped() {
    assert_pre_encryption_duplicate_needs_no_queue_slot(false);
}

#[test]
fn dtls13_pre_encryption_duplicate_at_queue_capacity_is_dropped() {
    assert_pre_encryption_duplicate_needs_no_queue_slot(true);
}

#[test]
fn dtls13_buffered_corrupted_copy_does_not_discard_clean_handshake_record() {
    let now = Instant::now();
    let config = Arc::new(
        Config::builder()
            .mtu(200)
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();
    server.handle_timeout(now).expect("server timeout");
    drain(&mut server, &mut server_out);
    client.handle_timeout(now).expect("client timeout");
    drain(&mut client, &mut client_out);
    deliver_packets(&mut client_out, &mut server, &mut server_out, true);

    let (ciphertext, plaintext): (Vec<_>, Vec<_>) =
        split_records(&std::mem::take(&mut server_out.packets), true)
            .into_iter()
            .partition(|record| record[0] & 0xe0 == 0x20);
    assert!(!plaintext.is_empty(), "server emits ServerHello");
    assert!(!ciphertext.is_empty(), "server emits encrypted handshake");

    // A damaged copy arrives before the ServerHello needed to derive keys.
    // The complete clean flight follows, also reordered ahead of ServerHello.
    let mut corrupted = ciphertext[0].clone();
    *corrupted.last_mut().expect("ciphertext has tag") ^= 0x55;
    client
        .handle_packet(&corrupted)
        .expect("buffer damaged copy");
    drain(&mut client, &mut client_out);
    for record in ciphertext.iter().chain(&plaintext) {
        client.handle_packet(record).expect("receive clean flight");
        drain(&mut client, &mut client_out);
    }
    assert!(
        client_out.connected,
        "the complete clean flight must progress after authentication discards the damaged copy"
    );
    deliver_packets(&mut client_out, &mut server, &mut server_out, true);
    assert!(
        server_out.connected,
        "both peers complete without a timed retry"
    );
}

#[test]
fn dtls12_buffered_short_copy_does_not_discard_clean_finished() {
    let now = Instant::now();
    let config = Arc::new(
        Config::builder()
            .mtu(200)
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();
    server.handle_timeout(now).expect("server timeout");
    drain(&mut server, &mut server_out);
    client.handle_timeout(now).expect("client timeout");
    drain(&mut client, &mut client_out);
    deliver_packets(&mut client_out, &mut server, &mut server_out, false);
    deliver_packets(&mut server_out, &mut client, &mut client_out, false);

    let flight = split_records(&std::mem::take(&mut client_out.packets), false);
    let finished = flight
        .iter()
        .find(|record| record[0] == 22 && record[3..5] == [0, 1])
        .expect("client emits epoch-1 Finished");
    // A too-short protected record is discarded without a fatal authentication
    // error. It cannot establish the identity of the genuine Finished before CCS.
    let mut short_copy = finished[..13].to_vec();
    short_copy[0] = 23;
    short_copy[11..13].copy_from_slice(&2u16.to_be_bytes());
    short_copy.extend_from_slice(&[0xaa, 0xbb]);
    server
        .handle_packet(&short_copy)
        .expect("buffer short copy");
    drain(&mut server, &mut server_out);
    server
        .handle_packet(finished)
        .expect("buffer clean Finished");
    drain(&mut server, &mut server_out);
    // Deliver the rest of the complete flight, including the CCS that makes
    // both buffered records eligible for authentication.
    for record in flight.iter().filter(|record| record[3..5] == [0, 0]) {
        server.handle_packet(record).expect("receive clean flight");
        drain(&mut server, &mut server_out);
    }
    assert!(
        server_out.connected,
        "the complete clean flight must progress after the short copy is discarded"
    );
    deliver_packets(&mut server_out, &mut client, &mut client_out, false);
    assert!(
        client_out.connected,
        "both peers complete without a timed retry"
    );
}

#[test]
fn dtls12_pre_encryption_handshake_ciphertext_cannot_advance_the_handshake() {
    let now = Instant::now();
    let config = Arc::new(
        Config::builder()
            .mtu(200)
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();
    server.handle_timeout(now).expect("server timeout");
    drain(&mut server, &mut server_out);
    client.handle_timeout(now).expect("client timeout");
    drain(&mut client, &mut client_out);
    deliver_packets(&mut client_out, &mut server, &mut server_out, false);

    let flight = split_records(&std::mem::take(&mut server_out.packets), false);
    let hello_done = flight
        .iter()
        .find(|record| record[0] == 22 && record[13] == 14)
        .expect("server emits ServerHelloDone");
    for record in flight.iter().filter(|record| *record != hello_done) {
        client.handle_packet(record).expect("receive server flight");
        drain(&mut client, &mut client_out);
    }
    assert!(client_out.packets.is_empty(), "await ServerHelloDone");

    // An epoch-1 record is ciphertext even when its opaque payload happens to
    // have the shape of a plaintext handshake. This record is too short to
    // authenticate and must never substitute for the missing epoch-0 message.
    let mut opaque = hello_done.clone();
    opaque[3..5].copy_from_slice(&1u16.to_be_bytes());
    client.handle_packet(&opaque).expect("buffer future epoch");
    drain(&mut client, &mut client_out);
    assert!(
        client_out.packets.is_empty(),
        "unauthenticated epoch-1 bytes must not trigger the client's next flight"
    );

    client
        .handle_packet(hello_done)
        .expect("receive genuine ServerHelloDone");
    drain(&mut client, &mut client_out);
    assert!(
        !client_out.packets.is_empty(),
        "genuine handshake progresses"
    );
    deliver_packets(&mut client_out, &mut server, &mut server_out, false);
    deliver_packets(&mut server_out, &mut client, &mut client_out, false);
    assert!(client_out.connected && server_out.connected);
}

#[test]
fn dtls12_pre_encryption_ciphertext_cannot_substitute_for_plaintext_ccs() {
    let now = Instant::now();
    let config = Arc::new(
        Config::builder()
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();
    server.handle_timeout(now).expect("server timeout");
    drain(&mut server, &mut server_out);
    client.handle_timeout(now).expect("client timeout");
    drain(&mut client, &mut client_out);
    deliver_packets(&mut client_out, &mut server, &mut server_out, false);
    deliver_packets(&mut server_out, &mut client, &mut client_out, false);
    deliver_packets(&mut client_out, &mut server, &mut server_out, false);
    let flight = split_records(&std::mem::take(&mut server_out.packets), false);
    let ccs = flight
        .iter()
        .find(|record| record[0] == 20)
        .expect("server emits CCS");
    let finished = flight
        .iter()
        .find(|record| record[0] == 22 && record[3..5] == [0, 1])
        .expect("server emits protected Finished");

    // This is an undecryptable future-epoch control record, not a legitimate
    // epoch-0 CCS. It must not make buffered Finished eligible for processing.
    let mut opaque = ccs.clone();
    opaque[3..5].copy_from_slice(&1u16.to_be_bytes());
    client.handle_packet(&opaque).expect("buffer future CCS");
    drain(&mut client, &mut client_out);
    client.handle_packet(finished).expect("buffer Finished");
    drain(&mut client, &mut client_out);
    assert!(
        !client_out.connected,
        "unauthenticated epoch-1 CCS must not enable peer encryption"
    );

    client.handle_packet(ccs).expect("receive genuine CCS");
    drain(&mut client, &mut client_out);
    assert!(
        client_out.connected,
        "genuine CCS releases the valid Finished"
    );
}

#[test]
fn dtls13_buffered_plaintext_key_updates_cannot_evict_authenticated_receive_keys() {
    let mut now = Instant::now();
    let config = Arc::new(
        Config::builder()
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();
    server.handle_timeout(now).expect("server timeout");
    drain(&mut server, &mut server_out);

    // ClientHello, Certificate, CertificateVerify and Finished use sequences
    // 0..=3. These future messages must not survive as actionable KeyUpdates:
    // post-handshake control messages require application-epoch protection.
    for sequence in 4..8u16 {
        let mut packet = vec![22, 0xfe, 0xfd, 0, 0];
        packet.extend_from_slice(&(sequence as u64).to_be_bytes()[2..]);
        packet.extend_from_slice(&13u16.to_be_bytes());
        packet.extend_from_slice(&[24, 0, 0, 1]); // KeyUpdate, body length 1
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0]); // offset, length, request
        server.handle_packet(&packet).expect("receive before keys");
        drain(&mut server, &mut server_out);
    }

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        drain(&mut client, &mut client_out);
        server.handle_timeout(now).expect("server timeout");
        drain(&mut server, &mut server_out);
        deliver_packets(&mut client_out, &mut server, &mut server_out, true);
        deliver_packets(&mut server_out, &mut client, &mut client_out, true);
        if client_out.connected && server_out.connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(client_out.connected && server_out.connected);
    for _ in 0..4 {
        server.handle_timeout(now).expect("server timeout");
        drain(&mut server, &mut server_out);
    }

    client
        .send_application_data(b"authenticated")
        .expect("send application data");
    drain(&mut client, &mut client_out);
    deliver_packets(&mut client_out, &mut server, &mut server_out, true);
    assert_eq!(
        server_out.app_data,
        [b"authenticated".to_vec()],
        "unauthenticated buffered KeyUpdates must not change receive keys"
    );
}

fn assert_dtls13_future_plaintext_client_hello_is_discarded(before_keys: bool) {
    let now = Instant::now();
    let config = Arc::new(
        Config::builder()
            .max_queue_rx(8)
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let mut client = Dtls::new_13(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();
    server.handle_timeout(now).expect("server timeout");
    drain(&mut server, &mut server_out);
    client.handle_timeout(now).expect("client timeout");
    drain(&mut client, &mut client_out);

    let mut future_hello = split_records(&client_out.packets, true)
        .into_iter()
        .find(|record| record[0] == 22 && record[13] == 1)
        .expect("client emits plaintext ClientHello");
    // The record and message are entirely public. A new message_seq makes this
    // a forged future message, rather than a genuine same-flight retransmission.
    future_hello[17..19].copy_from_slice(&0xff00u16.to_be_bytes());
    if before_keys {
        let result = server.handle_packet(&future_hello);
        drain(&mut server, &mut server_out);
        result.expect("receive future plaintext hello before keys");
    }

    deliver_packets(&mut client_out, &mut server, &mut server_out, true);
    deliver_packets(&mut server_out, &mut client, &mut client_out, true);
    deliver_packets(&mut client_out, &mut server, &mut server_out, true);
    deliver_packets(&mut server_out, &mut client, &mut client_out, true);
    assert!(client_out.connected && server_out.connected);

    if !before_keys {
        let result = server.handle_packet(&future_hello);
        drain(&mut server, &mut server_out);
        assert_eq!(
            result,
            Ok(()),
            "unauthenticated new plaintext hellos cannot terminate an established association"
        );
    }

    // A retained pre-key hello must not pin handled authenticated data behind
    // it until the receive queue fills. Poll fully after every mutation.
    for sequence in 0..16u8 {
        client
            .send_application_data(&[sequence])
            .expect("send authenticated data");
        drain(&mut client, &mut client_out);
        for packet in std::mem::take(&mut client_out.packets) {
            let result = server.handle_packet(&packet);
            drain(&mut server, &mut server_out);
            assert_eq!(
                result,
                Ok(()),
                "a stale plaintext hello must not exhaust the receive queue at data record {sequence}"
            );
        }
    }
    assert_eq!(
        server_out.app_data,
        (0..16u8).map(|sequence| vec![sequence]).collect::<Vec<_>>()
    );
}

#[test]
fn dtls13_new_plaintext_client_hello_after_handshake_is_ignored() {
    assert_dtls13_future_plaintext_client_hello_is_discarded(false);
}

#[test]
fn dtls13_buffered_future_plaintext_client_hello_does_not_pin_receive_queue() {
    assert_dtls13_future_plaintext_client_hello_is_discarded(true);
}
