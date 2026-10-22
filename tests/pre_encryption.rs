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
