#![cfg(feature = "rcgen")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::certificate::generate_self_signed_certificate;
use dimpl::{Config, Dtls, Error, Output, UnexpectedMessageError};

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

fn endpoints(dtls13: bool) -> (Dtls, Dtls, Instant) {
    let now = Instant::now();
    let config = Arc::new(
        Config::builder()
            .use_server_cookie(false)
            .build()
            .expect("config"),
    );
    let client_cert = generate_self_signed_certificate().expect("client certificate");
    let server_cert = generate_self_signed_certificate().expect("server certificate");
    let (mut client, mut server) = if dtls13 {
        (
            Dtls::new_13(Arc::clone(&config), client_cert, now),
            Dtls::new_13(config, server_cert, now),
        )
    } else {
        (
            Dtls::new_12(Arc::clone(&config), client_cert, now),
            Dtls::new_12(config, server_cert, now),
        )
    };
    client.set_active(true);
    server.set_active(false);
    (client, server, now)
}

fn handshake_epoch_error(message_type: u8) -> Error {
    Error::UnexpectedMessage(UnexpectedMessageError::HandshakeEpoch {
        message_type,
        epoch: 0,
    })
}

fn assert_plaintext_protected_handshake_errors(dtls13: bool, to_server: bool) {
    let (mut client, mut server, now) = endpoints(dtls13);
    let mut observed = Observed::default();
    let destination = if to_server { &mut server } else { &mut client };
    destination.handle_timeout(now).expect("start endpoint");
    drain(destination, &mut observed);

    let message_type = if dtls13 { 24 } else { 20 }; // KeyUpdate or Finished
    let body = if dtls13 { vec![0] } else { vec![0; 12] };
    let mut packet = vec![22, 0xfe, 0xfd, 0, 0];
    packet.extend_from_slice(&4u64.to_be_bytes()[2..]);
    packet.extend_from_slice(&((12 + body.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[message_type, 0, 0, body.len() as u8]);
    packet.extend_from_slice(&4u16.to_be_bytes()); // future handshake sequence
    packet.extend_from_slice(&[0, 0, 0, 0, 0, body.len() as u8]);
    packet.extend_from_slice(&body);
    let result = destination.handle_packet(&packet);
    drain(destination, &mut observed);
    assert_eq!(result, Err(handshake_epoch_error(message_type)));
}

fn assert_buffered_future_hello_errors(dtls13: bool, to_server: bool) {
    let (mut client, mut server, now) = endpoints(dtls13);
    let mut client_out = Observed::default();
    let mut server_out = Observed::default();
    server.handle_timeout(now).expect("start server");
    drain(&mut server, &mut server_out);
    client.handle_timeout(now).expect("start client");
    drain(&mut client, &mut client_out);
    if !to_server {
        deliver_packets(&mut client_out, &mut server, &mut server_out, dtls13);
    }
    let (source, destination, observed) = if to_server {
        (&mut client_out, &mut server, &mut server_out)
    } else {
        (&mut server_out, &mut client, &mut client_out)
    };
    let message_type = if to_server { 1 } else { 2 };
    let packet = source
        .packets
        .iter()
        .find(|packet| packet[0] == 22 && packet[13] == message_type)
        .expect("plaintext hello flight");
    let length = 13 + u16::from_be_bytes([packet[11], packet[12]]) as usize;
    let mut future_hello = packet[..length].to_vec();
    future_hello[17..19].copy_from_slice(&0xff00u16.to_be_bytes());
    let result = destination.handle_packet(&future_hello);
    drain(destination, observed);
    result.expect("buffer future hello while still awaiting the genuine hello");

    // Progress the genuine handshake. The state machine must reject the
    // leftover plaintext before waiting for protected handshake messages.
    for _ in 0..10 {
        for to_server_now in [true, false] {
            let (source, destination, observed) = if to_server_now {
                (&mut client_out, &mut server, &mut server_out)
            } else {
                (&mut server_out, &mut client, &mut client_out)
            };
            for packet in std::mem::take(&mut source.packets) {
                let result = destination.handle_packet(&packet);
                drain(destination, observed);
                if result.is_err() {
                    assert_eq!(to_server_now, to_server);
                    assert_eq!(result, Err(handshake_epoch_error(message_type)));
                    return;
                }
            }
        }
    }
    panic!("buffered plaintext hello survived the transition to protected handshakes");
}

#[test]
fn dtls12_client_errors_on_plaintext_finished() {
    assert_plaintext_protected_handshake_errors(false, false);
}

#[test]
fn dtls12_server_errors_on_plaintext_finished() {
    assert_plaintext_protected_handshake_errors(false, true);
}

#[test]
fn dtls13_client_errors_on_plaintext_key_update() {
    assert_plaintext_protected_handshake_errors(true, false);
}

#[test]
fn dtls13_server_errors_on_plaintext_key_update() {
    assert_plaintext_protected_handshake_errors(true, true);
}

#[test]
fn dtls12_client_errors_on_buffered_future_server_hello() {
    assert_buffered_future_hello_errors(false, false);
}

#[test]
fn dtls12_server_errors_on_buffered_future_client_hello() {
    assert_buffered_future_hello_errors(false, true);
}

#[test]
fn dtls13_client_errors_on_buffered_future_server_hello() {
    assert_buffered_future_hello_errors(true, false);
}

#[test]
fn dtls13_server_errors_on_buffered_future_client_hello() {
    assert_buffered_future_hello_errors(true, true);
}
