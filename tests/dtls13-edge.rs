//! DTLS 1.3 edge case and error recovery tests.

mod dtls13_common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::Dtls;
use dtls13_common::*;

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_too_short_ciphertext_record() {
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

    // Craft a DTLS 1.3 ciphertext record with length < 16 bytes.
    // Header: fixed bits 001, C=0, S=1 (16-bit seq), L=1 (length), epoch_bits=3
    // => 0b0010_1111 = 0x2F
    let bogus = vec![
        0x2F, // unified header byte
        0x00, 0x01, // encrypted sequence bits
        0x00, 0x01, // length = 1
        0x00, // 1 byte ciphertext (too short)
    ];

    // Should be silently discarded (no error)
    client
        .handle_packet(&bogus)
        .expect("too-short ciphertext record should be discarded");

    // Verify we can still exchange application data.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_cid_bit_records() {
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

    // Unified header with CID bit set: 001CSLEE with C=1, S=1, L=1, epoch_bits=3 => 0x3F.
    // We don't support CID, so this should be silently discarded.
    let bogus = vec![0x3F];

    client
        .handle_packet(&bogus)
        .expect("CID-bit record should be discarded");

    // Verify we can still exchange application data.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after CID-bit bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_unauthenticated_ciphertext_without_length_field() {
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

    // Craft a DTLS 1.3 ciphertext record with L=0 (no explicit length).
    // Header: 001CSLEE with C=0, S=1, L=0, epoch_bits=3 => 0x2B.
    // Provide 16+ bytes ciphertext so sequence-number mask can be computed.
    let mut bogus = Vec::new();
    bogus.push(0x2B);
    bogus.extend_from_slice(&0x0001u16.to_be_bytes()); // encrypted seq bits
    bogus.extend_from_slice(&[0u8; 16]); // unauthenticated ciphertext/tag bytes

    client
        .handle_packet(&bogus)
        .expect("Unauthenticated ciphertext should be discarded");

    // Verify we can still exchange application data.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after unauthenticated bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_recovers_from_corrupted_packet() {
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
    let mut corrupted_once = false;

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

        // Corrupt one packet
        for mut p in client_out.packets {
            if !corrupted_once && p.len() > 20 {
                // Corrupt some bytes in the middle (handshake length field)
                p[15] ^= 0xFF;
                p[16] ^= 0xFF;
                corrupted_once = true;
            }
            let _ = server.handle_packet(&p);
        }

        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        // Trigger retransmissions
        if i % 5 == 4 {
            now += Duration::from_secs(2);
        } else {
            now += Duration::from_millis(50);
        }
    }

    assert!(
        client_connected,
        "Client should connect despite corrupted packet"
    );
    assert!(
        server_connected,
        "Server should connect despite corrupted packet"
    );
}
