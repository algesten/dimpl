//! DTLS 1.3 edge case and error recovery tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls};

use crate::common::*;

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

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_close_notify_graceful_shutdown() {
    // NOTE: dimpl does not currently expose a close() or shutdown() method on the
    // Dtls API. The public API consists of handle_packet, poll_output,
    // handle_timeout, and send_application_data. There is no way for the
    // application to initiate a close_notify alert or graceful shutdown.
    //
    // This test documents the gap: a close_notify mechanism should be added so
    // that an endpoint can signal graceful connection closure to its peer.
    //
    // When a close() or shutdown() method is added, this test should be updated
    // to: (1) complete a handshake, (2) exchange some data, (3) call close() on
    // the client, (4) poll for the resulting alert packet, (5) deliver it to the
    // server, and (6) verify the server recognizes the connection as closed.
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

    // Exchange data to confirm the connection is fully operational.
    client
        .send_application_data(b"hello")
        .expect("send app data");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"hello"),
        "Server should receive application data"
    );

    // Gap: no close()/shutdown() method exists on Dtls.
    // When added, the test should call client.close() here and verify the alert.
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_unknown_epoch_record() {
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

    // After handshake, application data uses epoch 3 (epoch_bits = 3 & 0x03 = 3).
    // Craft a ciphertext record with epoch_bits=1, which would map to epoch 1 if
    // no keys exist for it (or to an epoch whose low 2 bits are 01, e.g. epoch 5
    // which has never been negotiated).
    //
    // Unified header: 001CSLEE with C=0, S=1, L=1, EE=01 => 0b0010_1101 = 0x2D.
    // This targets epoch_bits=1 -- no keys installed for any epoch with low bits 01.
    let mut bogus = Vec::new();
    bogus.push(0x2D); // flags: S=1, L=1, epoch_bits=01
    bogus.extend_from_slice(&0x0000u16.to_be_bytes()); // encrypted seq bits
    bogus.extend_from_slice(&0x0020u16.to_be_bytes()); // length = 32
    bogus.extend_from_slice(&[0xAA; 32]); // fake ciphertext (will fail AEAD)

    // Should be silently discarded (decryption will fail since no keys for this epoch)
    client
        .handle_packet(&bogus)
        .expect("unknown-epoch record should be discarded");

    // Verify normal data exchange still works.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after unknown-epoch bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_truncated_unified_header() {
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

    // Deliver a 1-byte packet that looks like a unified header but is truncated.
    // 0x2F = 001CSLEE with C=0, S=1, L=1, EE=11 -- expects at least 5 header
    // bytes (flags + 2 seq + 2 length) but we only provide the flags byte.
    let bogus = vec![0x2F];

    // The parser requires at least 2 bytes for a ciphertext record. This should
    // result in a parse error, but handle_packet may surface it as Err. Either way,
    // the endpoint must remain operational.
    let _ = client.handle_packet(&bogus);

    // Verify normal operation continues.
    client.send_application_data(b"ping").expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d.as_slice() == b"ping"),
        "Server should receive application data after truncated header packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_discards_plaintext_after_handshake() {
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

    // Craft a DTLS 1.2-style plaintext record (13-byte header).
    // content_type=22 (Handshake), version=0xFEFD (DTLS 1.2), epoch=0, seq=0,
    // length=5, then 5 bytes of garbage body.
    let bogus = vec![
        0x16, // content_type: Handshake
        0xFE, 0xFD, // version: DTLS 1.2
        0x00, 0x00, // epoch: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sequence_number: 0
        0x00, 0x05, // length: 5
        0x01, 0x00, 0x00, 0x00, 0x00, // 5 bytes of fake handshake body
    ];

    // Delivering a plaintext handshake record after the handshake is complete should
    // either be silently discarded or produce an error. Either way the connection
    // should remain operational for application data.
    let _ = client.handle_packet(&bogus);

    // Verify application data exchange still works.
    client
        .send_application_data(b"after-plaintext")
        .expect("send app");
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);

    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out
            .app_data
            .iter()
            .any(|d| d.as_slice() == b"after-plaintext"),
        "Server should receive application data after plaintext bogus packet"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls13_alert_bad_certificate() {
    // NOTE: dimpl does not perform certificate chain/trust validation. The library
    // surfaces the peer's leaf certificate via Output::PeerCert and delegates all
    // validation to the application layer. There is no configurable certificate
    // verifier or trust store that could cause the handshake to fail due to a
    // "bad certificate".
    //
    // This test documents the gap: dimpl should ideally support a pluggable
    // certificate verifier callback (e.g., via Config) so that applications can
    // reject untrusted certificates and trigger an appropriate alert.
    //
    // Since both endpoints use self-signed certificates and dimpl accepts them
    // unconditionally, we verify that the handshake completes and the peer
    // certificates are surfaced via Output::PeerCert. The application would
    // then inspect the certificate and decide whether to continue.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Store the DER bytes so we can verify PeerCert output
    let client_cert_der = client_cert.certificate.clone();
    let server_cert_der = server_cert.certificate.clone();

    let config = dtls13_config();

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_peer_cert: Option<Vec<u8>> = None;
    let mut server_peer_cert: Option<Vec<u8>> = None;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_out.peer_cert.is_some() {
            client_peer_cert = client_out.peer_cert;
        }
        if server_out.peer_cert.is_some() {
            server_peer_cert = server_out.peer_cert;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");

    // Verify that PeerCert was emitted so the application can inspect it.
    // The client should see the server's certificate and vice versa.
    let client_saw_cert = client_peer_cert.expect("Client should receive PeerCert");
    assert_eq!(
        client_saw_cert, server_cert_der,
        "Client's PeerCert should match the server's certificate"
    );

    let server_saw_cert = server_peer_cert.expect("Server should receive PeerCert");
    assert_eq!(
        server_saw_cert, client_cert_der,
        "Server's PeerCert should match the client's certificate"
    );

    // Gap: no way to reject a certificate and trigger a bad_certificate alert.
    // When a certificate verifier callback is added to Config, this test should
    // be updated to install a verifier that rejects the peer's self-signed cert
    // and assert the handshake fails with an appropriate error.
}

/// Regression test for bug #1: advertised signature schemes must all be functional.
///
/// Previously, Ed25519 (0x0807) and RSA_PSS_RSAE_SHA256 (0x0804) were advertised
/// in the ClientHello signature_algorithms extension but could not be verified,
/// causing handshake failures when a peer selected them.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_only_functional_signature_schemes_advertised() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");

    let config = dtls13_config();

    let mut client = Dtls::new_13(config, client_cert);
    client.set_active(true);

    // Trigger the first ClientHello
    let now = Instant::now();
    client.handle_timeout(now).expect("client timeout");
    let out = drain_outputs(&mut client);
    assert!(!out.packets.is_empty(), "Client should send ClientHello");

    // The first packet is a plaintext record containing the ClientHello.
    // DTLSPlaintext header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13 bytes.
    // Handshake header: msg_type(1) + length(3) + message_seq(2)
    //                   + frag_offset(3) + frag_length(3) = 12 bytes.
    // ClientHello body: version(2) + random(32) + session_id_len(1) + session_id + cookie_len(1) + cookie
    //                   + cipher_suites_len(2) + cipher_suites + comp_methods_len(1) + comp_methods
    //                   + extensions_len(2) + extensions...
    let ch_packet = &out.packets[0];

    // Find signature_algorithms extension (type 0x000D) in the packet.
    // Scan for the 2-byte extension type.
    let sig_alg_type: [u8; 2] = [0x00, 0x0D];
    let pos = ch_packet
        .windows(2)
        .position(|w| w == sig_alg_type)
        .expect("signature_algorithms extension should be present in ClientHello");

    // Extension format: type(2) + ext_len(2) + list_len(2) + schemes(2 each)
    let ext_len_offset = pos + 2;
    let list_len_offset = ext_len_offset + 2;
    let list_len =
        u16::from_be_bytes([ch_packet[list_len_offset], ch_packet[list_len_offset + 1]]) as usize;
    let schemes_start = list_len_offset + 2;

    // Extract all advertised scheme codes
    let mut advertised: Vec<u16> = Vec::new();
    let mut i = schemes_start;
    while i < schemes_start + list_len {
        let scheme = u16::from_be_bytes([ch_packet[i], ch_packet[i + 1]]);
        advertised.push(scheme);
        i += 2;
    }

    // Only ECDSA P-256 (0x0403) and P-384 (0x0503) should be advertised.
    let non_functional: Vec<u16> = advertised
        .iter()
        .copied()
        .filter(|s| *s != 0x0403 && *s != 0x0503)
        .collect();

    assert!(
        non_functional.is_empty(),
        "Non-functional signature schemes advertised: {:04X?}. \
         Only ECDSA_SECP256R1_SHA256 (0x0403) and ECDSA_SECP384R1_SHA384 (0x0503) \
         should be advertised.",
        non_functional,
    );

    assert_eq!(
        advertised,
        vec![0x0403, 0x0503],
        "Expected exactly ECDSA P-256 and P-384"
    );
}

/// Regression test for bug #2: a bad record in a multi-record datagram must not
/// kill subsequent valid records.
///
/// Previously, certain per-record errors (parse failure, content type recovery)
/// would propagate as Err and abort parsing of the entire datagram, causing valid
/// records after the bad one to be lost.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_bad_record_does_not_kill_datagram() {
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

    // Send application data from server and capture the ciphertext packet.
    server
        .send_application_data(b"hello")
        .expect("send app data");
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        !server_out.packets.is_empty(),
        "Server should produce a packet"
    );
    let good_record = &server_out.packets[0];

    // Construct a bogus ciphertext record with unknown epoch (epoch_bits=01).
    // Unified header: flags=0x2D (001 C=0 S=1 L=1 EE=01), seq=0x0000, length=32.
    let mut bogus_record = Vec::new();
    bogus_record.push(0x2D); // flags: S=1, L=1, epoch_bits=01
    bogus_record.extend_from_slice(&0x0000u16.to_be_bytes()); // encrypted seq
    bogus_record.extend_from_slice(&0x0020u16.to_be_bytes()); // length = 32
    bogus_record.extend_from_slice(&[0xAA; 32]); // fake ciphertext

    // Build a multi-record datagram: bogus record FIRST, then the valid record.
    // If the bad record aborts the datagram, the good record is lost.
    let mut combined = bogus_record;
    combined.extend_from_slice(good_record);

    // Deliver the combined datagram. Must not error.
    client
        .handle_packet(&combined)
        .expect("multi-record datagram with bad first record should not error");

    // The valid record should have been processed despite the bad first record.
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    assert!(
        client_out.app_data.iter().any(|d| d.as_slice() == b"hello"),
        "Client should receive the valid app data record that followed the bogus record"
    );
}

/// Regression test for bug #3: single replay window across epochs.
///
/// Before the fix, a single `ReplayWindow` tracked all epochs. When a
/// new-epoch record arrived (after KeyUpdate), the window advanced and
/// permanently rejected all old-epoch records — even though old receive
/// keys were still retained. This test verifies that a delayed old-epoch
/// packet IS accepted and delivered as application data after a KeyUpdate.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_old_epoch_record_accepted_after_key_update() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Low limit to trigger KeyUpdate quickly.
    let config = Arc::new(
        Config::builder()
            .aead_encryption_limit(5)
            .build()
            .expect("build config"),
    );

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

    // Complete handshake.
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

    // Send one message and capture its packet WITHOUT delivering to server.
    // This packet is encrypted on the initial application epoch (epoch 3).
    client
        .send_application_data(b"old-epoch-data")
        .expect("send delayed msg");
    now += Duration::from_millis(10);
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    let delayed_packets = client_out.packets.clone();

    // Process server output (don't deliver delayed to server).
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    deliver_packets(&server_out.packets, &mut client);

    // Send enough messages to trigger at least one KeyUpdate (limit=5).
    let mut server_received = 0;
    for i in 0..12 {
        let msg = format!("msg-{}", i);
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
        server_received, 12,
        "All regular messages should be received"
    );

    // NOW deliver the old-epoch packet. With per-epoch replay windows,
    // the epoch-3 window hasn't seen this sequence number, so it must be
    // accepted and decrypted using the retained old-epoch keys.
    deliver_packets(&delayed_packets, &mut server);
    now += Duration::from_millis(10);
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    deliver_packets(&server_out.packets, &mut client);

    assert!(
        server_out
            .app_data
            .iter()
            .any(|d| d.as_slice() == b"old-epoch-data"),
        "Server must receive the delayed old-epoch packet (per-epoch replay windows)"
    );
}

/// Test that the ClientHello is padded to fill the configured MTU.
///
/// RFC 7685 defines the padding extension (type 0x0015) to increase
/// the ClientHello size, reducing the server-to-client amplification
/// factor in DTLS.
#[test]
#[cfg(feature = "rcgen")]
fn dtls13_client_hello_padded_to_mtu() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let mtu = 1150; // default MTU

    let config = dtls13_config();

    let mut client = Dtls::new_13(config, client_cert);
    client.set_active(true);

    let now = Instant::now();
    client.handle_timeout(now).expect("client timeout");
    let out = drain_outputs(&mut client);
    assert!(!out.packets.is_empty(), "Client should send ClientHello");

    let ch_packet = &out.packets[0];

    // The ClientHello record should fill the MTU exactly.
    assert_eq!(
        ch_packet.len(),
        mtu,
        "ClientHello packet should be padded to MTU ({} bytes), got {} bytes",
        mtu,
        ch_packet.len()
    );

    // Verify the padding extension (type 0x0015) is present.
    let padding_type: [u8; 2] = [0x00, 0x15];
    let has_padding = ch_packet.windows(2).any(|w| w == padding_type);
    assert!(
        has_padding,
        "ClientHello should contain a padding extension (type 0x0015)"
    );
}
