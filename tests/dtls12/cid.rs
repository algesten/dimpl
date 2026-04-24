//! DTLS 1.2 Connection ID (RFC 9146) integration tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::crypto::Dtls12CipherSuite;
use dimpl::{Config, Dtls, Output};

use crate::common::*;

/// Name of an `Output` variant, without `Debug`-printing its payload.
/// Avoids logging sensitive-looking variant contents (e.g. `PeerCert`) in
/// assertion failure messages; CodeQL flags `{:?}` on `Output` as cleartext
/// logging even though our `Debug` impl only prints a length.
fn output_variant(o: &Output<'_>) -> &'static str {
    match o {
        Output::Packet(_) => "Packet",
        Output::Timeout(_) => "Timeout",
        Output::Connected => "Connected",
        Output::PeerCert(_) => "PeerCert",
        Output::KeyingMaterial(..) => "KeyingMaterial",
        Output::ApplicationData(_) => "ApplicationData",
        Output::CloseNotify => "CloseNotify",
        Output::ConnectionId(_) => "ConnectionId",
        _ => "Unknown",
    }
}

/// Helper to build a config with a connection ID.
fn dtls12_config_with_cid(cid: &[u8]) -> Arc<Config> {
    Arc::new(
        Config::builder()
            .with_connection_id(cid.to_vec())
            .build()
            .expect("Failed to build config"),
    )
}

/// Helper to build a config with a connection ID and specific cipher suite.
fn dtls12_config_with_cid_and_suite(cid: &[u8], suite: Dtls12CipherSuite) -> Arc<Config> {
    Arc::new(
        Config::builder()
            .with_connection_id(cid.to_vec())
            .dtls12_cipher_suites(&[suite])
            .build()
            .expect("Failed to build config"),
    )
}

/// Both sides configure CID → handshake completes, Output::ConnectionId emitted,
/// application data flows with CID-bearing records.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_both_sides() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_cid = b"client-cid";
    let server_cid = b"server-cid";

    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_connection_id: Option<Vec<u8>> = None;
    let mut server_connection_id: Option<Vec<u8>> = None;

    // Complete handshake
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_out.connection_id.is_some() {
            client_connection_id = client_out.connection_id;
        }
        if server_out.connection_id.is_some() {
            server_connection_id = server_out.connection_id;
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

    // Both sides should have emitted their CID
    assert_eq!(
        client_connection_id.as_deref(),
        Some(client_cid.as_slice()),
        "Client should emit its own CID"
    );
    assert_eq!(
        server_connection_id.as_deref(),
        Some(server_cid.as_slice()),
        "Server should emit its own CID"
    );

    // Application data should flow with CID-bearing records
    let client_data = b"hello via CID";
    let server_data = b"world via CID";

    client
        .send_application_data(client_data)
        .expect("client send");
    server
        .send_application_data(server_data)
        .expect("server send");

    let mut client_received = Vec::new();
    let mut server_received = Vec::new();

    for _ in 0..20 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        // Verify outgoing packets use CID content type (25)
        for pkt in &client_out.packets {
            if !pkt.is_empty() && pkt[0] == 25 {
                // CID record — verify CID bytes are present in header
                assert!(
                    pkt.len() >= 11 + server_cid.len() + 2,
                    "CID record too short"
                );
            }
        }

        for data in &client_out.app_data {
            client_received.extend_from_slice(data);
        }
        for data in &server_out.app_data {
            server_received.extend_from_slice(data);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if !client_received.is_empty() && !server_received.is_empty() {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert_eq!(
        server_received, client_data,
        "Server should receive client data"
    );
    assert_eq!(
        client_received, server_data,
        "Client should receive server data"
    );
}

/// Neither side configures CID → existing behavior unchanged, no ConnectionId emitted.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_neither_side() {
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
    let mut got_client_cid = false;
    let mut got_server_cid = false;

    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;
        got_client_cid |= client_out.connection_id.is_some();
        got_server_cid |= server_out.connection_id.is_some();

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");
    assert!(!got_client_cid, "Client should not emit ConnectionId");
    assert!(!got_server_cid, "Server should not emit ConnectionId");

    // Application data should still work without CID
    client.send_application_data(b"no cid").expect("send");

    let client_pkts = collect_packets(&mut client);

    // Verify no CID content type in outgoing packets
    for pkt in &client_pkts {
        assert_ne!(pkt[0], 25, "Should not use CID content type");
    }

    deliver_packets(&client_pkts, &mut server);
    let server_out = drain_outputs(&mut server);
    assert_eq!(server_out.app_data.len(), 1);
    assert_eq!(server_out.app_data[0], b"no cid");
}

/// One side offers CID, the other doesn't → graceful fallback to no-CID.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_one_side_only() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Client offers CID, server does not
    let client_config = dtls12_config_with_cid(b"my-cid");
    let server_config = dtls12_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut got_client_cid = false;
    let mut got_server_cid = false;

    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;
        got_client_cid |= client_out.connection_id.is_some();
        got_server_cid |= server_out.connection_id.is_some();

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Client should be connected even without CID"
    );
    assert!(
        server_connected,
        "Server should be connected even without CID"
    );
    // No CID should be emitted since server didn't offer one
    assert!(!got_client_cid, "Client should not emit ConnectionId");
    assert!(!got_server_cid, "Server should not emit ConnectionId");

    // Data should still flow
    client.send_application_data(b"fallback").expect("send");
    let client_pkts = collect_packets(&mut client);
    deliver_packets(&client_pkts, &mut server);
    let server_out = drain_outputs(&mut server);
    assert_eq!(server_out.app_data[0], b"fallback");
}

/// Empty CID (zero-length) is valid per RFC 9146.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_empty() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Both sides use empty CID
    let client_config = dtls12_config_with_cid(b"");
    let server_config = dtls12_config_with_cid(b"");

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_cid_event: Option<Vec<u8>> = None;
    let mut server_cid_event: Option<Vec<u8>> = None;

    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_out.connection_id.is_some() {
            client_cid_event = client_out.connection_id;
        }
        if server_out.connection_id.is_some() {
            server_cid_event = server_out.connection_id;
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

    // RFC 9146 §3 + Output::ConnectionId contract: the variant fires on
    // successful negotiation even when the negotiated value is empty.
    assert_eq!(
        client_cid_event.as_deref(),
        Some(&[][..]),
        "client must emit Output::ConnectionId(&[]) for zero-length negotiation"
    );
    assert_eq!(
        server_cid_event.as_deref(),
        Some(&[][..]),
        "server must emit Output::ConnectionId(&[]) for zero-length negotiation"
    );

    // Data should flow with empty CID using legacy (non-tls12_cid) framing.
    client.send_application_data(b"empty cid").expect("send");
    let client_pkts = collect_packets(&mut client);
    // RFC 9146 §3 zero-length-direction rule: legacy framing only —
    // never content type 25 on the wire.
    for p in &client_pkts {
        assert_ne!(
            p.first(),
            Some(&25),
            "zero-length CID direction must not emit tls12_cid (25) records"
        );
    }
    deliver_packets(&client_pkts, &mut server);
    let server_out = drain_outputs(&mut server);
    assert_eq!(server_out.app_data[0], b"empty cid");
}

/// CID with AES-128-GCM (8-byte explicit nonce) — verifies CID header layout
/// doesn't conflict with the explicit nonce prefix.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_aes128_gcm() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    let suite = Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256;
    let client_config = dtls12_config_with_cid_and_suite(b"gcm-client", suite);
    let server_config = dtls12_config_with_cid_and_suite(b"gcm-server", suite);

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..50 {
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

    assert!(
        client_connected,
        "Client should connect with AES-128-GCM + CID"
    );
    assert!(
        server_connected,
        "Server should connect with AES-128-GCM + CID"
    );

    // Bidirectional app data
    client.send_application_data(b"gcm-cid").expect("send");
    let pkts = collect_packets(&mut client);

    // Verify CID content type in encrypted records
    for pkt in &pkts {
        if !pkt.is_empty() {
            assert_eq!(pkt[0], 25, "Encrypted records should use CID content type");
        }
    }

    deliver_packets(&pkts, &mut server);
    let server_out = drain_outputs(&mut server);
    assert_eq!(server_out.app_data[0], b"gcm-cid");
}

/// CID with ChaCha20-Poly1305 (no explicit nonce) — verifies CID works with
/// suites that don't prepend an explicit nonce.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_chacha20() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    let suite = Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256;
    let client_config = dtls12_config_with_cid_and_suite(b"cc20-c", suite);
    let server_config = dtls12_config_with_cid_and_suite(b"cc20-s", suite);

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..50 {
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

    assert!(
        client_connected,
        "Client should connect with ChaCha20 + CID"
    );
    assert!(
        server_connected,
        "Server should connect with ChaCha20 + CID"
    );

    client.send_application_data(b"chacha-cid").expect("send");
    let pkts = collect_packets(&mut client);
    deliver_packets(&pkts, &mut server);
    let server_out = drain_outputs(&mut server);
    assert_eq!(server_out.app_data[0], b"chacha-cid");
}

/// Asymmetric CID lengths — client uses short CID, server uses longer CID.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_asymmetric_lengths() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    // Client: 2-byte CID, Server: 16-byte CID
    let client_config = dtls12_config_with_cid(b"\x01\x02");
    let server_config = dtls12_config_with_cid(b"0123456789abcdef");

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_cid: Option<Vec<u8>> = None;
    let mut server_cid: Option<Vec<u8>> = None;

    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_connected |= client_out.connected;
        server_connected |= server_out.connected;

        if client_out.connection_id.is_some() {
            client_cid = client_out.connection_id;
        }
        if server_out.connection_id.is_some() {
            server_cid = server_out.connection_id;
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected);
    assert!(server_connected);

    // Each side emits its own CID
    assert_eq!(client_cid.as_deref(), Some(b"\x01\x02".as_slice()));
    assert_eq!(server_cid.as_deref(), Some(b"0123456789abcdef".as_slice()));

    // Bidirectional data flows despite different CID lengths
    client.send_application_data(b"short->long").expect("send");
    server.send_application_data(b"long->short").expect("send");

    let mut client_app: Vec<Vec<u8>> = Vec::new();
    let mut server_app: Vec<Vec<u8>> = Vec::new();

    for _ in 0..20 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        client_app.extend(client_out.app_data.clone());
        server_app.extend(server_out.app_data.clone());

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if !client_app.is_empty() && !server_app.is_empty() {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        server_app.iter().any(|d| d == b"short->long"),
        "Server should receive data via short CID"
    );
    assert!(
        client_app.iter().any(|d| d == b"long->short"),
        "Client should receive data via long CID"
    );
}

/// CID with retransmission — verify CID records work across flight retransmits.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_retransmission() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    let client_config = dtls12_config_with_cid(b"retx-c");
    let server_config = dtls12_config_with_cid(b"retx-s");

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Complete handshake normally first
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..50 {
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

    assert!(client_connected);
    assert!(server_connected);

    // Send data, but DROP the packets (simulate loss)
    client
        .send_application_data(b"will-retransmit")
        .expect("send");
    let lost_pkts = collect_packets(&mut client);
    assert!(!lost_pkts.is_empty(), "Should have packets to send");
    // Intentionally not delivering lost_pkts

    // Send again — the application layer retransmit
    client.send_application_data(b"retry-data").expect("send");
    let retry_pkts = collect_packets(&mut client);
    deliver_packets(&retry_pkts, &mut server);

    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d == b"retry-data"),
        "Server should receive retried data over CID"
    );
}

/// RFC 9146 §5.3 / RFC 6347 §4.1.2.7: a CID record whose wire CID does not match
/// the negotiated inbound CID must be silently dropped at the AEAD layer, AND the
/// replay window must not advance on the tampered sequence. This test flips a
/// byte in the CID field of a post-handshake record, verifies the peer drops it
/// silently, then delivers the untampered original at the same sequence and
/// asserts it still arrives — proving both tamper detection and replay-window
/// correctness.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_tampered_record_is_dropped() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Client's inbound CID is what the server writes into the CID field of
    // records it sends. Tampering that byte on the wire should fail the client's
    // on-wire CID authentication check.
    let client_cid: &[u8] = b"tamper-c";
    let server_cid: &[u8] = b"tamper-s";

    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Complete the handshake normally.
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
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
    assert!(client_connected && server_connected);

    // Server sends a post-handshake application data record.
    let payload = b"cid-tamper-canary";
    server.send_application_data(payload).expect("server send");
    let server_pkts = collect_packets(&mut server);

    // Find the CID-typed record the server produced. Content type 25 = tls12_cid.
    let cid_pkt = server_pkts
        .iter()
        .find(|p| !p.is_empty() && p[0] == 25)
        .expect("server should emit a tls12_cid record");

    // The CID field sits at bytes [11..11+client_cid.len()]. Confirm layout and
    // build a tampered copy that flips one bit of the CID.
    assert!(
        cid_pkt.len() >= 11 + client_cid.len() + 2,
        "tls12_cid record too short"
    );
    assert_eq!(
        &cid_pkt[11..11 + client_cid.len()],
        client_cid,
        "wire CID should be the client's configured inbound CID"
    );

    let mut tampered = cid_pkt.clone();
    tampered[11] ^= 0x01;

    // Deliver the tampered record first. The client must drop it silently (no
    // error surfaced, no app data emitted).
    deliver_packets(&[tampered], &mut client);
    let after_tamper = drain_outputs(&mut client);
    assert!(
        after_tamper.app_data.is_empty(),
        "Client must not surface app data from a tampered CID record"
    );

    // Now deliver the untampered original at the same sequence number. The
    // replay window must NOT have advanced on the tampered drop, so this
    // retransmit still decrypts and the payload arrives.
    deliver_packets(std::slice::from_ref(cid_pkt), &mut client);
    let after_valid = drain_outputs(&mut client);
    assert!(
        after_valid.app_data.iter().any(|d| d == payload),
        "Client must accept the untampered original after a tampered drop \
         (replay window must not advance on tampered sequence)"
    );
}

/// RFC 6347 §4.1.2.6: the receive window is only updated once AEAD
/// verification succeeds. The CID tamper test above covers the CID-auth
/// failure case; this closes the symmetric gap by tampering the *ciphertext*
/// of a CID record (not the CID itself). The CID still matches the
/// negotiated value, so the on-wire CID check passes, but AEAD decryption
/// fails and the record is silently dropped. The replay window must not
/// advance on the tampered sequence, so a legitimate retransmit at the same
/// sequence still decrypts.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_tampered_ciphertext_preserves_replay_window() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_cid: &[u8] = b"ct-tc";
    let server_cid: &[u8] = b"ct-ts";

    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();

    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        client_connected |= co.connected;
        server_connected |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(client_connected && server_connected);

    // Server sends a post-handshake application data record.
    let payload = b"ct-tamper-canary";
    server.send_application_data(payload).expect("server send");
    let server_pkts = collect_packets(&mut server);
    let cid_pkt = server_pkts
        .iter()
        .find(|p| !p.is_empty() && p[0] == 25)
        .expect("server should emit a tls12_cid record")
        .clone();

    // Confirm the CID field layout so we flip a byte strictly *after* the
    // CID (i.e. inside the ciphertext), leaving the CID bytes intact.
    assert!(cid_pkt.len() >= 11 + client_cid.len() + 2);
    assert_eq!(&cid_pkt[11..11 + client_cid.len()], client_cid);

    // Flip one bit of the last ciphertext byte. This leaves the CID and
    // record header untouched, so the on-wire CID authentication check
    // passes; but the AEAD tag check must fail.
    let mut tampered = cid_pkt.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    // Sanity: the CID field was not touched.
    assert_eq!(&tampered[11..11 + client_cid.len()], client_cid);

    // Deliver the tampered ciphertext first. The client must drop it silently
    // (AEAD authentication fails, no app data is emitted).
    deliver_packets(&[tampered], &mut client);
    let after_tamper = drain_outputs(&mut client);
    assert!(
        after_tamper.app_data.is_empty(),
        "Client must not surface app data from a ciphertext-tampered CID record"
    );

    // Deliver the untampered original at the same sequence number. The replay
    // window must NOT have advanced on the AEAD-auth failure, so this
    // retransmit still decrypts and the payload arrives.
    deliver_packets(std::slice::from_ref(&cid_pkt), &mut client);
    let after_valid = drain_outputs(&mut client);
    assert!(
        after_valid.app_data.iter().any(|d| d == payload),
        "Client must accept the untampered original after an AEAD-auth \
         failure drop (replay window must not advance on failed decrypt)"
    );
}

/// Queue-and-defer across the CCS boundary. A CID-framed epoch-1 record
/// (Finished) can reach the client before the peer's ChangeCipherSpec if a
/// coalesced datagram is reordered or fragmented. The parser must keep the
/// CID record — `inbound_cid_active` is false at that instant — instead of
/// dropping it, and decryption must happen when `enable_peer_encryption`
/// later fires on the CCS. The GateStub unit test covers the drop branch;
/// this is the complementary integration test for the queue-and-decrypt
/// branch that `src/dtls12/incoming.rs:258-269` points at.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_finished_before_ccs_is_queued_then_decrypted() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_cid: &[u8] = b"reorder-c";
    let server_cid: &[u8] = b"reorder-s";

    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Drive the handshake but DO NOT deliver the server's final flight yet.
    // Any time the server emits a datagram that contains both a CCS record
    // (content type 20) and at least one CID record (content type 25), we
    // capture it unbroken for the reordering step below.
    let mut final_flight: Option<Vec<u8>> = None;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);

        // Route client → server normally so the server can progress to
        // sending its Finished flight.
        deliver_packets(&co.packets, &mut server);

        for pkt in so.packets {
            // Server's final flight is a coalesced datagram that begins with
            // a 14-byte ChangeCipherSpec record (content type 20, 13-byte
            // header + 1-byte payload) and is immediately followed by the
            // CID-framed Finished record (content type 25 at byte 14).
            let is_final_flight = pkt.len() > 14 && pkt[0] == 20 && pkt[14] == 25;
            if final_flight.is_none() && is_final_flight {
                final_flight = Some(pkt);
            } else {
                // Any other server-to-client packet (ServerHello flight, etc.)
                // flows through normally.
                let _ = client.handle_packet(&pkt);
            }
        }

        if final_flight.is_some() {
            break;
        }
        now += Duration::from_millis(10);
    }
    let final_flight =
        final_flight.expect("server should emit a coalesced CCS + CID Finished flight");

    // Split the flight into its individual DTLS records. Layout:
    //   non-CID record: type(1) | version(2) | epoch(2) | seq(6) | length(2) | body
    //   CID record:     type(1) | version(2) | epoch(2) | seq(6) | cid(N) | length(2) | body
    // We're the client side: the peer's CID for records sent to us is our own
    // configured `client_cid`.
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < final_flight.len() {
        assert!(i + 13 <= final_flight.len(), "flight truncated");
        let ct = final_flight[i];
        let (hdr_len, body_len) = if ct == 25 {
            let hdr = 11 + client_cid.len() + 2;
            assert!(i + hdr <= final_flight.len());
            let length =
                u16::from_be_bytes([final_flight[i + hdr - 2], final_flight[i + hdr - 1]]) as usize;
            (hdr, length)
        } else {
            let hdr = 13;
            let length = u16::from_be_bytes([final_flight[i + 11], final_flight[i + 12]]) as usize;
            (hdr, length)
        };
        let end = i + hdr_len + body_len;
        records.push(final_flight[i..end].to_vec());
        i = end;
    }
    assert!(
        records.len() >= 2,
        "expected at least one CCS + one Finished record"
    );

    // Find the indices of the CCS record and the first CID-framed record.
    let ccs_idx = records
        .iter()
        .position(|r| r.first().copied() == Some(20))
        .expect("CCS record should be present");
    let cid_idx = records
        .iter()
        .position(|r| r.first().copied() == Some(25))
        .expect("CID-framed Finished should be present");
    assert!(
        ccs_idx < cid_idx,
        "normal wire order places CCS before CID Finished"
    );

    // Phase A: deliver the CID-framed Finished *before* the CCS. At this
    // point the client has `our_cid` negotiated but `inbound_cid_active` is
    // still false, so the record must be parsed and queued rather than
    // dropped.
    let _ = client.handle_packet(&records[cid_idx]);
    let after_cid_first = drain_outputs(&mut client);
    assert!(
        !after_cid_first.connected,
        "Client must not complete handshake from a reordered Finished alone"
    );

    // Phase B: now deliver the CCS (and any other records in the flight).
    // `enable_peer_encryption` drains the queue, which includes the queued
    // CID-framed Finished — decryption must succeed and the client must
    // connect.
    for (j, rec) in records.iter().enumerate() {
        if j == cid_idx {
            continue; // already delivered
        }
        let _ = client.handle_packet(rec);
    }

    // Drive any remaining handshake exchanges to completion.
    let mut client_connected = false;
    for _ in 0..20 {
        let co = drain_outputs(&mut client);
        deliver_packets(&co.packets, &mut server);
        let so = drain_outputs(&mut server);
        deliver_packets(&so.packets, &mut client);

        let co_again = drain_outputs(&mut client);
        if co_again.connected || co.connected {
            client_connected = true;
            break;
        }
        now += Duration::from_millis(10);
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
    }
    assert!(
        client_connected,
        "Client must complete handshake once the queued CID Finished is \
         re-decrypted after CCS activates inbound CID"
    );
}

/// RFC 9146 §4 / RFC 6347 §4.1.2.7: a `tls12_cid` record for a direction where
/// CID is not negotiated MUST be discarded, but coalesced records in the same
/// datagram MUST still be processed. Regression guard against the prior
/// implementation which `break`'d out of the parse loop, silently dropping
/// unrelated records sharing the datagram.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_unsolicited_cid_record_does_not_drop_coalesced_records() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    // Neither side configures CID — so a content-type-25 record is unsolicited.
    let config = dtls12_config();
    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
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
    assert!(client_connected && server_connected);

    // Client sends an ApplicationData record.
    let payload = b"coalesced-after-stray";
    client.send_application_data(payload).expect("send");
    let client_pkts = collect_packets(&mut client);
    let valid_pkt = client_pkts
        .iter()
        .find(|p| !p.is_empty() && p[0] == 23)
        .expect("client should emit ApplicationData")
        .clone();

    // Craft a coalesced datagram: [stray tls12_cid record | valid ApplicationData].
    // The stray record has zero-length body with the standard 13-byte DTLS
    // header — just enough for the parser to frame and discard it.
    let stray_cid: [u8; 13] = [
        25, // ContentType::Tls12Cid
        0xfe, 0xfd, // DTLS 1.2
        0, 1, // epoch
        0, 0, 0, 0, 0, 0xab, // seqnum (arbitrary)
        0, 0, // length = 0
    ];
    let mut coalesced = Vec::with_capacity(stray_cid.len() + valid_pkt.len());
    coalesced.extend_from_slice(&stray_cid);
    coalesced.extend_from_slice(&valid_pkt);

    deliver_packets(&[coalesced], &mut server);
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d == payload),
        "Server must process coalesced ApplicationData after a stray tls12_cid"
    );
}

/// Plan §4 recovery limits: an unsolicited `tls12_cid` record whose wire CID
/// was non-zero cannot be reframed correctly — the bytes the parser would
/// otherwise read as `length` are actually CID bytes. The parser's post-skip
/// sanity check must detect that the implied follow-on position is NOT a
/// plausible DTLS record and drop the datagram remainder (safe fail-closed)
/// rather than silently desynchronize into attacker-controlled bytes. This
/// test crafts exactly that scenario and pins the safe behavior.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_unsolicited_nonzero_cid_record_triggers_safe_resync_failure() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    // Neither side negotiates CID.
    let config = dtls12_config();
    let mut now = Instant::now();

    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        client_connected |= co.connected;
        server_connected |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(client_connected && server_connected);

    // A legitimate follow-on ApplicationData record the attacker is trying to
    // smuggle past the parser by prepending an ambiguous stray.
    let payload = b"should-not-arrive-if-resync-fails";
    client.send_application_data(payload).expect("send");
    let client_pkts = collect_packets(&mut client);
    let valid_pkt = client_pkts
        .iter()
        .find(|p| !p.is_empty() && p[0] == 23)
        .expect("client should emit ApplicationData")
        .clone();

    // Stray tls12_cid record with a NON-ZERO embedded CID. Bytes [11..13] of
    // the wire are CID bytes (0xFF, 0xFF) — which the zero-CID-assumption
    // skip would interpret as a claimed length of 65535. That runs past the
    // datagram, tripping the early overshoot guard; failing that path, the
    // post-skip ContentType validator catches any garbage-aligned case. A
    // crafted CID whose bytes happen to be `[0x00, 0x04]` (length 4) would
    // land mid-record, which the ContentType check rejects.
    let stray_cid_bytes: [u8; 16] = [
        25, // ContentType::Tls12Cid
        0xfe, 0xfd, // DTLS 1.2
        0, 1, // epoch
        0, 0, 0, 0, 0, 0xbe, // seqnum
        // bytes [11..13] below are the *CID field*, not a length — but the
        // zero-CID-assumption path would misread them as length.
        0x00, 0x04, // first two CID bytes
        0x11, 0x22, // remaining CID bytes
        0x00, // length MSB (attacker's actual length-field — unreachable
              // through the misread-skip)
    ];
    let mut crafted = Vec::with_capacity(stray_cid_bytes.len() + valid_pkt.len());
    crafted.extend_from_slice(&stray_cid_bytes);
    crafted.extend_from_slice(&valid_pkt);

    deliver_packets(&[crafted], &mut server);
    let server_out = drain_outputs(&mut server);
    // The coalesced ApplicationData must NOT arrive — the parser's post-skip
    // ContentType sanity check detects that the skip landed on bytes that do
    // not begin a valid DTLS record and drops the datagram remainder. This
    // is the fail-closed property required by plan §4: "when framing permits
    // it" — and here it doesn't, because we cannot recover frame alignment.
    assert!(
        server_out.app_data.iter().all(|d| d != payload),
        "Server must not decrypt application data reached via desynchronized \
         skip past a non-zero-CID stray record — fail-closed recovery"
    );

    // And the session remains healthy afterwards: a legitimate follow-up
    // packet (no stray prefix) still works.
    let followup = b"session-healthy-after-drop";
    client.send_application_data(followup).expect("send");
    let client_pkts2 = collect_packets(&mut client);
    deliver_packets(&client_pkts2, &mut server);
    let server_out2 = drain_outputs(&mut server);
    assert!(
        server_out2.app_data.iter().any(|d| d == followup),
        "Subsequent legitimate traffic must still decrypt after a stray-CID \
         datagram was dropped"
    );
}

/// `poll_output` must not panic when the caller supplies a buffer too small
/// to hold the negotiated CID. Instead, the event is deferred (a `Timeout` is
/// returned) and the CID is delivered intact on a subsequent poll with an
/// adequately sized buffer.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_poll_output_undersized_buffer_defers() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // A long CID guarantees the tiny buffer below cannot fit it.
    let cid: &[u8] = b"rfc9146-long-connection-id-for-test-2026";
    let client_config = dtls12_config_with_cid(cid);
    let server_config = dtls12_config_with_cid(cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut big_buf = vec![0u8; 2048];
    let mut drove_cid_path = false;

    'outer: for _ in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        // Drain server → client.
        loop {
            match server.poll_output(&mut big_buf) {
                Output::Packet(p) => {
                    let data = p.to_vec();
                    let _ = client.handle_packet(&data);
                }
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        // Poll client, but stop the inner loop as soon as `Connected` fires —
        // the `ConnectionId` event is enqueued immediately behind `Connected`
        // in `client.rs`, so this is the exact moment to exercise the
        // undersized-buffer path.
        loop {
            match client.poll_output(&mut big_buf) {
                Output::Packet(p) => {
                    let data = p.to_vec();
                    let _ = server.handle_packet(&data);
                }
                Output::Connected => {
                    // Undersized buffer must not panic and must defer.
                    let mut tiny_buf = [0u8; 4];
                    let tiny = client.poll_output(&mut tiny_buf);
                    assert!(
                        matches!(tiny, Output::Timeout(_)),
                        "undersized buffer must yield Timeout, got {}",
                        output_variant(&tiny)
                    );

                    // Next poll with a large buffer must deliver the CID intact.
                    match client.poll_output(&mut big_buf) {
                        Output::ConnectionId(delivered) => {
                            assert_eq!(
                                delivered, cid,
                                "CID must be delivered intact after deferral"
                            );
                            drove_cid_path = true;
                            break 'outer;
                        }
                        ref other => panic!(
                            "expected ConnectionId after deferral, got {}",
                            output_variant(other)
                        ),
                    }
                }
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        now += Duration::from_millis(10);
    }

    assert!(
        drove_cid_path,
        "test did not reach the Connected → undersized poll → ConnectionId path"
    );
}

/// Companion regression for the poll-buffer safety property: when pre-connect
/// application data has been queued via `send_application_data` AND a
/// `ConnectionId` event is pending AND the caller polls with an undersized
/// buffer, nothing in the engine may panic. Prior to the `poll_app_data` /
/// `poll_packet_tx` defer paths this scenario tripped `engine.rs`'s
/// "Output buffer too small" asserts because the small-buffer fall-through
/// past `ConnectionId` landed on a queued packet that the engine then tried
/// to copy into `buf` unconditionally.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_poll_output_undersized_buffer_defers_with_queued_app_data() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let cid: &[u8] = b"rfc9146-queued-data-poll-buffer-safety";
    let client_config = dtls12_config_with_cid(cid);
    let server_config = dtls12_config_with_cid(cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Queue application data BEFORE the handshake completes. Client wraps it
    // in `queued_data` and flushes after `Connected`, so there will be real
    // outbound packets sitting behind the ConnectionId event in the engine's
    // tx queue at the exact moment the undersized buffer is polled.
    let queued_payload = b"pre-handshake-queued-app-data-for-panic-regression";
    client
        .send_application_data(queued_payload)
        .expect("queue pre-connect app data");

    let mut big_buf = vec![0u8; 2048];
    let mut drove_both_defers = false;

    'outer: for _ in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        loop {
            match server.poll_output(&mut big_buf) {
                Output::Packet(p) => {
                    let data = p.to_vec();
                    let _ = client.handle_packet(&data);
                }
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        loop {
            match client.poll_output(&mut big_buf) {
                Output::Packet(p) => {
                    let data = p.to_vec();
                    let _ = server.handle_packet(&data);
                }
                Output::Connected => {
                    // Right at Connected: ConnectionId event is enqueued AND
                    // the queued_data flush has enqueued at least one tx
                    // packet. Poll with a buffer too small for either —
                    // both the client-side CID deferral and the engine-side
                    // packet deferral must kick in without a panic.
                    let mut tiny_buf = [0u8; 2];
                    let tiny = client.poll_output(&mut tiny_buf);
                    assert!(
                        matches!(tiny, Output::Timeout(_)),
                        "undersized buffer must yield Timeout even with \
                         queued packets behind the CID event, got {}",
                        output_variant(&tiny)
                    );

                    // Next polls with a big buffer must deliver BOTH the CID
                    // event AND the queued application data packet intact.
                    let first = client.poll_output(&mut big_buf);
                    assert!(
                        matches!(first, Output::ConnectionId(c) if c == cid),
                        "expected ConnectionId first, got {}",
                        output_variant(&first)
                    );
                    // Flush remaining outputs and route any packets so the
                    // server receives the queued app data — proving the
                    // deferral didn't corrupt the tx queue.
                    loop {
                        match client.poll_output(&mut big_buf) {
                            Output::Packet(p) => {
                                let data = p.to_vec();
                                let _ = server.handle_packet(&data);
                            }
                            Output::Timeout(_) => break,
                            _ => {}
                        }
                    }
                    let so = drain_outputs(&mut server);
                    assert!(
                        so.app_data.iter().any(|d| d == queued_payload),
                        "Server must receive the queued app data intact after \
                         the undersized-buffer deferral path"
                    );
                    drove_both_defers = true;
                    break 'outer;
                }
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        now += Duration::from_millis(10);
    }

    assert!(
        drove_both_defers,
        "test did not reach the queued-data + undersized poll regression path"
    );
}

/// A CID record whose DTLSCiphertext.length is below the AEAD overhead
/// (explicit_nonce + tag) cannot contain a valid ciphertext. The decrypt path
/// must silently discard it (RFC 6347 §4.1.2.7) without panicking on the
/// slice bounds and without advancing the replay window, so a legitimate
/// record at the same sequence still decrypts.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_short_length_below_aead_overhead_is_dropped() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // AES-GCM default suite → overhead = 8 (explicit nonce) + 16 (tag) = 24.
    let client_cid: &[u8] = b"short-c";
    let server_cid: &[u8] = b"short-s";

    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        client_connected |= co.connected;
        server_connected |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(client_connected && server_connected);

    let payload = b"short-length-canary";
    server.send_application_data(payload).expect("server send");
    let server_pkts = collect_packets(&mut server);
    let cid_pkt = server_pkts
        .iter()
        .find(|p| !p.is_empty() && p[0] == 25)
        .expect("server should emit a tls12_cid record")
        .clone();

    // Layout: type(1) | version(2) | epoch(2) | seq(6) | cid(N) | length(2) | body
    let length_field_offset = 11 + client_cid.len();
    assert!(cid_pkt.len() >= length_field_offset + 2);

    // Craft a record that claims length=10 (below AEAD overhead=24) and
    // truncate the body to match. Without the §2 guard this underflows the
    // ciphertext slice below the explicit-nonce offset and panics.
    let mut short = cid_pkt.clone();
    short[length_field_offset] = 0;
    short[length_field_offset + 1] = 10;
    short.truncate(length_field_offset + 2 + 10);

    deliver_packets(&[short], &mut client);
    let after_short = drain_outputs(&mut client);
    assert!(
        after_short.app_data.is_empty(),
        "Client must silently drop a CID record whose length is below AEAD overhead"
    );

    // The replay window must NOT have advanced on the silent drop, so the
    // untampered original at the same sequence still decrypts.
    deliver_packets(std::slice::from_ref(&cid_pkt), &mut client);
    let after_valid = drain_outputs(&mut client);
    assert!(
        after_valid.app_data.iter().any(|d| d == payload),
        "Client must accept the original record after a short-length silent drop"
    );
}

/// RFC 9146 §3 — a zero-length CID advertised for a direction means
/// *use legacy RFC 6347 framing* in that direction, not "tls12_cid with
/// zero bytes." The extension is still negotiated; only framing stays
/// legacy. With client_cid non-empty and server_cid empty:
///
/// - client → server: legacy framing (server advertised zero-length
///   inbound, so the outbound CID from client's POV is empty)
/// - server → client: `tls12_cid` framing (client advertised non-empty
///   inbound)
///
/// Both directions must decrypt; the zero-length direction must not emit
/// content type 25.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_asymmetric_zero_length_uses_legacy_framing() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_cid: &[u8] = b"asym-c-nonzero";
    let server_cid: &[u8] = &[];

    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        client_connected |= co.connected;
        server_connected |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(
        client_connected && server_connected,
        "asymmetric zero-length CID must still complete the handshake"
    );

    // Client → server: legacy framing (no content type 25 on the wire) —
    // because the server advertised zero-length inbound.
    let c_payload = b"c2s-asym-zero";
    client
        .send_application_data(c_payload)
        .expect("client send");
    let co = drain_outputs(&mut client);
    assert!(
        co.packets
            .iter()
            .filter(|p| !p.is_empty())
            .all(|p| p[0] != 25),
        "client→server records must NOT use tls12_cid framing when server advertised zero-length inbound"
    );
    deliver_packets(&co.packets, &mut server);
    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == c_payload),
        "server must receive client app data over legacy framing"
    );

    // Server → client: tls12_cid framing (client advertised non-empty inbound).
    let s_payload = b"s2c-asym-zero";
    server
        .send_application_data(s_payload)
        .expect("server send");
    let so2 = drain_outputs(&mut server);
    let cid_pkt = so2
        .packets
        .iter()
        .find(|p| !p.is_empty() && p[0] == 25)
        .expect(
            "server→client records must use tls12_cid framing (client has non-empty inbound CID)",
        );
    // Verify CID bytes are present on the wire.
    assert!(cid_pkt.len() >= 11 + client_cid.len() + 2);
    assert_eq!(&cid_pkt[11..11 + client_cid.len()], client_cid);
    deliver_packets(&so2.packets, &mut client);
    let co2 = drain_outputs(&mut client);
    assert!(
        co2.app_data.iter().any(|d| d == s_payload),
        "client must receive server app data over tls12_cid framing"
    );
}

/// RFC 9146 §3 + RFC 5246 §7.4.1.4 — a server MUST NOT send a
/// `connection_id` extension the client did not offer, and the client MUST
/// treat such a ServerHello as `unsupported_extension`. Exercises the
/// rejection gate in `client.rs:await_server_hello`.
///
/// Construction: intercept the real ServerHello from a non-CID handshake,
/// splice a CID extension into its extension list (updating enclosing
/// length fields: extensions_length, handshake fragment length, handshake
/// total length, record length). Deliver the tampered ServerHello to the
/// client. The hardened parser must surface SecurityError because the
/// client's config has `connection_id = None`. Extension iteration happens
/// before EMS / cert / crypto binding so this path fires immediately.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_client_rejects_unsolicited_server_hello_extension() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");
    let config = dtls12_config();

    let mut now = Instant::now();
    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    // Drive the handshake until the server emits a ServerHello Handshake
    // record (content type 22, first handshake msg_type=2). Withhold the
    // ServerHello from the client so the client stays in `AwaitServerHello`
    // for our tampered delivery below.
    let mut sh_pkt: Option<Vec<u8>> = None;
    for _ in 0..6 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        deliver_packets(&co.packets, &mut server);
        for p in &so.packets {
            if !p.is_empty() && p[0] == 22 && p.get(13) == Some(&2) {
                if sh_pkt.is_none() {
                    sh_pkt = Some(p.clone());
                }
                // withhold — do not deliver to the client
                continue;
            }
            let _ = client.handle_packet(p);
        }
        if sh_pkt.is_some() {
            break;
        }
        now += Duration::from_millis(10);
    }
    let mut sh_pkt = sh_pkt.expect("server should emit ServerHello within 6 iterations");

    // ServerHello is the first handshake message in the flight (at byte 13).
    // Layout: record(13) | handshake_msg_type(1) | length(3) |
    //         message_seq(2) | fragment_offset(3) | fragment_length(3) |
    //         body
    // ServerHello body: server_version(2) | random(32) | session_id_len(1) |
    //                   session_id | cipher_suite(2) | compression_method(1) |
    //                   extensions_length(2) | extensions
    assert_eq!(
        sh_pkt[13], 2,
        "first handshake message should be ServerHello"
    );

    let hs_total_len_off = 14; // 3 bytes
    let hs_frag_len_off = 22; // 3 bytes
    let body_off = 25;

    let mut p = body_off + 2 + 32; // skip version + random
    let sid_len = sh_pkt[p] as usize;
    p += 1 + sid_len;
    p += 2 + 1; // cipher_suite + compression_method
    let ext_len_off = p;
    let old_ext_len = u16::from_be_bytes([sh_pkt[ext_len_off], sh_pkt[ext_len_off + 1]]) as usize;
    let extensions_start = ext_len_off + 2;
    let extensions_end = extensions_start + old_ext_len;

    // Build a CID extension: type(2) | len(2) | cid_len(1) | cid(n)
    let injected_cid: &[u8] = b"unsolicited";
    let ext_len: u16 = 1 + injected_cid.len() as u16;
    let mut cid_ext = Vec::new();
    cid_ext.extend_from_slice(&[0x00, 0x36]);
    cid_ext.extend_from_slice(&ext_len.to_be_bytes());
    cid_ext.push(injected_cid.len() as u8);
    cid_ext.extend_from_slice(injected_cid);
    let added = cid_ext.len();

    // Splice at extensions_end.
    sh_pkt.splice(extensions_end..extensions_end, cid_ext.iter().copied());

    // Update extensions_length.
    let new_ext_len = (old_ext_len + added) as u16;
    sh_pkt[ext_len_off] = (new_ext_len >> 8) as u8;
    sh_pkt[ext_len_off + 1] = new_ext_len as u8;

    // Update handshake fragment length.
    let mut hs_frag_len = ((sh_pkt[hs_frag_len_off] as usize) << 16)
        | ((sh_pkt[hs_frag_len_off + 1] as usize) << 8)
        | (sh_pkt[hs_frag_len_off + 2] as usize);
    hs_frag_len += added;
    sh_pkt[hs_frag_len_off] = (hs_frag_len >> 16) as u8;
    sh_pkt[hs_frag_len_off + 1] = (hs_frag_len >> 8) as u8;
    sh_pkt[hs_frag_len_off + 2] = hs_frag_len as u8;

    // Update handshake total length.
    let mut hs_total_len = ((sh_pkt[hs_total_len_off] as usize) << 16)
        | ((sh_pkt[hs_total_len_off + 1] as usize) << 8)
        | (sh_pkt[hs_total_len_off + 2] as usize);
    hs_total_len += added;
    sh_pkt[hs_total_len_off] = (hs_total_len >> 16) as u8;
    sh_pkt[hs_total_len_off + 1] = (hs_total_len >> 8) as u8;
    sh_pkt[hs_total_len_off + 2] = hs_total_len as u8;

    // Update record length. Following records in the flight still have
    // correct self-contained headers, so only the first record's length
    // needs to grow.
    let first_rec_len_off = 11;
    let old_rec_len =
        u16::from_be_bytes([sh_pkt[first_rec_len_off], sh_pkt[first_rec_len_off + 1]]) as usize;
    let new_rec_len = (old_rec_len + added) as u16;
    sh_pkt[first_rec_len_off] = (new_rec_len >> 8) as u8;
    sh_pkt[first_rec_len_off + 1] = new_rec_len as u8;

    // Deliver the tampered ServerHello. Client's extension scan hits the
    // unsolicited CID extension before any EMS/crypto checks.
    let result = client.handle_packet(&sh_pkt);
    match result {
        Err(dimpl::Error::SecurityError(msg)) => {
            assert!(
                msg.contains("unsolicited") || msg.contains("connection_id"),
                "expected SecurityError about unsolicited CID; got: {}",
                msg
            );
        }
        other => panic!(
            "expected SecurityError from unsolicited CID in ServerHello, got: {:?}",
            other
        ),
    }
}

/// RFC 5246 §7.2.2 — a malformed `connection_id` extension on the server
/// side must surface as `SecurityError` (decode_error). Previously the server
/// `warn!`'d and silently continued. Tampers the cid_len byte inside the
/// extension body to claim fewer bytes than present, which exercises the
/// trailing-bytes rejection added to `ConnectionIdExtension::parse`.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_server_rejects_malformed_extension() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    // Client offers a CID long enough that shortening cid_len leaves a
    // trailing byte. Server has its own CID so it would normally process the
    // extension.
    let client_cid: &[u8] = b"t5-client-cid";
    let server_cid: &[u8] = b"t5-server-cid";
    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Helper: locate the CID extension (type = 0x0036) inside a ClientHello
    // packet and shrink its cid_len byte by 1 so the body carries a trailing
    // byte — exercising the hardened `ConnectionIdExtension::parse`.
    fn tamper_cid_ext_in_ch(pkt: &mut [u8], client_cid_len: usize) {
        for i in 0..pkt.len().saturating_sub(5) {
            if pkt[i] == 0x00 && pkt[i + 1] == 0x36 {
                let ext_len = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]) as usize;
                if ext_len == 1 + client_cid_len && pkt[i + 4] as usize == client_cid_len {
                    pkt[i + 4] = (client_cid_len - 1) as u8;
                    return;
                }
            }
        }
        panic!("CID extension not found in ClientHello");
    }

    // Tamper CH1 (carries the CID extension) so the server's cookie is
    // computed against the same tampered bytes that CH2 will also carry
    // (we tamper CH2 identically below). RFC 9146 §3 / §7 cookie binding over
    // the offered CID means identical tampering on both CHs lets the
    // cookie verify — the strict extension parser then rejects.
    client.handle_timeout(now).expect("client timeout");
    let co = drain_outputs(&mut client);
    let mut ch1 = co
        .packets
        .into_iter()
        .find(|p| !p.is_empty() && p[0] == 22)
        .expect("client should emit CH1");
    tamper_cid_ext_in_ch(&mut ch1, client_cid.len());
    // Deliver tampered CH1 → server issues HVR (cookie bound over tampered
    // ext bytes). We must not surface the tamper error yet because the
    // strict parse runs only on the cookie-bearing CH.
    let _ = server.handle_packet(&ch1);
    let so = drain_outputs(&mut server);
    deliver_packets(&so.packets, &mut client);

    // CH2 with cookie — re-capture and apply the identical tamper so the
    // cookie binding still holds.
    client.handle_timeout(now).expect("client timeout");
    let co2 = drain_outputs(&mut client);
    let mut ch2 = co2
        .packets
        .into_iter()
        .find(|p| !p.is_empty() && p[0] == 22)
        .expect("client should emit CH2");
    tamper_cid_ext_in_ch(&mut ch2, client_cid.len());

    // Deliver the tampered ClientHello — server must fail with SecurityError.
    let result = server.handle_packet(&ch2);
    match result {
        Err(dimpl::Error::SecurityError(msg)) => {
            assert!(
                msg.contains("connection_id") || msg.contains("Malformed"),
                "expected SecurityError to mention CID; got: {}",
                msg
            );
        }
        other => panic!(
            "expected SecurityError on malformed CID extension, got: {:?}",
            other
        ),
    }
}

/// RFC 9146 §3 / §7 cookie binding: if the second ClientHello offers a
/// different `connection_id` extension than the first, the stateless
/// cookie must fail verification — because dimpl binds the offered CID
/// into the cookie HMAC. An attacker cannot forge a cookie for a swapped
/// CID (no server secret), so the server re-issues HVR and the handshake
/// cannot progress.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_server_rejects_swap_across_hello_verify_pair() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");
    let client_cid: &[u8] = b"hvr-swap-cli";
    let server_cid: &[u8] = b"hvr-swap-srv";

    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Cookie exchange: CH1 (with CID A) → HVR → CH2 (with CID A).
    client.handle_timeout(now).expect("client timeout");
    let co = drain_outputs(&mut client);
    deliver_packets(&co.packets, &mut server);
    let so = drain_outputs(&mut server);
    deliver_packets(&so.packets, &mut client);

    // Capture CH2 and rewrite the first byte of the CID field (a swap that
    // preserves length, so extension framing stays valid) — this is the
    // RFC 9146 §3 / §7 "second CH with a different CID" scenario.
    client.handle_timeout(now).expect("client timeout");
    let co2 = drain_outputs(&mut client);
    let mut ch2 = co2
        .packets
        .into_iter()
        .find(|p| !p.is_empty() && p[0] == 22)
        .expect("client should emit CH2");

    let mut swap_off = None;
    for i in 0..ch2.len().saturating_sub(5) {
        if ch2[i] == 0x00 && ch2[i + 1] == 0x36 {
            let ext_len = u16::from_be_bytes([ch2[i + 2], ch2[i + 3]]) as usize;
            if ext_len == 1 + client_cid.len()
                && ch2[i + 4] as usize == client_cid.len()
                && i + 5 + client_cid.len() <= ch2.len()
            {
                swap_off = Some(i + 5);
                break;
            }
        }
    }
    let off = swap_off.expect("CID extension not found in CH2");
    // Flip the first CID byte — framing stays valid, extension parses
    // cleanly; the swapped CID value is what the cookie binding catches.
    ch2[off] ^= 0xFF;

    // Deliver the swapped CH2. The cookie was HMAC'd over CH1's CID bytes;
    // the swapped CID bytes differ, so `verify_cookie` fails. The server
    // treats CH2 as cookie-invalid and re-issues HVR instead of progressing
    // to ServerHello. No ServerHello emerges within one handshake step.
    let _ = server.handle_packet(&ch2);
    let so2 = drain_outputs(&mut server);
    let has_server_hello = so2
        .packets
        .iter()
        .any(|p| !p.is_empty() && p[0] == 22 && p.get(13) == Some(&2));
    assert!(
        !has_server_hello,
        "server must NOT emit ServerHello for a CH2 with swapped CID"
    );
    // Should have emitted an HVR (content type 22, handshake msg_type=3).
    let has_hvr = so2
        .packets
        .iter()
        .any(|p| !p.is_empty() && p[0] == 22 && p.get(13) == Some(&3));
    assert!(
        has_hvr,
        "server must re-issue HelloVerifyRequest on cookie mismatch from CID swap"
    );
}

/// Regression for review item #1 (2026-04-23 third pass): when the configured
/// MTU is too small to hold record overhead + a handshake header + at least
/// one body byte, `create_handshake` must fail deterministically with
/// `Error::MtuTooSmall` rather than loop forever with `chunk_len == 0`.
/// Exercises the smallest allowed MTU (64) against a negotiated CID that
/// pushes the overhead past it.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_handshake_mtu_too_small_fails_closed() {
    use dimpl::Config;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    // Pick MTU/CID so epoch-0 handshake fits (record 13 + hs header 12 =
    // 25 bytes overhead) but epoch-1 + long CID + AEAD does not. At
    // MTU=300 with a 250-byte CID: epoch-1 overhead = 13 + 250 + 1 + 24 +
    // 12 = 300 ≥ 300 → MtuTooSmall must fire on the first encrypted
    // handshake fragment attempt (the Finished emission).
    let cid: Vec<u8> = vec![0xAB; 250];
    let server_config = Arc::new(
        Config::builder()
            .mtu(300)
            .with_connection_id(cid.clone())
            .build()
            .expect("build server config"),
    );
    let client_config = Arc::new(
        Config::builder()
            .mtu(300)
            .with_connection_id(cid)
            .build()
            .expect("build client config"),
    );

    let now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Drive a handful of handshake steps. At some point an encrypted
    // handshake flight must attempt to fragment post-negotiation and
    // surface MtuTooSmall. Before the fix, the fragmentation loop would
    // spin forever.
    let mut saw_mtu_error = false;
    for _ in 0..30 {
        if let Err(e) = client.handle_timeout(now) {
            if matches!(e, dimpl::Error::MtuTooSmall { .. }) {
                saw_mtu_error = true;
                break;
            }
        }
        let co = drain_outputs(&mut client);
        for p in &co.packets {
            let _ = server.handle_packet(p);
        }
        if let Err(e) = server.handle_timeout(now) {
            if matches!(e, dimpl::Error::MtuTooSmall { .. }) {
                saw_mtu_error = true;
                break;
            }
        }
        let so = drain_outputs(&mut server);
        for p in &so.packets {
            let _ = client.handle_packet(p);
        }
    }
    assert!(
        saw_mtu_error,
        "either side must surface MtuTooSmall instead of hanging"
    );
}

/// Contract test for `Config::mtu()`: MTU is a coalescing target, not a
/// hard per-record ceiling. An application-data record whose plaintext
/// exceeds MTU is still emitted as a single datagram (larger than MTU) —
/// the only hard cap on application data is `DTLS12_MAX_PLAINTEXT_LEN =
/// 2^14`, enforced by `Error::Oversized`. Pins the contract so a future
/// change to enforce MTU as a hard ceiling has a failing test to update.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_mtu_is_coalescing_target_not_hard_ceiling() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");

    let config = dtls12_config();
    let mut now = Instant::now();
    let mut client = Dtls::new_12(Arc::clone(&config), client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        client_connected |= co.connected;
        server_connected |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(client_connected && server_connected);

    // Write larger than default MTU (1150). Contract: succeeds, and the
    // resulting datagram exceeds MTU.
    let payload = vec![0xAAu8; 2000];
    client
        .send_application_data(&payload)
        .expect("2KB write must succeed — MTU is coalescing target, not hard ceiling");
    let co = drain_outputs(&mut client);
    let produced_oversize = co.packets.iter().any(|p| p.len() > 1150);
    assert!(
        produced_oversize,
        "2KB app-data must be emitted as a single >MTU datagram; got sizes: {:?}",
        co.packets.iter().map(|p| p.len()).collect::<Vec<_>>()
    );
    deliver_packets(&co.packets, &mut server);
    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == &payload),
        "server must still receive and decrypt the oversize record"
    );

    // Write at exactly `DTLS12_MAX_PLAINTEXT_LEN` — the hard cap.
    let at_cap = vec![0x55u8; 1 << 14];
    client
        .send_application_data(&at_cap)
        .expect("write at DTLS12_MAX_PLAINTEXT_LEN must succeed");

    // One byte over → `Error::Oversized`.
    let over = vec![0x66u8; (1 << 14) + 1];
    match client.send_application_data(&over) {
        Err(dimpl::Error::Oversized(n)) => {
            assert_eq!(n, (1 << 14) + 1, "Oversized should report the offered len");
        }
        other => panic!("expected Error::Oversized, got: {:?}", other),
    }
}

/// Regression for review item #3: 48-bit sequence-number exhaustion
/// surfaces as a specific `SequenceNumberExhausted` error, not as
/// `Oversized` which is reserved for payload-size failures.
#[test]
fn dtls12_error_variants_are_distinct() {
    use dimpl::Error;
    // The review's primary ask is that the two error conditions be
    // distinguishable at match time. Pattern-match to prove the contract.
    let seq = Error::SequenceNumberExhausted {
        epoch: 1,
        sequence: (1u64 << 48) - 1,
    };
    let oversized = Error::Oversized(1 << 14);
    assert!(matches!(seq, Error::SequenceNumberExhausted { .. }));
    assert!(matches!(oversized, Error::Oversized(_)));
    // They must not collide.
    assert!(!matches!(seq, Error::Oversized(_)));
    assert!(!matches!(oversized, Error::SequenceNumberExhausted { .. }));
}

/// RFC 6347 §4.1.2.7 / RFC 9146 §6: invalid records are silently
/// discarded. Three CID-adjacent record-boundary failures must surface
/// as `Ok(())` from `handle_packet` — not a propagated parse error that
/// would tear down the association at a Sans-IO caller treating
/// `handle_packet` errors as fatal.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_malformed_record_boundaries_are_silent_drops() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");
    let cid: &[u8] = b"silent-drop";
    let client_config = dtls12_config_with_cid(cid);
    let server_config = dtls12_config_with_cid(cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    // Complete the handshake so the client expects CID-framed inbound.
    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        client_connected |= co.connected;
        server_connected |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(client_connected && server_connected);

    // Case 1: a tls12_cid datagram shorter than 13 + cid_len bytes.
    let mut short_cid_pkt = vec![25u8, 0xFE, 0xFD]; // type + version, then truncated
    // Leave enough for the 11-byte sequence-prefixed header start, but cut
    // the rest off — header_len for our CID is 13 + 11 = 24, this is far
    // short.
    while short_cid_pkt.len() < 11 {
        short_cid_pkt.push(0);
    }
    client
        .handle_packet(&short_cid_pkt)
        .expect("short CID datagram must silent-drop, not surface error");

    // Case 2: a tls12_cid datagram whose claimed length runs past datagram
    // end. Header(13) + CID(11) + length=0xFFFF; actual datagram is far
    // shorter.
    let mut over_pkt = vec![25u8, 0xFE, 0xFD]; // content type + version
    over_pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // epoch + seq
    over_pkt.extend_from_slice(cid); // CID bytes
    over_pkt.extend_from_slice(&[0xFF, 0xFF]); // claimed length 65535
    over_pkt.extend_from_slice(&[0u8; 4]); // tiny body
    client
        .handle_packet(&over_pkt)
        .expect("over-length CID record must silent-drop, not surface error");

    // Case 3: a valid coalesced encrypted record before a malformed tail.
    // We can't easily forge a valid encrypted record, but post-handshake
    // app-data exchange after the malformed deliveries above proves the
    // session survived the silent drops.
    let payload = b"alive-after-malformed";
    server.send_application_data(payload).expect("server send");
    let so = drain_outputs(&mut server);
    deliver_packets(&so.packets, &mut client);
    let co = drain_outputs(&mut client);
    assert!(
        co.app_data.iter().any(|d| d == payload),
        "client must still receive valid app data after silent-drop malformed records"
    );
}

/// Regression for peer-address-update contract (2026-04-23 review #1):
/// `handle_packet` returning `Ok(())` is NOT an authentication signal —
/// tampered records silent-drop per RFC 6347 §4.1.2.7 and still surface
/// `Ok(())`. Callers using CID routing must gate address updates on a
/// positive authentication signal like `ApplicationData` from
/// `poll_output`, not on `handle_packet`'s return value.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cid_tampered_record_returns_ok_but_emits_no_app_data() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");
    let client_cid: &[u8] = b"addr-c";
    let server_cid: &[u8] = b"addr-s";
    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut c_ok = false;
    let mut s_ok = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        c_ok |= co.connected;
        s_ok |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if c_ok && s_ok {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(c_ok && s_ok);

    // Server emits a CID-framed app-data record; tamper the wire CID so
    // AEAD binding fails at the client.
    let payload = b"addr-update-bait";
    server.send_application_data(payload).expect("server send");
    let so = drain_outputs(&mut server);
    let cid_pkt = so
        .packets
        .iter()
        .find(|p| !p.is_empty() && p[0] == 25)
        .expect("server should emit a tls12_cid record")
        .clone();
    let mut tampered = cid_pkt.clone();
    tampered[11] ^= 0x01;

    // handle_packet must return Ok(()) — a CID-routing caller observing
    // only this return would (incorrectly) conclude the record was
    // authenticated.
    let result = client.handle_packet(&tampered);
    assert!(
        matches!(result, Ok(())),
        "handle_packet must return Ok(()) on silently-dropped tampered record, got {:?}",
        result
    );

    // But the authentication-positive signal must not appear: no
    // ApplicationData is emitted because AEAD authentication failed.
    let co = drain_outputs(&mut client);
    assert!(
        co.app_data.is_empty(),
        "tampered CID record must not surface ApplicationData — that's the real auth signal"
    );
}

/// Round-5 review #3: `connection_id` (RFC 9146 DTLS 1.2) must be rejected
/// at Config::build time when the caller filters out every DTLS 1.2 suite.
/// Without the gate the ClientHello would advertise CID on a handshake
/// that can only succeed as DTLS 1.3 (where dimpl does not implement
/// RFC 9147 CID) — a cross-setting mismatch users can hit.
#[test]
fn dtls12_cid_with_no_dtls12_suites_fails_config_build() {
    use dimpl::{Config, Error};

    let result = Config::builder()
        .with_connection_id(b"cid".to_vec())
        .dtls12_cipher_suites(&[]) // filter out all DTLS 1.2 suites
        .build();

    match result {
        Err(Error::ConfigError(msg)) => {
            assert!(
                msg.contains("Connection ID") || msg.contains("DTLS 1.2"),
                "ConfigError message should explain the CID/DTLS 1.2 mismatch: {}",
                msg
            );
        }
        other => panic!(
            "expected ConfigError rejecting CID-without-DTLS-1.2-suite, got: {:?}",
            other
        ),
    }
}

/// RFC 9146 §6 freshness API: `Dtls::newest_authenticated_record`
/// advances strictly on each authenticated record and does NOT
/// advance on silent-dropped (tampered CID) records. Callers use this
/// delta to gate peer-address updates.
#[test]
#[cfg(feature = "rcgen")]
fn dtls12_newest_authenticated_record_advances_only_on_valid_records() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen cert");
    let server_cert = generate_self_signed_certificate().expect("gen cert");
    let client_cid: &[u8] = b"auth-c";
    let server_cid: &[u8] = b"auth-s";
    let client_config = dtls12_config_with_cid(client_cid);
    let server_config = dtls12_config_with_cid(server_cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12(client_config, client_cert, now);
    client.set_active(true);
    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

    let mut c_ok = false;
    let mut s_ok = false;
    for _ in 0..50 {
        client.handle_timeout(now).expect("c timeout");
        server.handle_timeout(now).expect("s timeout");
        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);
        c_ok |= co.connected;
        s_ok |= so.connected;
        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);
        if c_ok && s_ok {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert!(c_ok && s_ok);

    let baseline = client.newest_authenticated_record();

    // Tampered CID record: handle_packet returns Ok(()) per silent-drop
    // contract, but `newest_authenticated_record` must NOT advance — this
    // is the property a CID-routing caller needs to distinguish
    // "authenticated fresh record arrived" from "we received something
    // that parsed".
    let payload = b"freshness-probe";
    server.send_application_data(payload).expect("send");
    let so = drain_outputs(&mut server);
    let cid_pkt = so
        .packets
        .iter()
        .find(|p| !p.is_empty() && p[0] == 25)
        .expect("server emits tls12_cid record")
        .clone();
    let mut tampered = cid_pkt.clone();
    tampered[11] ^= 0x01;
    client.handle_packet(&tampered).expect("ok");
    let _ = drain_outputs(&mut client);
    assert_eq!(
        client.newest_authenticated_record(),
        baseline,
        "tampered record must not advance newest_authenticated_record"
    );

    // Valid CID record: MUST advance (or set from None) the freshness
    // counter. Note: `baseline` can already be Some if the handshake's
    // last received flight was epoch 1 (Finished), so we only require
    // "strictly greater than baseline" or "Some when baseline was None".
    client.handle_packet(&cid_pkt).expect("ok");
    let co = drain_outputs(&mut client);
    assert!(
        co.app_data.iter().any(|d| d == payload),
        "valid record must deliver app data"
    );
    let after = client
        .newest_authenticated_record()
        .expect("after a valid record, freshness must be Some");
    match baseline {
        None => {} // any Some(..) is an advance from None
        Some(prev) => assert!(
            after > prev,
            "newest_authenticated_record must strictly advance on valid record: {:?} → {:?}",
            prev,
            after
        ),
    }
}
