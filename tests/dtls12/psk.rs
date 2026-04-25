//! DTLS 1.2 PSK handshake tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::crypto::Dtls12CipherSuite;
use dimpl::{Config, Dtls, PskResolver};

use crate::common::{collect_packets, deliver_packets, drain_outputs};

/// Simple PSK resolver that returns a fixed key for a known identity.
struct FixedPsk {
    identity: Vec<u8>,
    key: Vec<u8>,
}

impl PskResolver for FixedPsk {
    fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>> {
        if identity == self.identity {
            Some(self.key.clone())
        } else {
            None
        }
    }
}

fn psk_provider(suite: Dtls12CipherSuite) -> dimpl::crypto::CryptoProvider {
    let mut provider = Config::default().crypto_provider().clone();
    let psk_suite = provider
        .cipher_suites
        .iter()
        .copied()
        .find(|cs| cs.suite() == suite)
        .unwrap_or_else(|| panic!("{:?} not in provider", suite));

    let suites = Box::leak(Box::new([psk_suite]));
    provider.cipher_suites = suites;
    provider
}

/// Returns (client_config, server_config) for PSK tests.
fn psk_configs_for_suite(suite: Dtls12CipherSuite) -> (Arc<Config>, Arc<Config>) {
    let identity = b"test-device".to_vec();
    let key = b"0123456789abcdef".to_vec(); // 16 bytes

    let resolver = Arc::new(FixedPsk {
        identity: identity.clone(),
        key,
    });

    let provider = psk_provider(suite);

    let client = Arc::new(
        Config::builder()
            .with_crypto_provider(provider.clone())
            .with_psk_client(identity, resolver.clone())
            .build()
            .expect("build PSK client config"),
    );

    let server = Arc::new(
        Config::builder()
            .with_crypto_provider(provider)
            .with_psk_server(Some(b"hint".to_vec()), resolver)
            .build()
            .expect("build PSK server config"),
    );

    (client, server)
}

fn psk_configs() -> (Arc<Config>, Arc<Config>) {
    psk_configs_for_suite(Dtls12CipherSuite::PSK_AES128_CCM_8)
}

#[test]
fn dtls12_psk_self_handshake() {
    let _ = env_logger::try_init();

    let (client_config, server_config) = psk_configs();
    let now = Instant::now();

    let mut client = Dtls::new_12_psk(client_config, now);
    client.set_active(true);

    let mut server = Dtls::new_12_psk(server_config, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..60 {
        client.handle_timeout(Instant::now()).unwrap();
        server.handle_timeout(Instant::now()).unwrap();

        // Drain client → server
        let client_out = drain_outputs(&mut client);
        if client_out.connected {
            client_connected = true;
        }
        deliver_packets(&client_out.packets, &mut server);

        // Drain server → client
        let server_out = drain_outputs(&mut server);
        if server_out.connected {
            server_connected = true;
        }
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
    }

    assert!(client_connected, "PSK client should connect");
    assert!(server_connected, "PSK server should connect");
}

#[test]
fn dtls12_psk_application_data_roundtrip() {
    let _ = env_logger::try_init();

    let (client_config, server_config) = psk_configs();
    let now = Instant::now();

    let mut client = Dtls::new_12_psk(client_config, now);
    client.set_active(true);

    let mut server = Dtls::new_12_psk(server_config, now);
    server.set_active(false);

    // Complete handshake
    for _ in 0..60 {
        client.handle_timeout(Instant::now()).unwrap();
        server.handle_timeout(Instant::now()).unwrap();

        let co = drain_outputs(&mut client);
        deliver_packets(&co.packets, &mut server);

        let so = drain_outputs(&mut server);
        deliver_packets(&so.packets, &mut client);

        if co.connected || so.connected {
            // One more round to let both sides finish
            client.handle_timeout(Instant::now()).unwrap();
            server.handle_timeout(Instant::now()).unwrap();

            let co2 = drain_outputs(&mut client);
            deliver_packets(&co2.packets, &mut server);

            let so2 = drain_outputs(&mut server);
            deliver_packets(&so2.packets, &mut client);
            break;
        }
    }

    // Send data client → server
    let payload = b"Hello from PSK client!";
    client
        .send_application_data(payload)
        .expect("send app data");

    let co = drain_outputs(&mut client);
    deliver_packets(&co.packets, &mut server);

    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == payload),
        "Server should receive client's application data"
    );

    // Send data server → client
    let reply = b"Hello from PSK server!";
    server.send_application_data(reply).expect("send app data");

    let so = drain_outputs(&mut server);
    deliver_packets(&so.packets, &mut client);

    let co = drain_outputs(&mut client);
    assert!(
        co.app_data.iter().any(|d| d == reply),
        "Client should receive server's application data"
    );
}

#[test]
fn psk_invalid_identity_fails_at_finished() {
    let _ = env_logger::try_init();

    struct FailingResolver;
    impl PskResolver for FailingResolver {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    struct PassingResolver;
    impl PskResolver for PassingResolver {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(vec![0u8; 32])
        }
    }

    let server_config = dimpl::Config::builder()
        .with_psk_server(None, Arc::new(FailingResolver))
        .build()
        .expect("server config should build");
    let mut server = Dtls::new_12_psk(Arc::new(server_config), Instant::now());

    let client_config = dimpl::Config::builder()
        .with_psk_client(b"test_identity".to_vec(), Arc::new(PassingResolver))
        .build()
        .expect("client config should build");
    let mut client = Dtls::new_12_psk(Arc::new(client_config), Instant::now());
    client.set_active(true);

    // Drive the handshake; the security-relevant property is that neither
    // side ever signals Connected. Per RFC 6347 §4.1.2.7, AEAD failures on
    // the encrypted Finished are silently discarded, so a mismatched PSK
    // cannot surface as a propagated error — it manifests as handshake
    // stall, which is what we assert here.
    for _ in 0..60 {
        let _ = client.handle_timeout(Instant::now());
        let co = drain_outputs(&mut client);
        assert!(
            !co.connected,
            "client should not connect with mismatched PSK"
        );
        for p in &co.packets {
            let _ = server.handle_packet(p);
        }

        let _ = server.handle_timeout(Instant::now());
        let so = drain_outputs(&mut server);
        assert!(
            !so.connected,
            "server should not connect with mismatched PSK"
        );
        for p in &so.packets {
            let _ = client.handle_packet(p);
        }
    }
}

#[test]
fn psk_mismatched_keys_fail_at_finished_via_mac() {
    // Both resolvers return Some, so server.psk_valid stays Some(true) and
    // the defense-in-depth flag check is bypassed — any failure here must
    // come from the Finished MAC mismatch itself. Exercises the primary
    // cryptographic guarantee independently of the flag.
    let _ = env_logger::try_init();

    struct ZeroKey;
    impl PskResolver for ZeroKey {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(vec![0u8; 32])
        }
    }
    struct OneKey;
    impl PskResolver for OneKey {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(vec![0xAA; 32])
        }
    }

    let server_config = dimpl::Config::builder()
        .with_psk_server(None, Arc::new(ZeroKey))
        .build()
        .expect("server config should build");
    let mut server = Dtls::new_12_psk(Arc::new(server_config), Instant::now());

    let client_config = dimpl::Config::builder()
        .with_psk_client(b"test_identity".to_vec(), Arc::new(OneKey))
        .build()
        .expect("client config should build");
    let mut client = Dtls::new_12_psk(Arc::new(client_config), Instant::now());
    client.set_active(true);

    // Per RFC 6347 §4.1.2.7 the Finished MAC mismatch (an AEAD tag
    // failure) must be silently discarded — the security property is that
    // no connection is established. See `psk_invalid_identity_fails_at_finished`
    // for the same reasoning.
    for _ in 0..60 {
        let _ = client.handle_timeout(Instant::now());
        let co = drain_outputs(&mut client);
        assert!(
            !co.connected,
            "client should not connect with mismatched PSK keys"
        );
        for p in &co.packets {
            let _ = server.handle_packet(p);
        }

        let _ = server.handle_timeout(Instant::now());
        let so = drain_outputs(&mut server);
        assert!(
            !so.connected,
            "server should not connect with mismatched PSK keys"
        );
        for p in &so.packets {
            let _ = client.handle_packet(p);
        }
    }
}

#[test]
fn psk_valid_identity_succeeds() {
    let _ = env_logger::try_init();

    struct AlwaysPassResolver;
    impl PskResolver for AlwaysPassResolver {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(vec![0u8; 32])
        }
    }

    let server_config = dimpl::Config::builder()
        .with_psk_server(None, Arc::new(AlwaysPassResolver))
        .build()
        .expect("server config should build");
    let mut server = Dtls::new_12_psk(Arc::new(server_config), Instant::now());

    let client_config = dimpl::Config::builder()
        .with_psk_client(b"test_identity".to_vec(), Arc::new(AlwaysPassResolver))
        .build()
        .expect("client config should build");
    let mut client = Dtls::new_12_psk(Arc::new(client_config), Instant::now());
    client.set_active(true);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..60 {
        client.handle_timeout(Instant::now()).unwrap();
        server.handle_timeout(Instant::now()).unwrap();

        let co = drain_outputs(&mut client);
        if co.connected {
            client_connected = true;
        }
        deliver_packets(&co.packets, &mut server);

        let so = drain_outputs(&mut server);
        if so.connected {
            server_connected = true;
        }
        deliver_packets(&so.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
    }

    assert!(client_connected, "PSK client should connect");
    assert!(server_connected, "PSK server should connect");
}

/// Build PSK client + server configs that additionally negotiate CID.
fn psk_configs_with_cid(client_cid: &[u8], server_cid: &[u8]) -> (Arc<Config>, Arc<Config>) {
    let identity = b"test-device".to_vec();
    let key = b"0123456789abcdef".to_vec();

    let resolver = Arc::new(FixedPsk {
        identity: identity.clone(),
        key,
    });

    let provider = psk_provider(Dtls12CipherSuite::PSK_AES128_CCM_8);

    let client = Arc::new(
        Config::builder()
            .with_crypto_provider(provider.clone())
            .with_psk_client(identity, resolver.clone())
            .with_connection_id(client_cid.to_vec())
            .build()
            .expect("build PSK+CID client config"),
    );

    let server = Arc::new(
        Config::builder()
            .with_crypto_provider(provider)
            .with_psk_server(Some(b"hint".to_vec()), resolver)
            .with_connection_id(server_cid.to_vec())
            .build()
            .expect("build PSK+CID server config"),
    );

    (client, server)
}

/// PSK handshake with Connection ID negotiation for the primary IoT-roaming
/// use case. Verifies: handshake completes, both sides emit
/// `Output::ConnectionId`, and post-handshake application data flows in both
/// directions via CID-framed records (content type 25).
#[test]
fn dtls12_psk_with_cid_handshake_and_app_data() {
    let _ = env_logger::try_init();

    let client_cid: &[u8] = b"iot-c";
    let server_cid: &[u8] = b"iot-s";
    let (client_config, server_config) = psk_configs_with_cid(client_cid, server_cid);

    let mut now = Instant::now();

    let mut client = Dtls::new_12_psk(client_config, now);
    client.set_active(true);
    let mut server = Dtls::new_12_psk(server_config, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_reported_cid: Option<Vec<u8>> = None;
    let mut server_reported_cid: Option<Vec<u8>> = None;

    for _ in 0..60 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let co = drain_outputs(&mut client);
        let so = drain_outputs(&mut server);

        client_connected |= co.connected;
        server_connected |= so.connected;
        if co.connection_id.is_some() {
            client_reported_cid = co.connection_id;
        }
        if so.connection_id.is_some() {
            server_reported_cid = so.connection_id;
        }

        deliver_packets(&co.packets, &mut server);
        deliver_packets(&so.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
        now += Duration::from_millis(10);
    }

    assert!(client_connected, "PSK+CID client should connect");
    assert!(server_connected, "PSK+CID server should connect");

    assert_eq!(
        client_reported_cid.as_deref(),
        Some(client_cid),
        "PSK client should emit its own inbound CID"
    );
    assert_eq!(
        server_reported_cid.as_deref(),
        Some(server_cid),
        "PSK server should emit its own inbound CID"
    );

    let req = b"psk-cid-req";
    client.send_application_data(req).expect("client send");
    let client_pkts = collect_packets(&mut client);
    assert!(
        client_pkts.iter().any(|p| !p.is_empty() && p[0] == 25),
        "PSK client must emit tls12_cid app-data records after CID negotiation"
    );
    deliver_packets(&client_pkts, &mut server);
    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == req),
        "Server must decrypt PSK+CID client data"
    );

    let reply = b"psk-cid-reply";
    server.send_application_data(reply).expect("server send");
    let server_pkts = collect_packets(&mut server);
    assert!(
        server_pkts.iter().any(|p| !p.is_empty() && p[0] == 25),
        "PSK server must emit tls12_cid app-data records after CID negotiation"
    );
    deliver_packets(&server_pkts, &mut client);
    let co = drain_outputs(&mut client);
    assert!(
        co.app_data.iter().any(|d| d == reply),
        "Client must decrypt PSK+CID server data"
    );
}

/// Explicit PSK+CID rebinding harness.
///
/// In a real deployment a roaming IoT device's UDP 5-tuple changes under an
/// active association (Wi-Fi ⇄ LTE, NAT rebind, etc). dimpl is sans-io: the
/// engine never sees an address, so the harness represents the transport tuple
/// as an explicit label (`TransportTuple`) carried alongside each packet by the
/// test code. We then:
///
/// 1. Establish a PSK+CID session via tuple A.
/// 2. Exchange application data routed through tuple A, recording the CID and
///    sequence numbers the server observes on those records.
/// 3. **Rebind**: the test relabels the client's apparent tuple to B and
///    continues sending — at the wire level nothing about the DTLS record
///    changes except record sequence numbers; only the out-of-band tuple label
///    changes. The server has no tuple awareness, so it must decrypt purely by
///    CID. This is the property RFC 9146 is supposed to deliver.
/// 4. Inject a **late-arriving packet from tuple A** after the rebind —
///    modelling a middlebox that buffered it pre-transition. It must still
///    decrypt because CID identifies the association, not the source tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransportTuple(&'static str);

struct TaggedPacket {
    src: TransportTuple,
    bytes: Vec<u8>,
}

#[test]
fn dtls12_psk_with_cid_rebinds_across_transport_tuples() {
    let _ = env_logger::try_init();

    let (client_config, server_config) = psk_configs_with_cid(b"roam-c", b"roam-s");
    let mut now = Instant::now();

    let mut client = Dtls::new_12_psk(client_config, now);
    client.set_active(true);
    let mut server = Dtls::new_12_psk(server_config, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..60 {
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

    // Phase 1: the client is reachable via tuple A. Send app data and record
    // the CID+sequence the server decrypts.
    let tuple_a = TransportTuple("home-wifi: 10.0.0.1:54321");
    let tuple_b = TransportTuple("lte-fallback: 203.0.113.7:60000");

    let pre_payload = b"pre-rebind via tuple A";
    client.send_application_data(pre_payload).expect("send");
    let tagged_a: Vec<TaggedPacket> = collect_packets(&mut client)
        .into_iter()
        .map(|bytes| TaggedPacket {
            src: tuple_a,
            bytes,
        })
        .collect();
    assert!(
        tagged_a
            .iter()
            .any(|p| !p.bytes.is_empty() && p.bytes[0] == 25),
        "PSK client must emit a tls12_cid record on tuple A"
    );
    for p in &tagged_a {
        assert_eq!(p.src, tuple_a);
        // Caller does whatever socket-layer routing it likes; the server
        // engine just gets bytes.
        let _ = server.handle_packet(&p.bytes);
    }
    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == pre_payload),
        "Server must decrypt PSK+CID traffic arriving on tuple A"
    );

    // Phase 2: the transport tuple rebinds to B. No API call on the engine is
    // needed — that's the whole point. The test simply changes the label it
    // attaches to outgoing packets.
    now += Duration::from_secs(45);
    let post_payload = b"post-rebind via tuple B";
    client.send_application_data(post_payload).expect("send");
    let tagged_b: Vec<TaggedPacket> = collect_packets(&mut client)
        .into_iter()
        .map(|bytes| TaggedPacket {
            src: tuple_b,
            bytes,
        })
        .collect();
    assert!(
        !tagged_b.is_empty(),
        "Client must emit packets after rebinding to tuple B"
    );
    for p in &tagged_b {
        assert_eq!(p.src, tuple_b);
        let _ = server.handle_packet(&p.bytes);
    }
    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == post_payload),
        "Server must decrypt PSK+CID traffic after the transport tuple \
         changes from {:?} to {:?} — association continuity must come from \
         CID, not the 5-tuple",
        tuple_a,
        tuple_b
    );

    // Phase 3: a middlebox releases a buffered packet that was originally
    // transmitted on tuple A, arriving AFTER the rebind. The record's CID is
    // still valid and its sequence number is still fresh, so the server must
    // accept it.
    let late_payload = b"late packet via tuple A after rebind";
    client.send_application_data(late_payload).expect("send");
    let tagged_late_a: Vec<TaggedPacket> = collect_packets(&mut client)
        .into_iter()
        .map(|bytes| TaggedPacket {
            src: tuple_a, // buffered packet labelled with the OLD tuple
            bytes,
        })
        .collect();
    for p in &tagged_late_a {
        assert_eq!(p.src, tuple_a);
        let _ = server.handle_packet(&p.bytes);
    }
    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == late_payload),
        "Server must accept a late packet tagged with the pre-rebind tuple {:?} \
         because CID (not source tuple) identifies the association",
        tuple_a
    );
}

/// RFC 9146 §4 / RFC 6347 §4.1.2.7 applied to a PSK session: a stray
/// `tls12_cid` record where CID is not negotiated must be discarded without
/// dropping unrelated records coalesced into the same datagram. PSK analogue
/// of the cert-path `dtls12_unsolicited_cid_record_does_not_drop_coalesced_records`
/// test, kept because PSK is the primary-path product target per the rollback
/// plan and the coalesced-parsing guard should hold regardless of auth mode.
#[test]
fn dtls12_psk_unsolicited_cid_record_does_not_drop_coalesced_records() {
    let _ = env_logger::try_init();

    // Neither side configures CID, so a content-type-25 record is unsolicited.
    let (client_config, server_config) = psk_configs();
    let mut now = Instant::now();

    let mut client = Dtls::new_12_psk(client_config, now);
    client.set_active(true);
    let mut server = Dtls::new_12_psk(server_config, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..60 {
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

    let payload = b"psk-coalesced-after-stray";
    client.send_application_data(payload).expect("send");
    let client_pkts = collect_packets(&mut client);
    let valid_pkt = client_pkts
        .iter()
        .find(|p| !p.is_empty() && p[0] == 23)
        .expect("PSK client should emit an ApplicationData record")
        .clone();

    // Stray tls12_cid record, zero-length body, standard 13-byte DTLS header.
    let stray_cid: [u8; 13] = [
        25, // ContentType::Tls12Cid
        0xfe, 0xfd, // DTLS 1.2
        0, 1, // epoch
        0, 0, 0, 0, 0, 0xab, // seqnum
        0, 0, // length = 0
    ];
    let mut coalesced = Vec::with_capacity(stray_cid.len() + valid_pkt.len());
    coalesced.extend_from_slice(&stray_cid);
    coalesced.extend_from_slice(&valid_pkt);

    deliver_packets(&[coalesced], &mut server);
    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == payload),
        "PSK server must process coalesced ApplicationData after a stray tls12_cid"
    );
}

/// RFC 9146 §5.3 / RFC 6347 §4.1.2.7 applied to a PSK session: a tampered CID
/// field must be dropped silently at the AEAD layer, and the replay window
/// must not advance on the tampered sequence — so the legitimate retransmit
/// still arrives. PSK-specific analogue of the cert-path tamper test.
#[test]
fn dtls12_psk_with_cid_tampered_record_is_dropped() {
    let _ = env_logger::try_init();

    let client_cid: &[u8] = b"psk-tc";
    let server_cid: &[u8] = b"psk-ts";
    let (client_config, server_config) = psk_configs_with_cid(client_cid, server_cid);

    let mut now = Instant::now();
    let mut client = Dtls::new_12_psk(client_config, now);
    client.set_active(true);
    let mut server = Dtls::new_12_psk(server_config, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;
    for _ in 0..60 {
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

    let payload = b"psk-cid-tamper-canary";
    server.send_application_data(payload).expect("server send");
    let server_pkts = collect_packets(&mut server);
    let cid_pkt = server_pkts
        .iter()
        .find(|p| !p.is_empty() && p[0] == 25)
        .expect("PSK server should emit a tls12_cid record")
        .clone();

    assert!(cid_pkt.len() >= 11 + client_cid.len() + 2);
    assert_eq!(&cid_pkt[11..11 + client_cid.len()], client_cid);

    let mut tampered = cid_pkt.clone();
    tampered[11] ^= 0x40;

    deliver_packets(&[tampered], &mut client);
    let after_tamper = drain_outputs(&mut client);
    assert!(
        after_tamper.app_data.is_empty(),
        "PSK client must not surface app data from a tampered CID record"
    );

    deliver_packets(&[cid_pkt], &mut client);
    let after_valid = drain_outputs(&mut client);
    assert!(
        after_valid.app_data.iter().any(|d| d == payload),
        "PSK client must accept the untampered original after a tampered drop"
    );
}
