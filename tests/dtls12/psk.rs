//! DTLS 1.2 PSK handshake tests.

use std::sync::Arc;
use std::time::Instant;

use dimpl::crypto::Dtls12CipherSuite;
use dimpl::{Config, Dtls, Error, PskResolver};

use crate::common::{deliver_packets, drain_outputs};

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

fn psk_config_for_suite(suite: Dtls12CipherSuite) -> Arc<Config> {
    let identity = b"test-device".to_vec();
    let key = b"0123456789abcdef".to_vec(); // 16 bytes

    let resolver = FixedPsk {
        identity: identity.clone(),
        key,
    };

    let mut provider = Config::default().crypto_provider().clone();
    let psk_suite = provider
        .cipher_suites
        .iter()
        .copied()
        .find(|cs| cs.suite() == suite)
        .unwrap_or_else(|| panic!("{:?} not in provider", suite));

    let suites = Box::leak(Box::new([psk_suite]));
    provider.cipher_suites = suites;

    Arc::new(
        Config::builder()
            .with_crypto_provider(provider)
            .with_psk_identity(identity)
            .with_psk_identity_hint(b"hint".to_vec())
            .with_psk_resolver(Arc::new(resolver))
            .build()
            .expect("build PSK config"),
    )
}

fn psk_config() -> Arc<Config> {
    psk_config_for_suite(Dtls12CipherSuite::PSK_AES128_CCM_8)
}

#[test]
fn dtls12_psk_self_handshake() {
    let _ = env_logger::try_init();

    let config = psk_config();
    let now = Instant::now();

    let mut client = Dtls::new_12_psk(config.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12_psk(config, now);
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

    let config = psk_config();
    let now = Instant::now();

    let mut client = Dtls::new_12_psk(config.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12_psk(config, now);
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
    server
        .send_application_data(reply)
        .expect("send app data");

    let so = drain_outputs(&mut server);
    deliver_packets(&so.packets, &mut client);

    let co = drain_outputs(&mut client);
    assert!(
        co.app_data.iter().any(|d| d == reply),
        "Client should receive server's application data"
    );
}

#[test]
fn dtls12_psk_gcm_self_handshake() {
    let _ = env_logger::try_init();

    let config = psk_config_for_suite(Dtls12CipherSuite::PSK_AES128_GCM_SHA256);
    let now = Instant::now();

    let mut client = Dtls::new_12_psk(config.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12_psk(config, now);
    server.set_active(false);

    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..60 {
        client.handle_timeout(Instant::now()).unwrap();
        server.handle_timeout(Instant::now()).unwrap();

        let client_out = drain_outputs(&mut client);
        if client_out.connected {
            client_connected = true;
        }
        deliver_packets(&client_out.packets, &mut server);

        let server_out = drain_outputs(&mut server);
        if server_out.connected {
            server_connected = true;
        }
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }
    }

    assert!(client_connected, "PSK-GCM client should connect");
    assert!(server_connected, "PSK-GCM server should connect");
}

#[test]
fn dtls12_psk_gcm_application_data_roundtrip() {
    let _ = env_logger::try_init();

    let config = psk_config_for_suite(Dtls12CipherSuite::PSK_AES128_GCM_SHA256);
    let now = Instant::now();

    let mut client = Dtls::new_12_psk(config.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12_psk(config, now);
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
    let payload = b"Hello from PSK-GCM client!";
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
    let reply = b"Hello from PSK-GCM server!";
    server
        .send_application_data(reply)
        .expect("send app data");

    let so = drain_outputs(&mut server);
    deliver_packets(&so.packets, &mut client);

    let co = drain_outputs(&mut client);
    assert!(
        co.app_data.iter().any(|d| d == reply),
        "Client should receive server's application data"
    );
}

/// Helper: run a PSK handshake + app data roundtrip for any suite.
fn psk_handshake_and_roundtrip(suite: Dtls12CipherSuite) {
    let _ = env_logger::try_init();

    let config = psk_config_for_suite(suite);
    let now = Instant::now();

    let mut client = Dtls::new_12_psk(config.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12_psk(config, now);
    server.set_active(false);

    // Complete handshake
    let mut connected = false;
    for _ in 0..60 {
        client.handle_timeout(Instant::now()).unwrap();
        server.handle_timeout(Instant::now()).unwrap();

        let co = drain_outputs(&mut client);
        deliver_packets(&co.packets, &mut server);

        let so = drain_outputs(&mut server);
        deliver_packets(&so.packets, &mut client);

        if co.connected || so.connected {
            client.handle_timeout(Instant::now()).unwrap();
            server.handle_timeout(Instant::now()).unwrap();

            let co2 = drain_outputs(&mut client);
            deliver_packets(&co2.packets, &mut server);

            let so2 = drain_outputs(&mut server);
            deliver_packets(&so2.packets, &mut client);
            connected = true;
            break;
        }
    }
    assert!(connected, "{:?} handshake should complete", suite);

    // App data roundtrip
    let payload = b"Hello from PSK client!";
    client.send_application_data(payload).expect("send");

    let co = drain_outputs(&mut client);
    deliver_packets(&co.packets, &mut server);

    let so = drain_outputs(&mut server);
    assert!(
        so.app_data.iter().any(|d| d == payload),
        "{:?}: server should receive client data",
        suite
    );
}

#[test]
fn dtls12_psk_aes256_gcm_sha384() {
    psk_handshake_and_roundtrip(Dtls12CipherSuite::PSK_AES256_GCM_SHA384);
}

#[test]
fn dtls12_psk_chacha20_poly1305() {
    psk_handshake_and_roundtrip(Dtls12CipherSuite::PSK_CHACHA20_POLY1305_SHA256);
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
        .with_psk_resolver(Arc::new(FailingResolver))
        .build()
        .expect("server config should build");
    let mut server = Dtls::new_12_psk(Arc::new(server_config), Instant::now());

    let client_config = dimpl::Config::builder()
        .with_psk_identity(b"test_identity".to_vec())
        .with_psk_resolver(Arc::new(PassingResolver))
        .build()
        .expect("client config should build");
    let mut client = Dtls::new_12_psk(Arc::new(client_config), Instant::now());
    client.set_active(true);

    // Drive the handshake; expect a SecurityError from mismatched PSK keys.
    let mut error_found = false;
    for _ in 0..60 {
        if let Err(e) = client.handle_timeout(Instant::now()) {
            assert!(matches!(e, Error::SecurityError(_)), "unexpected error: {e:?}");
            error_found = true;
            break;
        }
        let co = drain_outputs(&mut client);
        for p in &co.packets {
            if let Err(e) = server.handle_packet(p) {
                assert!(matches!(e, Error::SecurityError(_)), "unexpected error: {e:?}");
                error_found = true;
                break;
            }
        }
        if error_found {
            break;
        }
        assert!(!co.connected, "client should not connect with mismatched PSK");

        if let Err(e) = server.handle_timeout(Instant::now()) {
            assert!(matches!(e, Error::SecurityError(_)), "unexpected error: {e:?}");
            error_found = true;
            break;
        }
        let so = drain_outputs(&mut server);
        for p in &so.packets {
            if let Err(e) = client.handle_packet(p) {
                assert!(matches!(e, Error::SecurityError(_)), "unexpected error: {e:?}");
                error_found = true;
                break;
            }
        }
        if error_found {
            break;
        }
        assert!(!so.connected, "server should not connect with mismatched PSK");
    }

    assert!(error_found, "Expected SecurityError from PSK verification failure");
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
        .with_psk_resolver(Arc::new(AlwaysPassResolver))
        .build()
        .expect("server config should build");
    let mut server = Dtls::new_12_psk(Arc::new(server_config), Instant::now());

    let client_config = dimpl::Config::builder()
        .with_psk_identity(b"test_identity".to_vec())
        .with_psk_resolver(Arc::new(AlwaysPassResolver))
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
