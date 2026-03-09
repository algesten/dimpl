//! DTLS 1.2 PSK handshake tests.

use std::sync::Arc;
use std::time::Instant;

use dimpl::crypto::Dtls12CipherSuite;
use dimpl::{Config, Dtls, PskResolver};

use crate::common::*;

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
