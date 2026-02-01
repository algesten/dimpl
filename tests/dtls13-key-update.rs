//! DTLS 1.3 key update tests.

mod dtls13_common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls};
use dtls13_common::*;

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

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

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

    let mut client = Dtls::new_13(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();

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
