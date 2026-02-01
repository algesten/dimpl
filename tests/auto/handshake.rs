//! Auto-negotiation handshake integration tests.
//!
//! Tests the `Dtls::new_auto()` + `set_active(true)` (client) path against
//! explicit DTLS 1.2, DTLS 1.3, and auto-sense servers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::Dtls;

use crate::common::*;

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server() {
    //! An auto-sensing client should complete a full handshake against an
    //! explicit DTLS 1.3 server.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
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

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Auto client should connect to DTLS 1.3 server");
    assert!(server_connected, "DTLS 1.3 server should connect to auto client");
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server_keying_material() {
    //! Verify that an auto-client and DTLS 1.3 server derive identical
    //! SRTP keying material.
    use dimpl::certificate::generate_self_signed_certificate;
    use dimpl::SrtpProfile;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_km: Option<(Vec<u8>, SrtpProfile)> = None;
    let mut server_km: Option<(Vec<u8>, SrtpProfile)> = None;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if let Some(km) = client_out.keying_material {
            client_km = Some(km);
        }
        if let Some(km) = server_out.keying_material {
            server_km = Some(km);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_km.is_some() && server_km.is_some() {
            break;
        }

        now += Duration::from_millis(10);
    }

    let client_km = client_km.expect("Client should have keying material");
    let server_km = server_km.expect("Server should have keying material");

    assert_eq!(
        client_km.0, server_km.0,
        "Client and server keying material should match"
    );
    assert_eq!(
        client_km.1, server_km.1,
        "Client and server SRTP profile should match"
    );
    assert!(!client_km.0.is_empty(), "Keying material should not be empty");
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_auto_server() {
    //! Both sides use auto-sense. They should negotiate DTLS 1.3 (the
    //! hybrid CH includes supported_versions with DTLS 1.3 first).
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_auto(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
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

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Auto client should connect to auto server");
    assert!(server_connected, "Auto server should connect to auto client");
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls12_server() {
    //! An auto-sensing client against an explicit DTLS 1.2 server.
    //! The server sends HelloVerifyRequest, triggering the 1.2 fork.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
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

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected, "Auto client should connect to DTLS 1.2 server");
    assert!(server_connected, "DTLS 1.2 server should connect to auto client");
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls12_server_keying_material() {
    //! Verify that an auto-client and DTLS 1.2 server derive identical
    //! SRTP keying material after HVR-based version negotiation.
    use dimpl::certificate::generate_self_signed_certificate;
    use dimpl::SrtpProfile;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_km: Option<(Vec<u8>, SrtpProfile)> = None;
    let mut server_km: Option<(Vec<u8>, SrtpProfile)> = None;

    for _ in 0..40 {
        client.handle_timeout(now).expect("client timeout");
        server.handle_timeout(now).expect("server timeout");

        let client_out = drain_outputs(&mut client);
        let server_out = drain_outputs(&mut server);

        if let Some(km) = client_out.keying_material {
            client_km = Some(km);
        }
        if let Some(km) = server_out.keying_material {
            server_km = Some(km);
        }

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_km.is_some() && server_km.is_some() {
            break;
        }

        now += Duration::from_millis(10);
    }

    let client_km = client_km.expect("Client should have keying material");
    let server_km = server_km.expect("Server should have keying material");

    assert_eq!(
        client_km.0, server_km.0,
        "Client and server keying material should match"
    );
    assert_eq!(
        client_km.1, server_km.1,
        "Client and server SRTP profile should match"
    );
    assert!(!client_km.0.is_empty(), "Keying material should not be empty");
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server_application_data() {
    //! After handshake, auto-client and DTLS 1.3 server can exchange
    //! application data in both directions.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    // Complete the handshake
    for _ in 0..40 {
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

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(client_connected && server_connected, "Handshake should complete");

    // Send data client -> server
    let msg = b"hello from auto client";
    client.send_application_data(msg).expect("client send");
    now += Duration::from_millis(10);
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    deliver_packets(&client_out.packets, &mut server);
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    assert!(
        server_out.app_data.iter().any(|d| d == msg),
        "Server should receive client's application data"
    );

    // Send data server -> client
    let reply = b"hello from server";
    server.send_application_data(reply).expect("server send");
    now += Duration::from_millis(10);
    server.handle_timeout(now).expect("server timeout");
    let server_out = drain_outputs(&mut server);
    deliver_packets(&server_out.packets, &mut client);
    client.handle_timeout(now).expect("client timeout");
    let client_out = drain_outputs(&mut client);
    assert!(
        client_out.app_data.iter().any(|d| d == reply),
        "Client should receive server's application data"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls12_server_no_cookie() {
    //! An auto-sensing client against a DTLS 1.2 server that skips
    //! HelloVerifyRequest (use_server_cookie = false). The server sends
    //! ServerHello directly.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_config = default_config();
    let server_config = no_cookie_config();

    let mut client = Dtls::new_auto(client_config, client_cert);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
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

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Auto client should connect to DTLS 1.2 server (no cookie)"
    );
    assert!(
        server_connected,
        "DTLS 1.2 server (no cookie) should connect to auto client"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn auto_client_to_dtls13_server_no_cookie() {
    //! An auto-sensing client against a DTLS 1.3 server that skips
    //! HelloRetryRequest cookie exchange (use_server_cookie = false).
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_config = default_config();
    let server_config = no_cookie_config();

    let mut client = Dtls::new_auto(client_config, client_cert);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert);
    server.set_active(false);

    let mut now = Instant::now();
    let mut client_connected = false;
    let mut server_connected = false;

    for _ in 0..40 {
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

        deliver_packets(&client_out.packets, &mut server);
        deliver_packets(&server_out.packets, &mut client);

        if client_connected && server_connected {
            break;
        }

        now += Duration::from_millis(10);
    }

    assert!(
        client_connected,
        "Auto client should connect to DTLS 1.3 server (no cookie)"
    );
    assert!(
        server_connected,
        "DTLS 1.3 server (no cookie) should connect to auto client"
    );
}
