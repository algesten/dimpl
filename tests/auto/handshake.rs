//! Auto-negotiation handshake integration tests.
//!
//! Tests the `Dtls::new_auto()` + `set_active(true)` (client) path against
//! explicit DTLS 1.2, DTLS 1.3, and auto-sense servers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Dtls, Error, Output, ProtocolVersion, SrtpProfile};

use crate::common::*;
use crate::shared::{Constructor, SRTP_PROFILE_CASES, handshake_with_srtp};

const SRTP_MODES: [(&str, Constructor, Constructor, ProtocolVersion); 5] = [
    (
        "auto to 1.2",
        Dtls::new_auto,
        Dtls::new_12,
        ProtocolVersion::DTLS1_2,
    ),
    (
        "auto to 1.3",
        Dtls::new_auto,
        Dtls::new_13,
        ProtocolVersion::DTLS1_3,
    ),
    (
        "1.2 to auto",
        Dtls::new_12,
        Dtls::new_auto,
        ProtocolVersion::DTLS1_2,
    ),
    (
        "1.3 to auto",
        Dtls::new_13,
        Dtls::new_auto,
        ProtocolVersion::DTLS1_3,
    ),
    (
        "auto",
        Dtls::new_auto,
        Dtls::new_auto,
        ProtocolVersion::DTLS1_3,
    ),
];

#[test]
fn auto_configured_srtp_version_specific_order_and_allowlist() {
    for (name, client_new, server_new, version) in SRTP_MODES {
        for cookie in [false, true] {
            for (client_profiles, server_profiles, expected_dtls13) in SRTP_PROFILE_CASES {
                let (client, server) = handshake_with_srtp(
                    client_new,
                    server_new,
                    Some(&client_profiles),
                    Some(&server_profiles),
                    cookie,
                );
                let (client_key, client_profile) =
                    client.keying_material.expect("client SRTP keys");
                let (server_key, server_profile) =
                    server.keying_material.expect("server SRTP keys");
                let expected = if version == ProtocolVersion::DTLS1_2 {
                    server_profiles[0]
                } else {
                    expected_dtls13
                };
                assert_eq!(client_profile, expected, "{name}, cookie={cookie}");
                assert_eq!(server_profile, client_profile, "{name}");
                assert_eq!(client_key, server_key, "{name}");
                assert_eq!(
                    client_key.len(),
                    client_profile.keying_material_len(),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn auto_configured_srtp_client_order_and_default_server_behavior() {
    use SrtpProfile::{AEAD_AES_128_GCM, AEAD_AES_256_GCM, AES128_CM_SHA1_80};

    for client_profiles in [
        [AES128_CM_SHA1_80, AEAD_AES_128_GCM, AEAD_AES_256_GCM],
        [AES128_CM_SHA1_80, AEAD_AES_256_GCM, AEAD_AES_128_GCM],
        [AEAD_AES_128_GCM, AES128_CM_SHA1_80, AEAD_AES_256_GCM],
        [AEAD_AES_128_GCM, AEAD_AES_256_GCM, AES128_CM_SHA1_80],
        [AEAD_AES_256_GCM, AES128_CM_SHA1_80, AEAD_AES_128_GCM],
        [AEAD_AES_256_GCM, AEAD_AES_128_GCM, AES128_CM_SHA1_80],
    ] {
        let (client, _) = handshake_with_srtp(
            Dtls::new_auto,
            Dtls::new_13,
            Some(&client_profiles),
            None,
            true,
        );
        assert_eq!(
            client.keying_material.expect("client SRTP keys").1,
            client_profiles[0],
        );
    }

    for (name, client_new, server_new, _) in SRTP_MODES {
        let (client, _) = handshake_with_srtp(
            client_new,
            server_new,
            Some(&[AEAD_AES_128_GCM, AES128_CM_SHA1_80]),
            None,
            true,
        );
        assert_eq!(
            client.keying_material.expect("client SRTP keys").1,
            AEAD_AES_128_GCM,
            "{name}: unoffered profile 8 must not be selected",
        );
    }
}

#[test]
fn auto_disjoint_srtp_profiles_complete_without_srtp_keys() {
    for (name, client_new, server_new, _) in SRTP_MODES {
        let (client, server) = handshake_with_srtp(
            client_new,
            server_new,
            Some(&[SrtpProfile::AES128_CM_SHA1_80]),
            Some(&[SrtpProfile::AEAD_AES_256_GCM]),
            true,
        );
        assert!(client.keying_material.is_none(), "{name}");
        assert!(server.keying_material.is_none(), "{name}");
    }
}

#[test]
fn auto_client_to_dtls13_server() {
    //! An auto-sensing client should complete a full handshake against an
    //! explicit DTLS 1.3 server.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
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
        "Auto client should connect to DTLS 1.3 server"
    );
    assert!(
        server_connected,
        "DTLS 1.3 server should connect to auto client"
    );
}

#[test]
fn auto_client_to_dtls13_server_keying_material() {
    //! Verify that an auto-client and DTLS 1.3 server derive identical
    //! SRTP keying material.
    use dimpl::SrtpProfile;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
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
    assert!(
        !client_km.0.is_empty(),
        "Keying material should not be empty"
    );
}

#[test]
fn auto_client_to_auto_server() {
    //! Both sides use auto-sense. They should negotiate DTLS 1.3 (the
    //! hybrid CH includes supported_versions with DTLS 1.3 first).
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_auto(config, server_cert, now);
    server.set_active(false);

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
        "Auto client should connect to auto server"
    );
    assert!(
        server_connected,
        "Auto server should connect to auto client"
    );
}

#[test]
fn auto_client_to_dtls12_server() {
    //! An auto-sensing client against an explicit DTLS 1.2 server.
    //! The server sends HelloVerifyRequest, triggering the 1.2 fork.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

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
        "Auto client should connect to DTLS 1.2 server"
    );
    assert!(
        server_connected,
        "DTLS 1.2 server should connect to auto client"
    );
}

#[test]
fn auto_client_to_dtls12_server_keying_material() {
    //! Verify that an auto-client and DTLS 1.2 server derive identical
    //! SRTP keying material after HVR-based version negotiation.
    use dimpl::SrtpProfile;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

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
    assert!(
        !client_km.0.is_empty(),
        "Keying material should not be empty"
    );
}

#[test]
fn auto_client_to_dtls13_server_application_data() {
    //! After handshake, auto-client and DTLS 1.3 server can exchange
    //! application data in both directions.
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);
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

    assert!(
        client_connected && server_connected,
        "Handshake should complete"
    );

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

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(server_config, server_cert, now);
    server.set_active(false);

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
fn auto_client_to_dtls13_server_no_cookie() {
    //! An auto-sensing client against a DTLS 1.3 server that skips
    //! HelloRetryRequest cookie exchange (use_server_cookie = false).
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let client_config = default_config();
    let server_config = no_cookie_config();

    let mut now = Instant::now();

    let mut client = Dtls::new_auto(client_config, client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(server_config, server_cert, now);
    server.set_active(false);
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

/// Auto-sense client defers the hybrid ClientHello when the poll buffer
/// is too small, and emits it on the next poll with a large enough buffer.
#[test]
fn auto_client_poll_output_undersized_buffer() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let cert = generate_self_signed_certificate().expect("gen cert");
    let config = default_config();

    let now = Instant::now();
    let mut client = Dtls::new_auto(config, cert, now);
    client.set_active(true);

    // Trigger the hybrid ClientHello
    client.handle_timeout(now).expect("handle_timeout");

    // Poll with a buffer that is too small for the wire packet.
    // Before the fix this would panic with an index-out-of-bounds.
    let mut tiny_buf = [0u8; 4];
    let output = client.poll_output(&mut tiny_buf);

    // Should report the required size while keeping the packet deferred.
    assert!(
        matches!(output, Output::BufferTooSmall { .. }),
        "undersized buffer should yield BufferTooSmall, got: {output:?}"
    );

    // Now poll with a large buffer — the deferred packet should come through.
    let mut big_buf = vec![0u8; 2048];
    let output = client.poll_output(&mut big_buf);
    assert!(
        matches!(output, Output::Packet(_)),
        "large buffer should yield Packet, got: {output:?}"
    );
}

/// Auto-sense client returns an error when the server response cannot be
/// identified as any known DTLS version.
#[test]
fn auto_client_rejects_unknown_version_response() {
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let cert = generate_self_signed_certificate().expect("gen cert");
    let config = default_config();

    let now = Instant::now();
    let mut client = Dtls::new_auto(config, cert, now);
    client.set_active(true);

    // Trigger the hybrid ClientHello
    client.handle_timeout(now).expect("handle_timeout");
    drain_outputs(&mut client);

    // Feed a garbage "server response" that won't parse as any known version.
    // server_hello_version returns Unknown for non-handshake content types.
    let garbage = vec![0xFF, 0x00, 0x01, 0x02];
    let result = client.handle_packet(&garbage);

    assert!(
        result.is_err(),
        "Unknown version response should be an error"
    );
    match result.unwrap_err() {
        Error::UnexpectedMessage(dimpl::UnexpectedMessageError::UnrecognizedAutoServerResponse) => {
        }
        other => panic!("expected UnexpectedMessage, got: {other:?}"),
    }
}

#[test]
fn auto_client_protocol_version_after_negotiating_dtls13() {
    //! After completing a handshake against a DTLS 1.3 server, the
    //! auto-sense client should report `Some(ProtocolVersion::DTLS1_3)`.
    use dimpl::ProtocolVersion;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();
    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_13(config, server_cert, now);
    server.set_active(false);

    // Before negotiation, auto-sense returns None.
    assert_eq!(client.protocol_version(), None);

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
        client_connected && server_connected,
        "Handshake should complete"
    );
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::DTLS1_3));
}

#[test]
fn auto_client_protocol_version_after_negotiating_dtls12() {
    //! After completing a handshake against a DTLS 1.2 server, the
    //! auto-sense client should report `Some(ProtocolVersion::DTLS1_2)`.
    use dimpl::ProtocolVersion;
    use dimpl::certificate::generate_self_signed_certificate;

    let _ = env_logger::try_init();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = default_config();
    let mut now = Instant::now();

    let mut client = Dtls::new_auto(Arc::clone(&config), client_cert, now);
    client.set_active(true);

    let mut server = Dtls::new_12(config, server_cert, now);
    server.set_active(false);

    // Before negotiation, auto-sense returns None.
    assert_eq!(client.protocol_version(), None);

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
        client_connected && server_connected,
        "Handshake should complete"
    );
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::DTLS1_2));
}
