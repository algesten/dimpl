mod ossl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, Output};
use ossl::{DtlsCertOptions, DtlsEvent, OsslDtlsCert};

#[test]
fn server_ossl() {
    let _ = env_logger::try_init();

    // Generate certificates for both server (dimpl) and client (OpenSSL)
    let server_cert_options = DtlsCertOptions::default();
    let server_cert = OsslDtlsCert::new(server_cert_options);

    let client_cert_options = DtlsCertOptions::default();
    let client_cert = OsslDtlsCert::new(client_cert_options);

    // Create OpenSSL DTLS client (active)
    let mut client = client_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS client");
    client.set_active(true);

    // Initialize dimpl server
    let config = Arc::new(Config::default());

    // dimpl Server expects its own certificate/private key (DER)
    let server_x509_der = server_cert
        .x509
        .to_der()
        .expect("Failed to get server cert DER");
    let server_pkey_der = server_cert
        .pkey
        .private_key_to_der()
        .expect("Failed to get server private key DER");

    let mut server = Dtls::new(
        config,
        dimpl::DtlsCertificate {
            certificate: server_x509_der,
            private_key: server_pkey_der,
        },
    );
    server.set_active(false);

    // Buffers and flags
    let mut client_events = VecDeque::new();

    let mut server_connected = false;
    let mut client_connected = false;

    let mut saw_server_peer_cert = false;
    let mut server_keying_material = None;
    let mut client_keying_material = None;

    // Test data
    let client_test_data = b"Hello from client";
    let server_test_data = b"Hello from server";

    let mut client_received_data = Vec::new();
    let mut server_received_data = Vec::new();

    // Drive handshake and data exchange
    let mut out_buf = vec![0u8; 2048];
    for _ in 0..40 {
        server.handle_timeout(Instant::now()).unwrap();
        client.handle_handshake(&mut client_events).unwrap();
        // 1) Drain client (OpenSSL) outgoing datagrams to the server
        while let Some(datagram) = client.poll_datagram() {
            server
                .handle_packet(&datagram)
                .expect("Server failed to handle client packet");
        }

        // 2) Poll server outputs and feed to client
        loop {
            match server.poll_output(&mut out_buf) {
                Output::Packet(data) => {
                    client
                        .handle_receive(data, &mut client_events)
                        .expect("Client failed to handle server packet");
                }
                Output::Connected => {
                    server_connected = true;
                }
                Output::PeerCert(_cert) => {
                    saw_server_peer_cert = true;
                }
                Output::KeyingMaterial(km, profile) => {
                    server_keying_material = Some((km.as_ref().to_vec(), profile));
                    // As soon as handshake completes from server side, send server app data
                    server
                        .send_application_data(server_test_data)
                        .expect("Server failed to send app data");
                }
                Output::ApplicationData(data) => {
                    server_received_data.extend_from_slice(data);
                }
                Output::Timeout(_) => break,
            }
        }

        // 3) Process client (OpenSSL) events
        while let Some(event) = client_events.pop_front() {
            match event {
                DtlsEvent::Connected => {
                    client_connected = true;
                    // Once client is connected, send app data from client to server
                    client
                        .handle_input(client_test_data)
                        .expect("Client failed to send app data");
                }
                DtlsEvent::RemoteFingerprint(_fp) => {
                    // Fingerprint not used in assertions here
                }
                DtlsEvent::SrtpKeyingMaterial(km, profile) => {
                    client_keying_material = Some((km, profile));
                }
                DtlsEvent::Data(data) => {
                    client_received_data.extend_from_slice(&data);
                }
            }
        }

        // 4) Deliver any further client datagrams produced after app writes
        while let Some(datagram) = client.poll_datagram() {
            server
                .handle_packet(&datagram)
                .expect("Server failed to handle client packet");
        }

        if server_connected
            && client_connected
            && !client_received_data.is_empty()
            && !server_received_data.is_empty()
        {
            break;
        }
    }

    // Assertions
    assert!(server_connected, "Server should be connected");
    assert!(client_connected, "Client should be connected");

    assert!(
        saw_server_peer_cert,
        "Server should have received peer certificate"
    );

    assert!(
        server_keying_material.is_some(),
        "Server should have SRTP keying material"
    );
    assert!(
        client_keying_material.is_some(),
        "Client should have SRTP keying material"
    );

    let (server_km, server_profile) = server_keying_material.unwrap();
    let (client_km, client_profile) = client_keying_material.unwrap();

    assert_eq!(
        server_profile, client_profile,
        "Both sides should negotiate same SRTP profile"
    );
    assert!(
        !server_km.is_empty(),
        "Server keying material should not be empty"
    );
    assert_eq!(
        server_km.len(),
        client_km.len(),
        "Keying material length should match"
    );

    assert_eq!(
        server_received_data, client_test_data,
        "Server should receive correct data"
    );
    assert_eq!(
        client_received_data, server_test_data,
        "Client should receive correct data"
    );
}
