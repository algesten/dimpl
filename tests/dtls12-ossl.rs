//! DTLS 1.2 interop tests: dimpl <-> OpenSSL (client + server).

mod ossl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, Output};
use ossl::{DtlsCertOptions, DtlsEvent, OsslDtlsCert};

#[test]
fn dtls12_ossl_client_handshake() {
    env_logger::init();

    // Generate certificates for both client and server
    let client_cert_options = DtlsCertOptions::default();
    let client_cert = OsslDtlsCert::new(client_cert_options);

    let server_cert_options = DtlsCertOptions::default();
    let server_cert = OsslDtlsCert::new(server_cert_options);

    // Create server
    let mut server = server_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS server");

    // Set server as passive (accepting connections)
    server.set_active(false);

    // Initialize client
    let config = Arc::new(Config::default());

    // Get client certificate as DER encoded bytes
    let client_x509_der = client_cert
        .x509
        .to_der()
        .expect("Failed to get client cert DER");
    let client_pkey_der = client_cert
        .pkey
        .private_key_to_der()
        .expect("Failed to get client private key DER");

    let now = Instant::now();

    let mut client = Dtls::new_12(
        config,
        dimpl::DtlsCertificate {
            certificate: client_x509_der,
            private_key: client_pkey_der,
        },
        now,
    );
    client.set_active(true);

    // Collection to store server events
    let mut server_events = VecDeque::new();

    // Stored outputs for verification
    let mut client_connected = false;
    let mut client_peer_cert = None;
    let mut client_keying_material = None;
    let mut server_connected = false;
    // Fingerprint is only used for logging
    let mut server_keying_material = None;

    // Test data to exchange
    let client_test_data = b"Hello from client";
    let server_test_data = b"Hello from server";

    // Buffers for received data
    let mut client_received_data = Vec::new();
    let mut server_received_data = Vec::new();
    let mut out_buf = vec![0u8; 2048];

    // Simulate handshake and data exchange
    // This might need several iterations until both sides consider themselves connected
    for _ in 0..20 {
        client.handle_timeout(Instant::now()).unwrap();
        // Poll client for output
        let mut continue_polling = true;
        while continue_polling {
            // poll_output returns an Output enum (not Option wrapped)
            let output = client.poll_output(&mut out_buf);
            match output {
                Output::Packet(data) => {
                    // Client data goes to server
                    if let Err(e) = server.handle_receive(data, &mut server_events) {
                        panic!("Server failed to handle client packet: {:?}", e);
                    }
                }
                Output::Connected => {
                    client_connected = true;
                    println!("Client connected");
                }
                Output::PeerCert(_cert) => {
                    client_peer_cert = Some(true);
                    println!("Client received peer certificate");
                }
                Output::KeyingMaterial(km, profile) => {
                    client_keying_material = Some((km.as_ref().to_vec(), profile));
                    println!("Client received keying material for profile: {:?}", profile);

                    // After handshake is complete, send test data
                    client
                        .send_application_data(client_test_data)
                        .expect("Failed to send client data");
                }
                Output::ApplicationData(data) => {
                    client_received_data.extend_from_slice(&data);
                    println!(
                        "Client received {} bytes of application data: {:02x?}",
                        data.len(),
                        data
                    );
                }
                Output::Timeout(_) => {
                    // If we get a timeout, it means there are no more packets ready
                    // so we stop polling in this iteration
                    continue_polling = false;
                }
            }
        }

        // Process server events
        while let Some(event) = server_events.pop_front() {
            match event {
                DtlsEvent::Connected => {
                    server_connected = true;
                    println!("Server connected");
                }
                DtlsEvent::RemoteFingerprint(fp) => {
                    println!("Server received fingerprint: {}", fp);
                    // We don't need to store the fingerprint, just log it
                }
                DtlsEvent::SrtpKeyingMaterial(km, profile) => {
                    server_keying_material = Some((km, profile));
                    println!("Server received keying material for profile: {:?}", profile);

                    // After handshake is complete, send test data from server
                    server
                        .handle_input(server_test_data)
                        .expect("Failed to send server data");
                }
                DtlsEvent::Data(data) => {
                    server_received_data.extend_from_slice(&data);
                    println!(
                        "Server received {} bytes of application data: {:02x?}",
                        data.len(),
                        data
                    );
                }
            }
        }

        // Send server datagrams to client
        while let Some(datagram) = server.poll_datagram() {
            client
                .handle_packet(&datagram)
                .expect("Failed to handle server packet");
        }

        // If both connected and data exchanged, we can break
        if client_connected
            && server_connected
            && !client_received_data.is_empty()
            && !server_received_data.is_empty()
        {
            break;
        }
    }

    // Verify both sides connected
    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");

    // Verify client received server certificate
    assert!(
        client_peer_cert.is_some(),
        "Client should have received peer certificate"
    );

    // Verify client and server negotiated keying material
    assert!(
        client_keying_material.is_some(),
        "Client should have received keying material"
    );
    assert!(
        server_keying_material.is_some(),
        "Server should have received keying material"
    );

    // Verify they negotiated the same SRTP profile
    let (client_km, client_profile) = client_keying_material.unwrap();
    let (server_km, server_profile) = server_keying_material.unwrap();
    assert_eq!(
        client_profile, server_profile,
        "Client and server should negotiate the same SRTP profile"
    );

    // Verify keying material has the right length
    assert!(
        client_km.len() > 0,
        "Client keying material should not be empty"
    );
    assert_eq!(
        client_km.len(),
        server_km.len(),
        "Client and server keying material should have the same length"
    );

    // Verify data exchange
    assert_eq!(
        server_received_data, client_test_data,
        "Server should receive correct data from client"
    );
    assert_eq!(
        client_received_data, server_test_data,
        "Client should receive correct data from server"
    );
}

#[test]
fn dtls12_ossl_server_handshake() {
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

    let now = Instant::now();

    let mut server = Dtls::new_12(
        config,
        dimpl::DtlsCertificate {
            certificate: server_x509_der,
            private_key: server_pkey_der,
        },
        now,
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
                    server_received_data.extend_from_slice(&data);
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
        server_km.len() > 0,
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
