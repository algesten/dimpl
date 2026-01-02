mod ossl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, Output};
use ossl::{DtlsCertOptions, DtlsEvent, OsslDtlsCert};

#[test]
fn client_ossl() {
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

    let mut client = Dtls::new(
        config,
        dimpl::DtlsCertificate {
            certificate: client_x509_der,
            private_key: client_pkey_der,
        },
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
                    // println!(
                    //     "Client -> Server packet ({} bytes): {:02x?}",
                    //     data.len(),
                    //     data
                    // );
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
                    client_received_data.extend_from_slice(data);
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
            // println!(
            //     "Server -> Client packet ({} bytes): {:02x?}",
            //     datagram.len(),
            //     datagram
            // );
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
        !client_km.is_empty(),
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
