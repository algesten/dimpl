mod ossl;

use std::collections::VecDeque;
use std::fs;
use std::path::Path;

use ossl::{DtlsCertOptions, DtlsEvent, OsslDtlsCert};

#[test]
fn ossl_ossl() {
    // Create datagrams directory if it doesn't exist
    let datagrams_dir = Path::new("tests/datagrams");
    fs::create_dir_all(datagrams_dir).expect("Failed to create datagrams directory");

    // Counter for datagram files
    let mut datagram_counter = 0;

    // Generate certificates for both client and server
    let client_cert_options = DtlsCertOptions::default();
    let client_cert = OsslDtlsCert::new(client_cert_options);

    let server_cert_options = DtlsCertOptions::default();
    let server_cert = OsslDtlsCert::new(server_cert_options);

    // Save certificates and keys
    fs::write(
        "tests/datagrams/client_cert.der",
        client_cert
            .x509
            .to_der()
            .expect("Failed to get client cert DER"),
    )
    .expect("Failed to write client cert");
    fs::write(
        "tests/datagrams/client_key.der",
        client_cert
            .pkey
            .private_key_to_der()
            .expect("Failed to get client key DER"),
    )
    .expect("Failed to write client key");
    fs::write(
        "tests/datagrams/server_cert.der",
        server_cert
            .x509
            .to_der()
            .expect("Failed to get server cert DER"),
    )
    .expect("Failed to write server cert");
    fs::write(
        "tests/datagrams/server_key.der",
        server_cert
            .pkey
            .private_key_to_der()
            .expect("Failed to get server key DER"),
    )
    .expect("Failed to write server key");

    // Create server
    let mut server = server_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS server");

    // Create client
    let mut client = client_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS client");

    // Set server as passive (accepting connections)
    server.set_active(false);
    // Set client as active (initiating connections)
    client.set_active(true);

    // Collection to store server events
    let mut server_events = VecDeque::new();
    let mut client_events = VecDeque::new();

    // Stored outputs for verification
    let mut client_connected = false;
    let mut server_connected = false;
    let mut client_keying_material = None;
    let mut server_keying_material = None;

    // Test data to exchange
    let client_test_data = b"Hello from client";
    let server_test_data = b"Hello from server";

    // Buffers for received data
    let mut client_received_data = Vec::new();
    let mut server_received_data = Vec::new();

    client.handle_handshake(&mut client_events).unwrap();

    // Simulate handshake and data exchange
    // This might need several iterations until both sides consider themselves connected
    for _ in 0..20 {
        // Poll client for datagrams
        while let Some(datagram) = client.poll_datagram() {
            // println!(
            //     "Client -> Server packet ({} bytes): {:02x?}",
            //     datagram.len(),
            //     datagram
            // );
            // Save client->server datagram
            let filename = format!("tests/datagrams/client_to_server_{}.bin", datagram_counter);
            fs::write(&filename, &*datagram).expect("Failed to write client datagram");
            datagram_counter += 1;

            // Client data goes to server
            if let Err(e) = server.handle_receive(&datagram, &mut server_events) {
                panic!("Server failed to handle client packet: {:?}", e);
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

        // Poll server for datagrams
        while let Some(datagram) = server.poll_datagram() {
            // println!(
            //     "Server -> Client packet ({} bytes): {:02x?}",
            //     datagram.len(),
            //     datagram
            // );
            // Save server->client datagram
            let filename = format!("tests/datagrams/server_to_client_{}.bin", datagram_counter);
            fs::write(&filename, &*datagram).expect("Failed to write server datagram");
            datagram_counter += 1;

            // Server data goes to client
            if let Err(e) = client.handle_receive(&datagram, &mut client_events) {
                panic!("Client failed to handle server packet: {:?}", e);
            }
        }

        // Process client events
        while let Some(event) = client_events.pop_front() {
            match event {
                DtlsEvent::Connected => {
                    client_connected = true;
                    println!("Client connected");
                }
                DtlsEvent::RemoteFingerprint(fp) => {
                    println!("Client received fingerprint: {}", fp);
                    // We don't need to store the fingerprint, just log it
                }
                DtlsEvent::SrtpKeyingMaterial(km, profile) => {
                    client_keying_material = Some((km, profile));
                    println!("Client received keying material for profile: {:?}", profile);

                    // After handshake is complete, send test data from client
                    client
                        .handle_input(client_test_data)
                        .expect("Failed to send client data");
                }
                DtlsEvent::Data(data) => {
                    client_received_data.extend_from_slice(&data);
                    println!(
                        "Client received {} bytes of application data: {:02x?}",
                        data.len(),
                        data
                    );
                }
            }
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
        client_km.as_ref().len() > 0,
        "Client keying material should not be empty"
    );
    assert_eq!(
        client_km.as_ref().len(),
        server_km.as_ref().len(),
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
