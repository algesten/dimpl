mod ossl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{CertVerifier, Config, Dtls, Output};
use ossl::{DtlsCertOptions, DtlsEvent, OsslDtlsCert};

fn run_client_server_with_mtu(mtu: usize) -> (usize, usize) {
    // Initialize logger once across test runs
    let _ = env_logger::try_init();

    // Generate certificates for both client and server
    let client_cert_options = DtlsCertOptions::default();
    let client_cert = OsslDtlsCert::new(client_cert_options);

    let server_cert_options = DtlsCertOptions::default();
    let server_cert = OsslDtlsCert::new(server_cert_options);

    // Create server (OpenSSL-backed)
    let mut server = server_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS server");

    // Server is passive
    server.set_active(false);

    // Initialize client
    let mut cfg = Config::default();
    cfg.mtu = mtu;
    let config = Arc::new(cfg);

    // Get client certificate as DER encoded bytes
    let client_x509_der = client_cert
        .x509
        .to_der()
        .expect("Failed to get client cert DER");
    let client_pkey_der = client_cert
        .pkey
        .private_key_to_der()
        .expect("Failed to get client private key DER");

    // Simple certificate verifier that accepts any certificate
    struct DummyVerifier;
    impl CertVerifier for DummyVerifier {
        fn verify_certificate(&self, _der: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    let mut client = Dtls::new(
        config,
        client_x509_der,
        client_pkey_der,
        Box::new(DummyVerifier),
    );
    client.set_active(true);

    // Server events queue
    let mut server_events = VecDeque::new();

    // State
    let mut client_connected = false;
    let mut server_connected = false;

    // Packet counters
    let mut client_to_server_packets: usize = 0;
    let mut server_to_client_packets: usize = 0;
    let mut max_c2s_len: usize = 0;

    // Test data
    let client_test_data = b"Hello from client";
    let server_test_data = b"Hello from server";

    // Buffers for received data
    let mut client_received_data = Vec::new();
    let mut server_received_data = Vec::new();

    // Drive handshake and data exchange
    let mut out_buf = vec![0u8; mtu + 512];
    for _ in 0..20 {
        client.handle_timeout(Instant::now()).unwrap();

        let mut continue_polling = true;
        while continue_polling {
            let output = client.poll_output(&mut out_buf);
            match output {
                Output::Packet(data) => {
                    client_to_server_packets += 1;
                    if data.len() > max_c2s_len {
                        max_c2s_len = data.len();
                    }
                    if let Err(e) = server.handle_receive(data, &mut server_events) {
                        panic!("Server failed to handle client packet: {:?}", e);
                    }
                }
                Output::Connected => {
                    client_connected = true;
                }
                Output::PeerCert(_cert) => {
                    // ignore for this test
                }
                Output::KeyingMaterial(_km, _profile) => {
                    // After handshake is complete, send test data
                    client
                        .send_application_data(client_test_data)
                        .expect("Failed to send client data");
                }
                Output::ApplicationData(data) => {
                    client_received_data.extend_from_slice(&data);
                }
                Output::Timeout(_) => {
                    continue_polling = false;
                }
            }
        }

        // Process server events
        while let Some(event) = server_events.pop_front() {
            match event {
                DtlsEvent::Connected => {
                    server_connected = true;
                }
                DtlsEvent::RemoteFingerprint(_fp) => {}
                DtlsEvent::SrtpKeyingMaterial(_km, _profile) => {
                    // After handshake is complete, send test data from server
                    server
                        .handle_input(server_test_data)
                        .expect("Failed to send server data");
                }
                DtlsEvent::Data(data) => {
                    server_received_data.extend_from_slice(&data);
                }
            }
        }

        // Send server datagrams to client and count them
        while let Some(datagram) = server.poll_datagram() {
            server_to_client_packets += 1;
            client
                .handle_packet(&datagram)
                .expect("Failed to handle server packet");
        }

        if client_connected
            && server_connected
            && !client_received_data.is_empty()
            && !server_received_data.is_empty()
        {
            break;
        }
    }

    // Basic correctness
    assert!(client_connected, "Client should be connected");
    assert!(server_connected, "Server should be connected");
    assert_eq!(server_received_data, client_test_data);
    assert_eq!(client_received_data, server_test_data);

    // Ensure the client never emits datagrams above its configured MTU
    assert!(
        max_c2s_len <= mtu,
        "client->server datagram length {} exceeds MTU {}",
        max_c2s_len,
        mtu
    );

    (client_to_server_packets, server_to_client_packets)
}

#[test]
fn client_fragments() {
    // Larger MTU should pack more and send fewer packets
    let (large_c2s, large_s2c) = run_client_server_with_mtu(1400);
    // Smaller MTU forces more fragmentation
    let (small_c2s, small_s2c) = run_client_server_with_mtu(100);

    println!(
        "packet counts: large(c2s={}, s2c={}), small(c2s={}, s2c={})",
        large_c2s, large_s2c, small_c2s, small_s2c
    );

    // Tight-ish bounds informed by expected DTLS handshake/message sizes and packing
    assert!(
        large_c2s >= 3 && large_c2s <= 8,
        "large MTU client->server packets: {}",
        large_c2s
    );
    assert!(
        small_c2s >= 4 && small_c2s <= 20,
        "small MTU client->server packets: {}",
        small_c2s
    );
    assert!(
        small_c2s > large_c2s,
        "small MTU should produce more client->server packets"
    );

    // Optional checks for server->client direction with similarly tight bounds
    assert!(
        large_s2c >= 3 && large_s2c <= 10,
        "large MTU server->client packets: {}",
        large_s2c
    );
    assert!(
        small_s2c >= 5 && small_s2c <= 20,
        "small MTU server->client packets: {}",
        small_s2c
    );
    assert!(
        small_s2c >= large_s2c,
        "small MTU should produce at least as many server->client packets"
    );
}
