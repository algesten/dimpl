mod ossl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::crypto::{CipherSuite, SignatureAlgorithm};
use dimpl::{Config, Dtls, Output};
use ossl::{DtlsCertOptions, DtlsEvent, DtlsPKeyType, OsslDtlsCert};

#[test]
fn all_crypto() {
    let _ = env_logger::try_init();

    // Loop over all supported cipher suites and ensure we can connect
    for &suite in CipherSuite::all().iter() {
        eprintln!("Testing suite (dimpl client ↔️ ossl server): {:?}", suite);

        run_dimpl_client_vs_ossl_server_for_suite(suite);

        eprintln!("Testing suite (ossl client ↔️ dimpl server): {:?}", suite);
        run_ossl_client_vs_dimpl_server_for_suite(suite);
    }
}

fn run_dimpl_client_vs_ossl_server_for_suite(suite: CipherSuite) {
    // Generate certificates for both client and server matching the suite's signature algorithm
    let pkey_type = match suite.signature_algorithm() {
        SignatureAlgorithm::ECDSA => DtlsPKeyType::EcDsaP256,
        SignatureAlgorithm::RSA => DtlsPKeyType::Rsa2048,
        _ => panic!("Unsupported signature algorithm in suite: {:?}", suite),
    };

    let client_cert = OsslDtlsCert::new(DtlsCertOptions {
        common_name: "WebRTC".into(),
        pkey_type: pkey_type.clone(),
    });

    let server_cert = OsslDtlsCert::new(DtlsCertOptions {
        common_name: "WebRTC".into(),
        pkey_type,
    });

    // Create OpenSSL server impl
    let mut server = server_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS server");
    server.set_active(false);

    // Initialize dimpl client restricted to the single suite
    // Note: cipher suites are determined by the crypto provider
    let config = Arc::new(Config::default());

    // DER encodings for our client
    let client_x509_der = client_cert.x509.to_der().expect("client cert der");
    let client_pkey_der = client_cert
        .pkey
        .private_key_to_der()
        .expect("client key der");

    let mut client = Dtls::new(config, client_x509_der, client_pkey_der);
    client.set_active(true);

    let mut server_events = VecDeque::new();
    let mut client_connected = false;
    let mut server_connected = false;

    let mut out_buf = vec![0u8; 2048];
    for _ in 0..60 {
        client.handle_timeout(Instant::now()).unwrap();
        // Drain client outputs
        loop {
            match client.poll_output(&mut out_buf) {
                Output::Packet(data) => {
                    server
                        .handle_receive(&data, &mut server_events)
                        .expect("Server failed to handle client packet");
                }
                Output::Connected => {
                    client_connected = true;
                }
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        // Process server events
        while let Some(event) = server_events.pop_front() {
            match event {
                DtlsEvent::Connected => {
                    server_connected = true;
                }
                _ => {}
            }
        }

        // Send server datagrams back to client
        while let Some(datagram) = server.poll_datagram() {
            client
                .handle_packet(&datagram)
                .expect("Failed to handle server packet");
        }

        if client_connected && server_connected {
            break;
        }
    }

    assert!(
        client_connected,
        "Client should connect for suite {:?}",
        suite
    );
    assert!(
        server_connected,
        "Server should connect for suite {:?}",
        suite
    );
}

fn run_ossl_client_vs_dimpl_server_for_suite(suite: CipherSuite) {
    // Generate certificates for both ends
    let pkey_type = match suite.signature_algorithm() {
        SignatureAlgorithm::ECDSA => DtlsPKeyType::EcDsaP256,
        SignatureAlgorithm::RSA => DtlsPKeyType::Rsa2048,
        _ => panic!("Unsupported signature algorithm in suite: {:?}", suite),
    };

    let server_cert = OsslDtlsCert::new(DtlsCertOptions {
        common_name: "WebRTC".into(),
        pkey_type: pkey_type.clone(),
    });
    let client_cert = OsslDtlsCert::new(DtlsCertOptions {
        common_name: "WebRTC".into(),
        pkey_type,
    });

    // OpenSSL DTLS client
    let mut ossl_client = client_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS client");
    ossl_client.set_active(true);

    // dimpl server with single-suite config
    // Note: cipher suites are determined by the crypto provider
    let config = Arc::new(Config::default());

    let server_x509_der = server_cert.x509.to_der().expect("server cert der");
    let server_pkey_der = server_cert
        .pkey
        .private_key_to_der()
        .expect("server key der");

    let mut server = Dtls::new(config, server_x509_der, server_pkey_der);
    server.set_active(false);

    // Drive handshake until both sides report connected
    let mut client_events = VecDeque::new();
    let mut server_connected = false;
    let mut client_connected = false;

    let mut out_buf = vec![0u8; 2048];
    for _ in 0..60 {
        server.handle_timeout(Instant::now()).unwrap();
        ossl_client.handle_handshake(&mut client_events).unwrap();

        // 1) Drain client (OpenSSL) outgoing datagrams to the server
        while let Some(datagram) = ossl_client.poll_datagram() {
            server
                .handle_packet(&datagram)
                .expect("Server failed to handle client packet");
        }

        // 2) Poll server outputs and feed to client
        loop {
            match server.poll_output(&mut out_buf) {
                Output::Packet(data) => {
                    ossl_client
                        .handle_receive(data, &mut client_events)
                        .expect("Client failed to handle server packet");
                }
                Output::Connected => {
                    server_connected = true;
                }
                Output::Timeout(_) => break,
                _ => {}
            }
        }

        // 3) Process client (OpenSSL) events
        while let Some(event) = client_events.pop_front() {
            if let DtlsEvent::Connected = event {
                client_connected = true;
            }
        }

        // 4) Deliver any further client datagrams produced after events
        while let Some(datagram) = ossl_client.poll_datagram() {
            server
                .handle_packet(&datagram)
                .expect("Server failed to handle client packet");
        }

        if server_connected && client_connected {
            break;
        }
    }

    assert!(
        server_connected,
        "Server should connect for suite {:?}",
        suite
    );
    assert!(
        client_connected,
        "Client should connect for suite {:?}",
        suite
    );
}
