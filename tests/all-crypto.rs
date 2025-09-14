mod ossl;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use dimpl::{CertVerifier, CipherSuite, Client, Config, Output, SignatureAlgorithm};
use ossl::{DtlsCertOptions, DtlsEvent, DtlsPKeyType, OsslDtlsCert};

#[test]
fn all_crypto() {
    let _ = env_logger::try_init();

    // Loop over all supported cipher suites and ensure we can connect
    for &suite in CipherSuite::all().iter() {
        eprintln!("Testing suite: {:?}", suite);

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

        // Create server
        let mut server = server_cert
            .new_dtls_impl()
            .expect("Failed to create DTLS server");
        server.set_active(false);

        // Initialize client with config restricted to a single cipher suite
        let now = Instant::now();
        let mut cfg = Config::default();
        cfg.cipher_suites = vec![suite];
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

        let mut client = Client::new(
            now,
            config,
            client_x509_der,
            client_pkey_der,
            Box::new(DummyVerifier),
        );

        // Minimal handshake: just ensure both sides report connected
        let mut server_events = VecDeque::new();
        let mut client_connected = false;
        let mut server_connected = false;

        client.handle_timeout(Instant::now()).unwrap();

        for _ in 0..40 {
            // Drain client outputs
            loop {
                match client.poll_output() {
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
}
