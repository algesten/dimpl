//! DTLS 1.2 handshake tests (cookie retry, parallel handshakes).

mod dtls12_common;

use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls};
use dtls12_common::*;

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_cookie_retry_proceeds_to_server_hello() {
    //! Verify that after HelloVerifyRequest, the ClientHello with cookie
    //! is properly processed and the server sends ServerHello (not another HVR).

    use dimpl::certificate::generate_self_signed_certificate;

    let now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(Config::builder().build().expect("Failed to build config"));

    let mut client = Dtls::new_12(config.clone(), client_cert.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12(config.clone(), server_cert.clone(), now);
    server.set_active(false);

    // FLIGHT 1: Client sends ClientHello (no cookie)
    client.handle_timeout(now).expect("client timeout start");
    client.handle_timeout(now).expect("client arm flight 1");
    let f1 = collect_packets(&mut client);
    assert!(!f1.is_empty(), "client should emit ClientHello");

    // Verify it's a ClientHello
    let f1_hs_types: Vec<u8> = f1.iter().flat_map(|p| parse_handshake_types(p)).collect();
    assert!(
        f1_hs_types.contains(&CLIENT_HELLO),
        "flight 1 should contain ClientHello, got {:?}",
        f1_hs_types
    );

    // Deliver to server
    for p in &f1 {
        server.handle_packet(p).expect("server recv f1");
    }

    // FLIGHT 2: Server sends HelloVerifyRequest
    server.handle_timeout(now).expect("server arm flight 2");
    let f2 = collect_packets(&mut server);
    assert!(!f2.is_empty(), "server should emit HelloVerifyRequest");

    // Verify it's a HelloVerifyRequest
    let f2_hs_types: Vec<u8> = f2.iter().flat_map(|p| parse_handshake_types(p)).collect();
    assert!(
        f2_hs_types.contains(&HELLO_VERIFY_REQUEST),
        "flight 2 should contain HelloVerifyRequest, got {:?}",
        f2_hs_types
    );

    // Deliver to client
    for p in &f2 {
        client.handle_packet(p).expect("client recv f2");
    }

    // FLIGHT 3: Client sends ClientHello WITH cookie (message_seq=1 per RFC 6347)
    client.handle_timeout(now).expect("client arm flight 3");
    let f3 = collect_packets(&mut client);
    assert!(!f3.is_empty(), "client should emit ClientHello with cookie");

    let f3_hs_types: Vec<u8> = f3.iter().flat_map(|p| parse_handshake_types(p)).collect();
    assert!(
        f3_hs_types.contains(&CLIENT_HELLO),
        "flight 3 should contain ClientHello (with cookie), got {:?}",
        f3_hs_types
    );

    // Deliver to server - THIS IS WHERE THE BUG MANIFESTS
    for p in &f3 {
        server.handle_packet(p).expect("server recv f3");
    }

    // FLIGHT 4: Server should send ServerHello, Certificate, etc. - NOT HelloVerifyRequest
    server.handle_timeout(now).expect("server arm flight 4");
    let f4 = collect_packets(&mut server);
    assert!(
        !f4.is_empty(),
        "server should emit flight 4 after ClientHello with cookie"
    );

    let f4_hs_types: Vec<u8> = f4.iter().flat_map(|p| parse_handshake_types(p)).collect();

    // THE KEY ASSERTION: Server should NOT send another HelloVerifyRequest
    assert!(
        !f4_hs_types.contains(&HELLO_VERIFY_REQUEST),
        "server should NOT send HelloVerifyRequest after valid cookie - BUG! got {:?}",
        f4_hs_types
    );

    // Server should send ServerHello
    assert!(
        f4_hs_types.contains(&SERVER_HELLO),
        "server should send ServerHello after valid cookie, got {:?}",
        f4_hs_types
    );

    // Should also contain Certificate and ServerHelloDone
    assert!(
        f4_hs_types.contains(&CERTIFICATE),
        "server should send Certificate, got {:?}",
        f4_hs_types
    );
    assert!(
        f4_hs_types.contains(&SERVER_HELLO_DONE),
        "server should send ServerHelloDone, got {:?}",
        f4_hs_types
    );

    println!(
        "SUCCESS: Server correctly processed ClientHello with cookie and sent ServerHello flight"
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_parallel_handshakes_with_cookies() {
    //! Test multiple parallel DTLS handshakes to ensure cookie handling
    //! works correctly under concurrent load (the original bug scenario).

    use dimpl::certificate::generate_self_signed_certificate;

    let now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(Config::builder().build().expect("Failed to build config"));

    // Create 5 parallel client-server pairs
    let mut pairs: Vec<(Dtls, Dtls)> = (0..5)
        .map(|_| {
            let mut client = Dtls::new_12(config.clone(), client_cert.clone(), now);
            client.set_active(true);
            let mut server = Dtls::new_12(config.clone(), server_cert.clone(), now);
            server.set_active(false);
            (client, server)
        })
        .collect();

    // Run all handshakes through the cookie exchange phase
    for (i, (client, server)) in pairs.iter_mut().enumerate() {
        // Flight 1: ClientHello
        client.handle_timeout(now).expect("client timeout");
        client.handle_timeout(now).expect("client arm f1");
        let f1 = collect_packets(client);
        for p in &f1 {
            server.handle_packet(p).expect("server recv f1");
        }

        // Flight 2: HelloVerifyRequest
        server.handle_timeout(now).expect("server arm f2");
        let f2 = collect_packets(server);
        for p in &f2 {
            client.handle_packet(p).expect("client recv f2");
        }

        // Flight 3: ClientHello with cookie
        client.handle_timeout(now).expect("client arm f3");
        let f3 = collect_packets(client);
        for p in &f3 {
            server.handle_packet(p).expect("server recv f3");
        }

        // Flight 4: Should be ServerHello, not HelloVerifyRequest
        server.handle_timeout(now).expect("server arm f4");
        let f4 = collect_packets(server);
        let f4_hs_types: Vec<u8> = f4.iter().flat_map(|p| parse_handshake_types(p)).collect();

        assert!(
            !f4_hs_types.contains(&HELLO_VERIFY_REQUEST),
            "pair {}: server sent HelloVerifyRequest instead of ServerHello - BUG!",
            i
        );
        assert!(
            f4_hs_types.contains(&SERVER_HELLO),
            "pair {}: server should send ServerHello, got {:?}",
            i,
            f4_hs_types
        );
    }

    println!(
        "SUCCESS: All {} parallel handshakes processed cookies correctly",
        pairs.len()
    );
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_retransmit_no_cookie_after_cookie_sent() {
    //! Simulates the real Firefox bug scenario:
    //! 1. Client sends ClientHello (no cookie)
    //! 2. Server sends HelloVerifyRequest
    //! 3. Client sends ClientHello (with cookie)
    //! 4. Client's timer fires and it ALSO retransmits the original no-cookie ClientHello
    //! 5. Server should NOT get confused by this out-of-order retransmit

    use dimpl::certificate::generate_self_signed_certificate;

    let now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(Config::builder().build().expect("Failed to build config"));

    let mut client = Dtls::new_12(config.clone(), client_cert.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12(config.clone(), server_cert.clone(), now);
    server.set_active(false);

    // Flight 1: ClientHello (no cookie)
    client.handle_timeout(now).expect("client timeout");
    client.handle_timeout(now).expect("client arm f1");
    let f1 = collect_packets(&mut client);
    assert!(!f1.is_empty());

    // Save a copy of the original no-cookie ClientHello for later retransmit
    let f1_copy = f1.clone();

    // Deliver to server
    for p in &f1 {
        server.handle_packet(p).expect("server recv f1");
    }

    // Flight 2: HelloVerifyRequest
    server.handle_timeout(now).expect("server arm f2");
    let f2 = collect_packets(&mut server);
    assert!(!f2.is_empty());

    // Deliver to client
    for p in &f2 {
        client.handle_packet(p).expect("client recv f2");
    }

    // Flight 3: ClientHello WITH cookie
    client.handle_timeout(now).expect("client arm f3");
    let f3 = collect_packets(&mut client);
    assert!(!f3.is_empty());

    // Deliver the cookie version to server
    for p in &f3 {
        server.handle_packet(p).expect("server recv f3 with cookie");
    }

    // NOW simulate Firefox's retransmit timer firing - send the ORIGINAL
    // no-cookie ClientHello again (this is what Firefox does in the real bug)
    for p in &f1_copy {
        // This should not cause the handshake to fail
        server
            .handle_packet(p)
            .expect("server recv retransmit of no-cookie CH");
    }

    // Server should still send ServerHello flight, not another HelloVerifyRequest
    server.handle_timeout(now).expect("server arm f4");
    let f4 = collect_packets(&mut server);
    assert!(!f4.is_empty(), "server should emit flight 4");

    let f4_hs_types: Vec<u8> = f4.iter().flat_map(|p| parse_handshake_types(p)).collect();

    // The key test: even after receiving the retransmitted no-cookie ClientHello,
    // the server should proceed with ServerHello (having already processed the cookie version)
    assert!(
        f4_hs_types.contains(&SERVER_HELLO),
        "server should send ServerHello even after retransmit of no-cookie CH, got {:?}",
        f4_hs_types
    );

    println!("SUCCESS: Server correctly handled out-of-order retransmit scenario");
}

#[test]
#[cfg(feature = "rcgen")]
fn dtls12_retransmit_no_cookie_before_cookie_received() {
    //! Tests the specific bug scenario from webrtc deployments:
    //!
    //! 1. Client sends ClientHello (seq=0, no cookie)
    //! 2. Server sends HelloVerifyRequest, clears queue_rx
    //! 3. Client retransmits old ClientHello (seq=0, no cookie) - HVR was lost/delayed
    //! 4. Server resends HelloVerifyRequest (correct), but OLD ClientHello must NOT
    //!    be inserted into queue_rx, otherwise it blocks the new ClientHello
    //! 5. Client sends ClientHello (seq=1, with cookie)
    //! 6. Server should process it and send ServerHello

    use dimpl::certificate::generate_self_signed_certificate;

    let now = Instant::now();

    let client_cert = generate_self_signed_certificate().expect("gen client cert");
    let server_cert = generate_self_signed_certificate().expect("gen server cert");

    let config = Arc::new(Config::builder().build().expect("Failed to build config"));

    let mut client = Dtls::new_12(config.clone(), client_cert.clone(), now);
    client.set_active(true);

    let mut server = Dtls::new_12(config.clone(), server_cert.clone(), now);
    server.set_active(false);

    // Flight 1: ClientHello (no cookie)
    client.handle_timeout(now).expect("client timeout");
    client.handle_timeout(now).expect("client arm f1");
    let f1 = collect_packets(&mut client);
    assert!(!f1.is_empty());

    // Save a copy of the original no-cookie ClientHello for retransmit simulation
    let f1_copy = f1.clone();

    // Deliver to server
    for p in &f1 {
        server.handle_packet(p).expect("server recv f1");
    }

    // Flight 2: HelloVerifyRequest
    server.handle_timeout(now).expect("server arm f2");
    let f2 = collect_packets(&mut server);
    assert!(!f2.is_empty());

    // Simulate: HVR is "lost" - don't deliver to client yet
    // Instead, client's retransmit timer fires and sends the old ClientHello again

    // THIS IS THE BUG TRIGGER: old ClientHello (seq=0) arrives at server
    // BEFORE the cookie-bearing ClientHello (seq=1)
    for p in &f1_copy {
        server
            .handle_packet(p)
            .expect("server recv retransmit of no-cookie CH");
    }

    // Server should resend HelloVerifyRequest (this is correct behavior)
    // The bug was that the old ClientHello got inserted into queue_rx
    let f2_resend = collect_packets(&mut server);
    let f2_resend_types: Vec<u8> = f2_resend
        .iter()
        .flat_map(|p| parse_handshake_types(p))
        .collect();
    assert!(
        f2_resend_types.contains(&HELLO_VERIFY_REQUEST),
        "server should resend HelloVerifyRequest after duplicate, got {:?}",
        f2_resend_types
    );

    // Now deliver the original HVR to client
    for p in &f2 {
        client.handle_packet(p).expect("client recv f2");
    }

    // Flight 3: ClientHello WITH cookie (seq=1)
    client.handle_timeout(now).expect("client arm f3");
    let f3 = collect_packets(&mut client);
    assert!(!f3.is_empty());

    // Deliver to server - THIS IS WHERE THE BUG MANIFESTED
    // Before fix: queue_rx had old ClientHello (seq=0), blocking this one
    for p in &f3 {
        server.handle_packet(p).expect("server recv f3 with cookie");
    }

    // Server should now send ServerHello flight
    server.handle_timeout(now).expect("server arm f4");
    let f4 = collect_packets(&mut server);
    assert!(!f4.is_empty(), "server should emit flight 4");

    let f4_hs_types: Vec<u8> = f4.iter().flat_map(|p| parse_handshake_types(p)).collect();

    // THE KEY ASSERTION: Server must NOT be stuck sending HelloVerifyRequest
    assert!(
        !f4_hs_types.contains(&HELLO_VERIFY_REQUEST),
        "server should NOT resend HelloVerifyRequest after valid cookie, got {:?}",
        f4_hs_types
    );

    // Server should send ServerHello
    assert!(
        f4_hs_types.contains(&SERVER_HELLO),
        "server should send ServerHello after cookie CH, got {:?}",
        f4_hs_types
    );

    println!("SUCCESS: Old duplicate ClientHello did not block new ClientHello with cookie");
}
