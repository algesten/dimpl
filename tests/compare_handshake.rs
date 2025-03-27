mod ossl;

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Instant;

use dimpl::buffer::{Buffer, BufferPool};
use dimpl::incoming::Incoming;
use dimpl::message::{CipherSuite, ContentType, Handshake, MessageType};
use dimpl::{CertVerifier, Client, Config, Output};
use ossl::{DtlsCertOptions, DtlsEvent, OsslDtlsCert, OsslDtlsImpl};

/// A simple data structure to store comparable handshake messages
#[derive(Debug, Clone)]
struct HandshakeInfo {
    msg_type: MessageType,
    message_seq: u16,
    fragment_offset: u32,
    fragment_length: u32,
    total_length: u32,
}

impl HandshakeInfo {
    fn from_handshake(handshake: &Handshake) -> Self {
        HandshakeInfo {
            msg_type: handshake.header.msg_type,
            message_seq: handshake.header.message_seq,
            fragment_offset: handshake.header.fragment_offset,
            fragment_length: handshake.header.fragment_length,
            total_length: handshake.header.length,
        }
    }
}

// Wrapper type for MessageType to allow it to be used as a key in HashMap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MessageTypeWrapper(MessageType);

impl From<MessageType> for MessageTypeWrapper {
    fn from(msg_type: MessageType) -> Self {
        MessageTypeWrapper(msg_type)
    }
}

impl Hash for MessageTypeWrapper {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Use the discriminant value as the hash
        std::mem::discriminant(&self.0).hash(state);
    }
}

/// HandshakeCapture is used to record handshake messages
struct HandshakeCapture {
    messages: HashMap<(MessageTypeWrapper, u16), Vec<HandshakeInfo>>,
    buffer_pool: BufferPool,
    current_cipher_suite: Option<CipherSuite>,
}

impl HandshakeCapture {
    fn new() -> Self {
        HandshakeCapture {
            messages: HashMap::new(),
            buffer_pool: BufferPool::default(),
            current_cipher_suite: None,
        }
    }

    /// Process a DTLS packet and extract handshake messages from it
    fn process_packet(&mut self, packet: &[u8]) {
        // Parse the packet
        let buffer = self.buffer_pool.pop();
        if let Ok(incoming) = Incoming::parse_packet(packet, &mut self.current_cipher_suite, buffer)
        {
            let records = incoming.records();

            // Iterate over records using slice indexing since Records implements Deref to [Record]
            for i in 0..records.len() {
                let record = &records[i];
                if record.record.content_type == ContentType::Handshake {
                    if let Some(handshake) = &record.handshake {
                        // Create a HandshakeInfo and store it
                        let info = HandshakeInfo::from_handshake(handshake);
                        let key = (info.msg_type.into(), info.message_seq);

                        self.messages.entry(key).or_insert_with(Vec::new).push(info);
                    }
                }
            }
        }
    }

    /// Get all the messages in a structured format
    fn get_message_summary(&self) -> Vec<(MessageType, u16, u32)> {
        let mut result = Vec::new();

        for ((msg_type_wrapper, message_seq), fragments) in &self.messages {
            // Sum up fragment lengths to check if we have the whole message
            let total_length = fragments.first().map_or(0, |f| f.total_length);

            // Add to result
            result.push((msg_type_wrapper.0, *message_seq, total_length));
        }

        // Sort by message_seq
        result.sort_by_key(|(_, message_seq, _)| *message_seq);

        result
    }
}

/// Simple certificate verifier that accepts any certificate
struct DummyVerifier;
impl CertVerifier for DummyVerifier {
    fn verify_certificate(&self, _der: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

/// Run a handshake with both OpenSSL client and our client against an OpenSSL server,
/// then compare the handshake messages.
#[test]
fn compare_handshake_messages() {
    // Generate certificates
    let server_cert_options = DtlsCertOptions::default();
    let server_cert = OsslDtlsCert::new(server_cert_options);

    let client_cert_options1 = DtlsCertOptions::default();
    let client_cert1 = OsslDtlsCert::new(client_cert_options1);

    let client_cert_options2 = DtlsCertOptions::default();
    let client_cert2 = OsslDtlsCert::new(client_cert_options2);

    // Create OpenSSL server
    let mut server = server_cert
        .new_dtls_impl()
        .expect("Failed to create DTLS server");

    // Set server as passive (accepting connections)
    server.set_active(false);

    // Create OpenSSL client
    let mut openssl_client = client_cert1
        .new_dtls_impl()
        .expect("Failed to create OpenSSL client");

    // Set client as active (initiating connections)
    openssl_client.set_active(true);

    // Create our DTLS client
    let now = Instant::now();
    let config = Arc::new(Config::default());

    // Get client certificate as DER encoded bytes for our client
    let client_x509_der = client_cert2
        .x509
        .to_der()
        .expect("Failed to get client cert DER");
    let client_pkey_der = client_cert2
        .pkey
        .private_key_to_der()
        .expect("Failed to get client private key DER");

    let mut our_client = Client::new(
        now,
        config,
        client_x509_der,
        client_pkey_der,
        Box::new(DummyVerifier),
    );

    // Create handshake capture systems
    let mut openssl_server_from_openssl_client = HandshakeCapture::new();
    let mut openssl_server_from_our_client = HandshakeCapture::new();
    let mut openssl_client_capture = HandshakeCapture::new();
    let mut our_client_capture = HandshakeCapture::new();

    // Collection for server events
    let mut server_events_from_openssl = VecDeque::new();
    let mut server_events_from_our_client = VecDeque::new();

    // Run the handshake for OpenSSL client and server
    println!("Running OpenSSL client handshake with OpenSSL server...");
    run_openssl_handshake(
        &mut openssl_client,
        &mut server,
        &mut openssl_client_capture,
        &mut openssl_server_from_openssl_client,
        &mut server_events_from_openssl,
    );

    // Reset the server for our client
    let server = server_cert
        .new_dtls_impl()
        .expect("Failed to create fresh DTLS server");
    let mut server = server;
    server.set_active(false);

    // Run the handshake for our client and OpenSSL server
    println!("Running our client handshake with OpenSSL server...");
    run_our_handshake(
        &mut our_client,
        &mut server,
        &mut our_client_capture,
        &mut openssl_server_from_our_client,
        &mut server_events_from_our_client,
    );

    // Verify both handshakes completed successfully
    assert!(
        server_events_from_openssl
            .iter()
            .any(|e| matches!(e, DtlsEvent::Connected)),
        "OpenSSL handshake didn't complete"
    );
    assert!(
        server_events_from_our_client
            .iter()
            .any(|e| matches!(e, DtlsEvent::Connected)),
        "Our handshake didn't complete"
    );

    // Compare handshake messages
    let openssl_msgs = openssl_client_capture.get_message_summary();
    let our_msgs = our_client_capture.get_message_summary();

    // Print out the message sequences for debugging
    println!("OpenSSL client handshake messages:");
    for (msg_type, seq, len) in &openssl_msgs {
        println!("  {:?} (seq: {}, len: {})", msg_type, seq, len);
    }

    println!("Our client handshake messages:");
    for (msg_type, seq, len) in &our_msgs {
        println!("  {:?} (seq: {}, len: {})", msg_type, seq, len);
    }

    // Compare the message types and sequence
    assert_eq!(
        openssl_msgs.len(),
        our_msgs.len(),
        "Different number of handshake messages: OpenSSL: {}, Ours: {}",
        openssl_msgs.len(),
        our_msgs.len()
    );

    // Check that the message types match in order
    let openssl_types: Vec<MessageType> = openssl_msgs.iter().map(|(ty, _, _)| *ty).collect();
    let our_types: Vec<MessageType> = our_msgs.iter().map(|(ty, _, _)| *ty).collect();

    assert_eq!(
        openssl_types, our_types,
        "Handshake message types don't match"
    );

    // Compare server-side views
    let server_view_openssl = openssl_server_from_openssl_client.get_message_summary();
    let server_view_our = openssl_server_from_our_client.get_message_summary();

    println!("Server view of OpenSSL client messages:");
    for (msg_type, seq, len) in &server_view_openssl {
        println!("  {:?} (seq: {}, len: {})", msg_type, seq, len);
    }

    println!("Server view of our client messages:");
    for (msg_type, seq, len) in &server_view_our {
        println!("  {:?} (seq: {}, len: {})", msg_type, seq, len);
    }

    // Check that the server-side message types match
    let server_view_openssl_types: Vec<MessageType> =
        server_view_openssl.iter().map(|(ty, _, _)| *ty).collect();
    let server_view_our_types: Vec<MessageType> =
        server_view_our.iter().map(|(ty, _, _)| *ty).collect();

    assert_eq!(
        server_view_openssl_types, server_view_our_types,
        "Server-side handshake message types don't match"
    );
}

/// Run a handshake between an OpenSSL client and server
fn run_openssl_handshake(
    openssl_client: &mut OsslDtlsImpl,
    server: &mut OsslDtlsImpl,
    client_capture: &mut HandshakeCapture,
    server_capture: &mut HandshakeCapture,
    server_events: &mut VecDeque<DtlsEvent>,
) {
    let mut handshake_complete = false;

    // Run until handshake is complete
    for _ in 0..20 {
        // Poll client for packets
        while let Some(datagram) = openssl_client.poll_datagram() {
            // Capture client's outgoing packets
            client_capture.process_packet(&datagram);

            // Send to server
            if let Err(e) = server.handle_receive(&datagram, server_events) {
                panic!("Server failed to handle client packet: {:?}", e);
            }
        }

        // Poll server for packets
        while let Some(datagram) = server.poll_datagram() {
            // Capture server's outgoing packets
            server_capture.process_packet(&datagram);

            // Send to client
            let mut client_events = VecDeque::new();
            if let Err(e) = openssl_client.handle_receive(&datagram, &mut client_events) {
                panic!("Client failed to handle server packet: {:?}", e);
            }

            // Check if handshake is complete
            if client_events
                .iter()
                .any(|e| matches!(e, DtlsEvent::Connected))
            {
                handshake_complete = true;
            }
        }

        // Check if server is connected
        if server_events
            .iter()
            .any(|e| matches!(e, DtlsEvent::Connected))
        {
            handshake_complete = true;
        }

        if handshake_complete {
            break;
        }
    }

    assert!(handshake_complete, "OpenSSL handshake didn't complete");
}

/// Run a handshake between our client and an OpenSSL server
fn run_our_handshake(
    our_client: &mut Client,
    server: &mut OsslDtlsImpl,
    client_capture: &mut HandshakeCapture,
    server_capture: &mut HandshakeCapture,
    server_events: &mut VecDeque<DtlsEvent>,
) {
    let mut handshake_complete = false;

    // Run until handshake is complete
    for _ in 0..20 {
        // Poll client for output
        let mut continue_polling = true;
        while continue_polling {
            let output = our_client.poll_output();
            match output {
                Output::Packet(data) => {
                    // Capture client's outgoing packets
                    client_capture.process_packet(data);

                    // Send to server
                    if let Err(e) = server.handle_receive(data, server_events) {
                        panic!("Server failed to handle our client packet: {:?}", e);
                    }
                }
                Output::Connected => {
                    handshake_complete = true;
                }
                Output::Timeout(_) => {
                    continue_polling = false;
                }
                _ => {} // Ignore other outputs
            }
        }

        // Poll server for packets
        while let Some(datagram) = server.poll_datagram() {
            // Capture server's outgoing packets
            server_capture.process_packet(&datagram);

            // Send to client
            if let Err(e) = our_client.handle_packet(&datagram) {
                panic!("Our client failed to handle server packet: {:?}", e);
            }
        }

        // Check if server is connected
        if server_events
            .iter()
            .any(|e| matches!(e, DtlsEvent::Connected))
        {
            handshake_complete = true;
        }

        if handshake_complete {
            break;
        }
    }

    assert!(handshake_complete, "Our handshake didn't complete");
}
