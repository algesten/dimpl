// DTLS Client Handshake Flow:
//
// 1. Client sends ClientHello
// 2. Server may respond with HelloVerifyRequest containing a cookie
//    - If so, Client sends another ClientHello with the cookie
// 3. Server sends ServerHello, Certificate, ServerKeyExchange,
//    CertificateRequest (optional), ServerHelloDone
// 4. Client sends Certificate (if requested), ClientKeyExchange,
//    CertificateVerify (if client cert present), ChangeCipherSpec, Finished
// 5. Server sends ChangeCipherSpec, Finished
// 6. Handshake complete, application data can flow
//
// This implementation is a Sans-IO DTLS 1.2 client for WebRTC.
// It uses self-signed certificates and fingerprint verification.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

use tinyvec::array_vec;

use crate::crypto::CryptoContext;
use crate::engine::Engine;
use crate::incoming::{Incoming, Record};
use crate::message::{
    Body, Certificate, CertificateRequest, CipherSuite, ClientDiffieHellmanPublic, ClientHello,
    ClientKeyExchange, CompressionMethod, ContentType, Cookie, ExchangeKeys, Finished, MessageType,
    ProtocolVersion, PublicValueEncoding, Random, SessionId,
};
use crate::{Config, Error, Output};

pub struct Client {
    /// Random unique data (with gmt timestamp). Used for signature checks.
    random: Random,

    /// SessionId is set by the server and only sent by the client if we
    /// are reusing a session (key renegotiation).
    session_id: Option<SessionId>,

    /// Cookie is sent by the server in the optional HelloVerifyRequest.
    /// It might remain null if there is no HelloVerifyRequest.
    cookie: Option<Cookie>,

    /// The cipher suites in use. Set by ServerHello.
    cipher_suite: Option<CipherSuite>,

    /// Current client state.
    state: ClientState,

    /// Engine in common between server and client.
    engine: Engine,

    /// Server random. Set by ServerHello.
    server_random: Option<Random>,

    /// Cryptographic context
    crypto_context: CryptoContext,

    /// Flag indicating if the client certificate was requested
    certificate_requested: bool,

    /// Certificate request details (for client auth)
    certificate_request: Option<CertificateRequest<'static>>,

    /// Server hostname (for certificate validation)
    hostname: String,

    /// Server certificate chain
    server_certificates: Vec<Vec<u8>>,
}

/// Current state of the client.
#[derive(Debug)]
pub enum ClientState {
    /// Send the ClientHello
    SendClientHello,

    /// Waiting for a ServerHello, or maybe a HelloVerifyRequest
    ///
    /// Wait until we see ServerHelloDone.
    AwaitServerHello { can_hello_verify: bool },

    /// Send the client certificate and keys.
    ///
    /// All the messages up to Finished.
    SendClientCertAndKeys,

    /// Await server message until Finished.
    AwaitServerFinished,

    /// Send and receive encrypted data.
    Running,
}

impl Client {
    pub fn new(now: Instant, config: Arc<Config>) -> Client {
        // Create client with default values
        let mut client = Client {
            random: Random::new(now),
            session_id: None,
            cookie: None,
            cipher_suite: None,
            state: ClientState::SendClientHello,
            engine: Engine::new(config),
            server_random: None,
            crypto_context: CryptoContext::new(),
            certificate_requested: false,
            certificate_request: None,
            hostname: String::new(),
            server_certificates: Vec::new(),
        };

        // Generate a self-signed certificate for the client
        // This ensures we always have a certificate for WebRTC
        if let Ok(_) = client
            .crypto_context
            .trust_store_mut()
            .generate_self_signed_certificate()
        {
            // Certificate generated successfully
        }

        client
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.engine.parse_packet(packet, &mut self.cipher_suite)?;
        self.process_input()?;
        Ok(())
    }

    pub fn poll_output(&mut self) -> Output {
        self.engine.poll_output()
    }

    fn process_input(&mut self) -> Result<(), Error> {
        match self.state {
            ClientState::SendClientHello => {
                self.send_client_hello()?;
                self.state = ClientState::AwaitServerHello {
                    can_hello_verify: true,
                };
                Ok(())
            }
            ClientState::AwaitServerHello { can_hello_verify } => {
                self.process_server_hello(can_hello_verify)?;
                Ok(())
            }
            ClientState::SendClientCertAndKeys => {
                self.send_client_cert_and_keys()?;
                self.state = ClientState::AwaitServerFinished;
                Ok(())
            }
            ClientState::AwaitServerFinished => {
                self.process_server_finished()?;
                Ok(())
            }
            ClientState::Running => {
                // Just keep the connection running
                Ok(())
            }
        }
    }

    fn send_client_hello(&mut self) -> Result<(), Error> {
        // Prepare a ClientHello message
        let client_version = ProtocolVersion::DTLS1_2;
        let session_id = self
            .session_id
            .clone()
            .unwrap_or_else(|| SessionId::empty());
        let cookie = self.cookie.clone().unwrap_or_else(|| Cookie::empty());
        let cipher_suites = CipherSuite::all();
        let compression_methods = array_vec![[CompressionMethod; 4] => CompressionMethod::Null];

        let client_hello = ClientHello::new(
            client_version,
            self.random.clone(),
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
        );

        // Create and send the ClientHello message
        self.engine
            .create_handshake(MessageType::ClientHello, 0, |body| {
                client_hello.serialize(body);
            })?;

        Ok(())
    }

    fn process_server_hello(&mut self, can_hello_verify: bool) -> Result<(), Error> {
        // Extract messages from the engine queue
        while self.engine.has_incoming() {
            if let Some(incoming) = self.engine.next_incoming() {
                // Get the slice of records
                let records = incoming.records();

                // Iterate through each record in the slice
                for i in 0..records.len() {
                    let record = &records[i];

                    if let Some(handshake) = &record.handshake {
                        match handshake.header.msg_type {
                            MessageType::HelloVerifyRequest => {
                                if !can_hello_verify {
                                    return Err(Error::UnexpectedMessage(
                                        "Unexpected HelloVerifyRequest".to_string(),
                                    ));
                                }

                                // Extract the cookie from the HelloVerifyRequest
                                if let Body::HelloVerifyRequest(hello_verify) = &handshake.body {
                                    self.cookie = Some(hello_verify.cookie.clone());

                                    // Reset state to send ClientHello again, but with the cookie
                                    self.state = ClientState::SendClientHello;
                                    return Ok(());
                                }
                            }
                            MessageType::ServerHello => {
                                // Extract information from ServerHello
                                if let Body::ServerHello(server_hello) = &handshake.body {
                                    self.cipher_suite = Some(server_hello.cipher_suite);
                                    self.session_id = Some(server_hello.session_id.clone());
                                    self.server_random = Some(server_hello.random.clone());

                                    // Initialize the key exchange based on selected cipher suite
                                    if let Some(cs) = self.cipher_suite {
                                        self.crypto_context.init_key_exchange(cs).map_err(|e| {
                                            Error::CryptoError(format!(
                                                "Failed to initialize key exchange: {}",
                                                e
                                            ))
                                        })?;
                                    }
                                }
                            }
                            MessageType::Certificate => {
                                // Process server certificate
                                if let Body::Certificate(certificate) = &handshake.body {
                                    // Store the certificate chain for validation
                                    self.server_certificates.clear();

                                    // Convert ASN.1 certificates to byte arrays
                                    for cert in &certificate.certificate_list {
                                        self.server_certificates.push(cert.0.to_vec());
                                    }
                                }
                            }
                            MessageType::ServerKeyExchange => {
                                // Process server key exchange parameters
                                // In a real implementation, we would extract key exchange parameters
                                // from the server's key exchange message
                            }
                            MessageType::CertificateRequest => {
                                // Server requests client certificate
                                self.certificate_requested = true;
                            }
                            MessageType::ServerHelloDone => {
                                // Server is done sending initial messages

                                // Validate the server certificate if we have one
                                if !self.server_certificates.is_empty() && !self.hostname.is_empty()
                                {
                                    // Convert certificates to the format needed for verification
                                    let cert_refs: Vec<&[u8]> = self
                                        .server_certificates
                                        .iter()
                                        .map(|cert| cert.as_slice())
                                        .collect();

                                    // Verify the certificate chain (which for WebRTC just checks fingerprint)
                                    if let Err(err) = self
                                        .crypto_context
                                        .verify_server_cert_chain(&cert_refs, &self.hostname)
                                    {
                                        return Err(Error::CertificateError(format!(
                                            "Certificate verification failed: {}",
                                            err
                                        )));
                                    }
                                }

                                // Transition to next state
                                self.state = ClientState::SendClientCertAndKeys;
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // No state transition yet, continue waiting for more messages
        Ok(())
    }

    fn send_client_cert_and_keys(&mut self) -> Result<(), Error> {
        // Send client certificate if requested by server
        if self.certificate_requested {
            // In WebRTC, we always send our self-signed certificate
            if let Some(client_cert) = self.crypto_context.get_client_certificate() {
                self.engine
                    .create_handshake(MessageType::Certificate, 0, |body| {
                        client_cert.serialize(body);
                    })?;
            } else {
                // If we don't have a certificate (which shouldn't happen), send empty list
                // Create an empty certificate with proper initialization
                let empty_cert_list = array_vec![[crate::message::Asn1Cert<'_>; 32]];
                let empty_cert = Certificate::new(empty_cert_list);
                self.engine
                    .create_handshake(MessageType::Certificate, 0, |body| {
                        empty_cert.serialize(body);
                    })?;
            }
        }

        // Send client key exchange message
        if let Some(cipher_suite) = self.cipher_suite {
            // Generate key exchange data
            let public_key = self.crypto_context.generate_key_exchange().map_err(|e| {
                Error::CryptoError(format!("Failed to generate key exchange: {}", e))
            })?;

            // Send client key exchange message
            self.engine
                .create_handshake(MessageType::ClientKeyExchange, 1, |body| {
                    // Create a properly formatted ClientKeyExchange message
                    // First create a ClientDiffieHellmanPublic with the correct encoding
                    let dh_public =
                        ClientDiffieHellmanPublic::new(PublicValueEncoding::Explicit, &public_key);

                    // Then wrap it in ExchangeKeys and ClientKeyExchange
                    let client_key_exchange =
                        ClientKeyExchange::new(ExchangeKeys::DhAnon(dh_public));

                    // Serialize the fully structured message
                    client_key_exchange.serialize(body);
                })?;

            // Send CertificateVerify if we sent a client certificate
            if self.certificate_requested && self.crypto_context.has_client_certificate() {
                // In a real implementation, we would:
                // 1. Create a signature over all handshake messages
                // 2. Send the signature in a CertificateVerify message
                // This is not implemented in this simplified version
            }

            // Derive keys
            if let Some(server_random) = &self.server_random {
                // Extract and format the random values for key derivation
                let mut client_random = Vec::with_capacity(32);
                let mut server_random_vec = Vec::with_capacity(32);

                // Serialize the random values to raw bytes
                self.random.serialize(&mut client_random);
                server_random.serialize(&mut server_random_vec);

                // Derive master secret
                self.crypto_context
                    .derive_master_secret(&client_random, &server_random_vec)
                    .map_err(|e| {
                        Error::CryptoError(format!("Failed to derive master secret: {}", e))
                    })?;

                // Derive the encryption/decryption keys
                self.crypto_context
                    .derive_keys(cipher_suite, &client_random, &server_random_vec)
                    .map_err(|e| Error::CryptoError(format!("Failed to derive keys: {}", e)))?;
            }

            // Send change cipher spec
            self.engine
                .create_record(ContentType::ChangeCipherSpec, |body| {
                    // Change cipher spec is just a single byte with value 1
                    body.push(1);
                })?;

            // Calculate verify data for Finished message
            // In a real implementation, this would use all handshake messages
            let verify_data = [0u8; 12]; // Placeholder

            // Send finished message
            let finished = Finished::new(&verify_data);
            self.engine
                .create_handshake(MessageType::Finished, 2, |body| {
                    finished.serialize(body);
                })?;
        } else {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            )); // No cipher suite selected
        }

        Ok(())
    }

    fn process_server_finished(&mut self) -> Result<(), Error> {
        // Wait for server change cipher spec and finished messages
        while self.engine.has_incoming() {
            if let Some(incoming) = self.engine.next_incoming() {
                // Get the slice of records
                let records = incoming.records();

                // Iterate through each record in the slice
                for i in 0..records.len() {
                    let record = &records[i];

                    match record.record.content_type {
                        ContentType::ChangeCipherSpec => {
                            // Server changed encryption state
                            // In a real implementation, we would update our state to use encryption
                        }
                        ContentType::Handshake => {
                            if let Some(handshake) = &record.handshake {
                                if handshake.header.msg_type == MessageType::Finished {
                                    // Verify server finished message
                                    // In a real implementation, we would verify the server's verify_data

                                    // Handshake is complete
                                    self.state = ClientState::Running;
                                    return Ok(());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Continue waiting for server finished
        Ok(())
    }

    /// Send application data when the client is in the Running state
    ///
    /// This should only be called when the client is in the Running state,
    /// after the handshake is complete.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.state {
            ClientState::Running => {
                // Generate a secure random nonce from the client cipher
                let nonce = self
                    .crypto_context
                    .generate_client_nonce()
                    .map_err(|e| Error::CryptoError(format!("Failed to generate nonce: {}", e)))?;

                // Prepare AAD (Additional Authenticated Data)
                // For DTLS, this would typically include parts of the record header
                let aad = Vec::new(); // Using an empty AAD for simplicity

                // Encrypt the data using the established crypto context
                let encrypted = self
                    .crypto_context
                    .encrypt_client_to_server(data, &aad, &nonce)
                    .map_err(|e| Error::CryptoError(format!("Encryption failed: {}", e)))?;

                // Send the encrypted data in an ApplicationData record
                self.engine
                    .create_record(ContentType::ApplicationData, |body| {
                        body.extend_from_slice(&encrypted);
                    })?;

                Ok(())
            }
            _ => Err(Error::UnexpectedMessage("Not in Running state".to_string())),
        }
    }

    /// Set the hostname for certificate validation
    pub fn set_hostname(&mut self, hostname: &str) {
        self.hostname = hostname.to_string();
    }

    /// Set the expected fingerprint for the remote peer
    /// This is critical for WebRTC security
    pub fn set_remote_fingerprint(&mut self, fingerprint: Vec<u8>) {
        if !self.hostname.is_empty() {
            self.crypto_context
                .trust_store_mut()
                .add_trusted_fingerprint(&self.hostname, fingerprint);
        }
    }

    /// Get the fingerprint of our local certificate
    /// This should be shared with the remote peer through the signaling channel
    pub fn get_local_fingerprint(&self) -> Option<Vec<u8>> {
        if self.crypto_context.trust_store().has_client_certificate() {
            // Get the client certificate from the trust store
            if let Some(cert) = self.crypto_context.trust_store().get_client_certificate() {
                if !cert.certificate_list.is_empty() {
                    let cert_bytes = cert.certificate_list[0].0;
                    return Some(crate::crypto::calculate_fingerprint(cert_bytes));
                }
            }
        }
        None
    }

    /// Get the fingerprint of our local certificate as a formatted string
    /// Returns the SHA-256 fingerprint in WebRTC's standard colon-separated hex format
    /// Example: "SHA-256 AF:12:F6:..."
    pub fn get_formatted_fingerprint(&self) -> Option<String> {
        self.get_local_fingerprint()
            .map(|fp| format!("SHA-256 {}", crate::crypto::format_fingerprint(&fp)))
    }

    /// Generate a new self-signed certificate for this client
    /// Returns the SHA-256 fingerprint of the certificate
    pub fn generate_certificate(&mut self) -> Result<Vec<u8>, crate::Error> {
        self.crypto_context
            .trust_store_mut()
            .generate_self_signed_certificate()
            .map_err(|e| {
                crate::Error::CertificateError(format!("Failed to generate certificate: {:?}", e))
            })
    }

    /// Get a mutable reference to the crypto context
    pub fn crypto_context_mut(&mut self) -> &mut CryptoContext {
        &mut self.crypto_context
    }
}
