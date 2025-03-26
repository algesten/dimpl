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
// This implementation is a Sans-IO DTLS 1.2 client.

use std::sync::Arc;
use std::time::Instant;

use tinyvec::array_vec;

use crate::crypto::{CertVerifier, CryptoContext};
use crate::engine::Engine;
use crate::message::{
    Body, Certificate, CertificateRequest, CipherSuite, ClientDiffieHellmanPublic, ClientHello,
    ClientKeyExchange, CompressionMethod, ContentType, Cookie, ExchangeKeys, Finished, MessageType,
    ProtocolVersion, PublicValueEncoding, Random, ServerKeyExchange, SessionId,
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
    _certificate_request: Option<CertificateRequest<'static>>,

    /// Server certificates
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
    /// Create a new DTLS client
    ///
    /// # Parameters
    ///
    /// * `now` - Current timestamp for random generation
    /// * `config` - DTLS configuration
    /// * `certificate` - Client certificate, create one with `generate_self_signed_certificate()`
    /// * `cert_verifier` - Certificate verifier for validating server certificates
    pub fn new(
        now: Instant,
        config: Arc<Config>,
        certificate: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
    ) -> Client {
        Client {
            random: Random::new(now),
            session_id: None,
            cookie: None,
            cipher_suite: None,
            state: ClientState::SendClientHello,
            engine: Engine::new(config),
            server_random: None,
            crypto_context: CryptoContext::new(certificate, cert_verifier),
            certificate_requested: false,
            _certificate_request: None,
            server_certificates: Vec::new(),
        }
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
                                    // unwrap is safe because we just set the cipher suite
                                    let cs = self.cipher_suite.unwrap();
                                    self.crypto_context.init_key_exchange(cs).map_err(|e| {
                                        Error::CryptoError(format!(
                                            "Failed to initialize key exchange: {}",
                                            e
                                        ))
                                    })?;
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
                                if let Body::ServerKeyExchange(server_key_exchange) =
                                    &handshake.body
                                {
                                    // Process the server key exchange message
                                    self.crypto_context
                                        .process_server_key_exchange(server_key_exchange)
                                        .map_err(|e| {
                                            Error::CryptoError(format!(
                                                "Failed to process server key exchange: {}",
                                                e
                                            ))
                                        })?;
                                }
                            }
                            MessageType::CertificateRequest => {
                                // Server requests client certificate
                                self.certificate_requested = true;
                            }
                            MessageType::ServerHelloDone => {
                                // Server is done sending initial messages

                                // Validate the server certificate
                                if self.server_certificates.is_empty() {
                                    return Err(Error::CertificateError(
                                        "No server certificate received".to_string(),
                                    ));
                                }

                                // Verify the certificate using the configured verifier
                                if let Err(err) = self
                                    .crypto_context
                                    .verify_server_certificate(&self.server_certificates[0])
                                {
                                    return Err(Error::CertificateError(format!(
                                        "Certificate verification failed: {}",
                                        err
                                    )));
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
            // Check if we have a client certificate
            if let Some(client_cert) = self.crypto_context.get_client_certificate() {
                self.engine
                    .create_handshake(MessageType::Certificate, 0, |body| {
                        client_cert.serialize(body);
                    })?;
            } else {
                // If we don't have a certificate, send empty list
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
            ));
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
}
