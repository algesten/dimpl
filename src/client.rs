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

use crate::crypto::CertVerifier;
use crate::engine::Engine;
use crate::message::{
    Body, Certificate, CertificateRequest, CertificateVerify, CipherSuite,
    ClientDiffieHellmanPublic, ClientHello, ClientKeyExchange, CompressionMethod, ContentType,
    Cookie, DigitallySigned, ExchangeKeys, Finished, MessageType, ProtocolVersion,
    PublicValueEncoding, Random, SessionId,
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

    /// Flag indicating if the client certificate was requested
    certificate_requested: bool,

    /// Certificate request details (for client auth)
    _certificate_request: Option<CertificateRequest<'static>>,

    /// Server certificates
    server_certificates: Vec<Vec<u8>>,

    /// Server encryption enabled flag - set when server ChangeCipherSpec is received
    server_encryption_enabled: bool,
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
        let engine = Engine::new(config, certificate, cert_verifier, true);

        Client {
            random: Random::new(now),
            session_id: None,
            cookie: None,
            cipher_suite: None,
            state: ClientState::SendClientHello,
            engine,
            server_random: None,
            certificate_requested: false,
            _certificate_request: None,
            server_certificates: Vec::new(),
            server_encryption_enabled: false,
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
                self.process_server_hello(can_hello_verify)
            }
            ClientState::SendClientCertAndKeys => {
                self.send_client_cert_and_keys()?;
                self.state = ClientState::AwaitServerFinished;
                Ok(())
            }
            ClientState::AwaitServerFinished => self.process_server_finished(),
            ClientState::Running => {
                // Just keep the connection running
                Ok(())
            }
        }
    }

    fn send_client_hello(&mut self) -> Result<(), Error> {
        let client_version = ProtocolVersion::DTLS1_2;
        let session_id = self.session_id.clone().unwrap_or_else(SessionId::empty);
        let cookie = self.cookie.clone().unwrap_or_else(Cookie::empty);

        // Convert Vec<CipherSuite> to ArrayVec<[CipherSuite; 32]>
        let mut cipher_suites = array_vec![[CipherSuite; 32]];
        cipher_suites.extend(self.engine.config().cipher_suites.iter().cloned().take(32));

        let compression_methods = array_vec![[CompressionMethod; 4] => CompressionMethod::Null];

        let client_hello = ClientHello::new(
            client_version,
            self.random.clone(),
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
        );

        self.engine
            .create_handshake(MessageType::ClientHello, 0, |body| {
                client_hello.serialize(body);
            })?;

        Ok(())
    }

    fn process_server_hello(&mut self, can_hello_verify: bool) -> Result<(), Error> {
        // Initialize the handshake state machine based on where we are in the flow
        let mut state = if can_hello_verify {
            HandshakeState::AwaitingFirstServerMessage
        } else {
            HandshakeState::AwaitingServerHelloAfterVerify
        };

        while let Some(incoming) = self.engine.next_incoming() {
            let records = incoming.records();

            for i in 0..records.len() {
                let record = &records[i];

                let handshake = match &record.handshake {
                    Some(h) => h,
                    None => continue,
                };

                // Save handshake message for CertificateVerify signature
                self.engine.add_handshake_message(record.record.fragment);

                // Validate transition using our FSM
                state = state.handle(handshake.header.msg_type)?;

                match handshake.header.msg_type {
                    MessageType::HelloVerifyRequest => {
                        let Body::HelloVerifyRequest(hello_verify) = &handshake.body else {
                            continue;
                        };

                        self.cookie = Some(hello_verify.cookie.clone());
                        self.state = ClientState::SendClientHello;
                        return Ok(());
                    }

                    MessageType::ServerHello => {
                        self.handle_server_hello(handshake)?;
                    }

                    MessageType::Certificate => {
                        self.handle_server_certificate(handshake)?;
                    }

                    MessageType::ServerKeyExchange => {
                        self.handle_server_key_exchange(handshake)?;
                    }

                    MessageType::CertificateRequest => {
                        self.certificate_requested = true;
                    }

                    MessageType::ServerHelloDone => {
                        return self.handle_server_hello_done();
                    }

                    _ => {
                        // Unknown or unexpected message type
                        return Err(Error::UnexpectedMessage(format!(
                            "Unexpected message type: {:?}",
                            handshake.header.msg_type
                        )));
                    }
                }
            }
        }

        if state != HandshakeState::HandshakePhaseComplete {
            return Err(Error::IncompleteServerHello);
        }

        // No state transition yet, continue waiting for more messages
        Ok(())
    }

    fn handle_server_hello(&mut self, handshake: &crate::message::Handshake) -> Result<(), Error> {
        let Body::ServerHello(server_hello) = &handshake.body else {
            return Ok(());
        };

        self.cipher_suite = Some(server_hello.cipher_suite);
        self.session_id = Some(server_hello.session_id.clone());
        self.server_random = Some(server_hello.random.clone());

        // Initialize the key exchange based on selected cipher suite
        let cs = server_hello.cipher_suite;
        self.engine
            .crypto_context_mut()
            .init_key_exchange(cs)
            .map_err(|e| Error::CryptoError(format!("Failed to initialize key exchange: {}", e)))?;

        Ok(())
    }

    fn handle_server_certificate(
        &mut self,
        handshake: &crate::message::Handshake,
    ) -> Result<(), Error> {
        let Body::Certificate(certificate) = &handshake.body else {
            return Ok(());
        };

        // Store the certificate chain for validation
        self.server_certificates.clear();

        // Convert ASN.1 certificates to byte arrays
        for cert in &certificate.certificate_list {
            self.server_certificates.push(cert.0.to_vec());
        }

        Ok(())
    }

    fn handle_server_key_exchange(
        &mut self,
        handshake: &crate::message::Handshake,
    ) -> Result<(), Error> {
        let Body::ServerKeyExchange(server_key_exchange) = &handshake.body else {
            return Ok(());
        };

        // Process the server key exchange message
        self.engine
            .crypto_context_mut()
            .process_server_key_exchange(server_key_exchange)
            .map_err(|e| {
                Error::CryptoError(format!("Failed to process server key exchange: {}", e))
            })?;

        Ok(())
    }

    fn handle_server_hello_done(&mut self) -> Result<(), Error> {
        // Validate the server certificate
        if self.server_certificates.is_empty() {
            return Err(Error::CertificateError(
                "No server certificate received".to_string(),
            ));
        }

        // Verify the certificate using the configured verifier
        if let Err(err) = self
            .engine
            .crypto_context()
            .verify_server_certificate(&self.server_certificates[0])
        {
            return Err(Error::CertificateError(format!(
                "Certificate verification failed: {}",
                err
            )));
        }

        // Transition to next state
        self.state = ClientState::SendClientCertAndKeys;
        Ok(())
    }

    fn send_client_cert_and_keys(&mut self) -> Result<(), Error> {
        self.send_client_certificate()?;
        self.send_client_key_exchange()?;
        self.derive_and_send_keys()?;

        Ok(())
    }

    fn send_client_certificate(&mut self) -> Result<(), Error> {
        if !self.certificate_requested {
            return Ok(());
        }

        // Get the client certificate info before borrowing engine mutably
        let crypto = self.engine.crypto_context();
        let client_cert_opt = crypto.get_client_certificate();

        if let Some(client_cert) = client_cert_opt {
            // Store the client certificate data for sending
            let mut cert_data = Vec::new();
            client_cert.serialize(&mut cert_data);

            // Now use the engine with the stored data
            self.engine
                .create_handshake(MessageType::Certificate, 0, |body| {
                    body.extend_from_slice(&cert_data);
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

        Ok(())
    }

    fn send_client_key_exchange(&mut self) -> Result<(), Error> {
        // Just check that a cipher suite exists without binding to unused variable
        if self.cipher_suite.is_none() {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            ));
        }

        // Generate key exchange data
        let public_key = self
            .engine
            .crypto_context_mut()
            .generate_key_exchange()
            .map_err(|e| Error::CryptoError(format!("Failed to generate key exchange: {}", e)))?;

        // Send client key exchange message
        self.engine
            .create_handshake(MessageType::ClientKeyExchange, 1, |body| {
                // Create a properly formatted ClientKeyExchange message
                // First create a ClientDiffieHellmanPublic with the correct encoding
                let dh_public =
                    ClientDiffieHellmanPublic::new(PublicValueEncoding::Explicit, &public_key);

                // Then wrap it in ExchangeKeys and ClientKeyExchange
                let client_key_exchange = ClientKeyExchange::new(ExchangeKeys::DhAnon(dh_public));

                // Serialize the fully structured message
                client_key_exchange.serialize(body);
            })?;

        // Send CertificateVerify if we sent a client certificate
        if self.certificate_requested && self.engine.crypto_context().has_client_certificate() {
            self.send_certificate_verify()?;
        }

        Ok(())
    }

    fn derive_and_send_keys(&mut self) -> Result<(), Error> {
        let cipher_suite = match self.cipher_suite {
            Some(cs) => cs,
            None => {
                return Err(Error::UnexpectedMessage(
                    "No cipher suite selected".to_string(),
                ))
            }
        };

        let server_random = match &self.server_random {
            Some(sr) => sr,
            None => {
                return Err(Error::UnexpectedMessage(
                    "No server random available".to_string(),
                ))
            }
        };

        // Extract and format the random values for key derivation
        let mut client_random = Vec::with_capacity(32);
        let mut server_random_vec = Vec::with_capacity(32);

        // Serialize the random values to raw bytes
        self.random.serialize(&mut client_random);
        server_random.serialize(&mut server_random_vec);

        // Derive master secret
        self.engine
            .crypto_context_mut()
            .derive_master_secret(&client_random, &server_random_vec)
            .map_err(|e| Error::CryptoError(format!("Failed to derive master secret: {}", e)))?;

        // Derive the encryption/decryption keys
        self.engine
            .crypto_context_mut()
            .derive_keys(cipher_suite, &client_random, &server_random_vec)
            .map_err(|e| Error::CryptoError(format!("Failed to derive keys: {}", e)))?;

        // Send change cipher spec
        self.engine
            .create_record(ContentType::ChangeCipherSpec, |body| {
                // Change cipher spec is just a single byte with value 1
                body.push(1);
            })?;

        // Enable client encryption
        self.engine.enable_client_encryption();

        // Send finished message with verify data
        self.send_finished_message()?;

        Ok(())
    }

    fn send_finished_message(&mut self) -> Result<(), Error> {
        // Calculate verify data for Finished message using PRF
        let verify_data = self.generate_verify_data(true)?;

        // Send finished message
        let finished = Finished::new(&verify_data);
        self.engine
            .create_handshake(MessageType::Finished, 2, |body| {
                finished.serialize(body);
            })?;

        Ok(())
    }

    fn generate_verify_data(&self, is_client: bool) -> Result<[u8; 12], Error> {
        let verify_data_vec = self
            .engine
            .crypto_context()
            .generate_verify_data(self.engine.handshake_messages(), is_client)
            .map_err(|e| Error::CryptoError(format!("Failed to generate verify data: {}", e)))?;

        if verify_data_vec.len() != 12 {
            return Err(Error::CryptoError("Invalid verify data length".to_string()));
        }

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&verify_data_vec);

        Ok(verify_data)
    }

    fn process_server_finished(&mut self) -> Result<(), Error> {
        // Wait for server change cipher spec and finished messages
        while let Some(incoming) = self.engine.next_incoming() {
            let records = incoming.records();

            for i in 0..records.len() {
                let record = &records[i];

                match record.record.content_type {
                    ContentType::ChangeCipherSpec => {
                        // Server changed encryption state
                        self.server_encryption_enabled = true;
                        self.engine.enable_server_encryption();
                        debug!("Server encryption enabled after ChangeCipherSpec");
                    }
                    ContentType::Handshake => {
                        let handshake = match &record.handshake {
                            Some(h) => h,
                            None => continue,
                        };

                        if handshake.header.msg_type != MessageType::Finished {
                            continue;
                        }

                        let Body::Finished(finished) = &handshake.body else {
                            continue;
                        };

                        // Verify the server's verify_data
                        let expected = self.generate_verify_data(false)?;

                        // If verification fails, return an error
                        if finished.verify_data != expected {
                            return Err(Error::SecurityError(
                                "Server Finished verification failed".to_string(),
                            ));
                        }

                        // Handshake is complete
                        self.state = ClientState::Running;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // Continue waiting for server finished
        Ok(())
    }

    /// Send a CertificateVerify message to prove possession of the private key
    fn send_certificate_verify(&mut self) -> Result<(), Error> {
        // Get the signature algorithm recommended for this client
        let algorithm = self.engine.crypto_context().get_signature_algorithm();

        // Sign all handshake messages
        let signature = self
            .engine
            .crypto_context()
            .sign_data(self.engine.handshake_messages())
            .map_err(|e| Error::CryptoError(format!("Failed to sign handshake messages: {}", e)))?;

        // Create the digitally signed structure
        let digitally_signed = DigitallySigned::new(algorithm, &signature);

        // Create the certificate verify message
        let certificate_verify = CertificateVerify::new(digitally_signed);

        // Send the certificate verify message
        self.engine
            .create_handshake(MessageType::CertificateVerify, 0, |body| {
                certificate_verify.serialize(body);
            })?;

        Ok(())
    }

    /// Send application data when the client is in the Running state
    ///
    /// This should only be called when the client is in the Running state,
    /// after the handshake is complete.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if !matches!(self.state, ClientState::Running) {
            return Err(Error::UnexpectedMessage("Not in Running state".to_string()));
        }

        // Use the engine's create_record to send application data
        // The encryption is now handled in the engine
        self.engine
            .create_record(ContentType::ApplicationData, |body| {
                body.extend_from_slice(data);
            })?;

        Ok(())
    }
}

/// Handshake state machine states for tracking message order
#[derive(Debug, PartialEq, Eq)]
enum HandshakeState {
    /// Initial state when starting handshake
    Initial,

    /// Waiting for initial server response after sending ClientHello
    /// Can receive either ServerHello or HelloVerifyRequest
    AwaitingFirstServerMessage,

    /// Waiting for ServerHello after HelloVerifyRequest
    /// After HelloVerifyRequest, only ServerHello is valid
    AwaitingServerHelloAfterVerify,

    /// Server hello received, waiting for certificate
    AwaitingCertificate,

    /// Certificate received, waiting for server key exchange
    AwaitingServerKeyExchange,

    /// Server key exchange received, waiting for certificate request or hello done
    AwaitingCertificateRequestOrHelloDone,

    /// Certificate request received, waiting for hello done
    AwaitingServerHelloDone,

    /// After ServerHelloDone, handshake is complete from server hello phase
    HandshakePhaseComplete,
}

impl HandshakeState {
    /// Process a handshake message and return the next state
    fn handle(&self, message_type: MessageType) -> Result<HandshakeState, Error> {
        match (self, message_type) {
            // Initial state transitions
            (HandshakeState::Initial, _) => Err(Error::UnexpectedMessage(
                "Not in a valid state to process messages".to_string(),
            )),

            // First server message after ClientHello
            (HandshakeState::AwaitingFirstServerMessage, MessageType::HelloVerifyRequest) => {
                Ok(HandshakeState::Initial)
            } // Will restart with a new ClientHello

            (HandshakeState::AwaitingFirstServerMessage, MessageType::ServerHello) => {
                Ok(HandshakeState::AwaitingCertificate)
            }

            // After HelloVerifyRequest and sending a new ClientHello
            (HandshakeState::AwaitingServerHelloAfterVerify, MessageType::ServerHello) => {
                Ok(HandshakeState::AwaitingCertificate)
            }

            (HandshakeState::AwaitingServerHelloAfterVerify, MessageType::HelloVerifyRequest) => {
                Err(Error::UnexpectedMessage(
                    "Received second HelloVerifyRequest".to_string(),
                ))
            }

            // ServerHello already received, expecting Certificate
            (HandshakeState::AwaitingCertificate, MessageType::Certificate) => {
                Ok(HandshakeState::AwaitingServerKeyExchange)
            }

            // Certificate received, expecting ServerKeyExchange
            (HandshakeState::AwaitingServerKeyExchange, MessageType::ServerKeyExchange) => {
                Ok(HandshakeState::AwaitingCertificateRequestOrHelloDone)
            }

            // After ServerKeyExchange, can get either CertificateRequest or ServerHelloDone
            (
                HandshakeState::AwaitingCertificateRequestOrHelloDone,
                MessageType::CertificateRequest,
            ) => Ok(HandshakeState::AwaitingServerHelloDone),

            (
                HandshakeState::AwaitingCertificateRequestOrHelloDone,
                MessageType::ServerHelloDone,
            ) => Ok(HandshakeState::HandshakePhaseComplete),

            // After CertificateRequest, must get ServerHelloDone
            (HandshakeState::AwaitingServerHelloDone, MessageType::ServerHelloDone) => {
                Ok(HandshakeState::HandshakePhaseComplete)
            }

            // After HandshakePhaseComplete, no more messages expected during this phase
            (HandshakeState::HandshakePhaseComplete, _) => Err(Error::UnexpectedMessage(
                "Handshake phase already complete".to_string(),
            )),

            // Any other state/message combination is invalid
            (state, message) => Err(Error::UnexpectedMessage(format!(
                "Unexpected message {:?} in state {:?}",
                message, state
            ))),
        }
    }
}
