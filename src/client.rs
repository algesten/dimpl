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

use log::debug;
use tinyvec::array_vec;

use crate::crypto::{CertVerifier, SrtpProfile};
use crate::engine::Engine;
use crate::message::{
    Body, CertificateVerify, ClientDiffieHellmanPublic, ClientEcdhKeys, ClientHello,
    ClientKeyExchange, CompressionMethod, ContentType, Cookie, DigitallySigned, ExchangeKeys,
    ExtensionType, Finished, KeyExchangeAlgorithm, MessageType, ProtocolVersion,
    PublicValueEncoding, Random, SessionId, SignatureAndHashAlgorithm, UseSrtpExtension,
};
use crate::message::{CipherSuite, HashAlgorithm};
use crate::{Config, Error, Output};

/// DTLS client
pub struct Client {
    /// Random unique data (with gmt timestamp). Used for signature checks.
    random: Random,

    /// SessionId is set by the server and only sent by the client if we
    /// are reusing a session (key renegotiation).
    session_id: Option<SessionId>,

    /// Cookie is sent by the server in the optional HelloVerifyRequest.
    /// It might remain null if there is no HelloVerifyRequest.
    cookie: Option<Cookie>,

    /// The cipher suite in use. Set by ServerHello.
    cipher_suite: Option<CipherSuite>,

    /// Storage for extension data
    extension_data: Vec<u8>,

    /// The negotiated SRTP profile (if any)
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Current client state.
    state: ClientState,

    /// Engine in common between server and client.
    engine: Engine,

    /// Server random. Set by ServerHello.
    server_random: Option<Random>,

    /// Server certificates
    server_certificates: Vec<Vec<u8>>,

    /// Buffer for defragmenting handshakes
    defragment_buffer: Vec<u8>,

    /// Whether we requested a CertificateVerify
    certificate_verify: bool,
}

/// Current state of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// * `private_key` - Client private key corresponding to the certificate
    /// * `cert_verifier` - Certificate verifier for validating server certificates
    pub fn new(
        now: Instant,
        config: Arc<Config>,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
    ) -> Client {
        let engine = Engine::new(config, certificate, private_key, cert_verifier, true);

        Client {
            random: Random::new(now),
            session_id: None,
            cookie: None,
            cipher_suite: None,
            state: ClientState::SendClientHello,
            engine,
            server_random: None,
            server_certificates: Vec::new(),
            negotiated_srtp_profile: None,
            extension_data: Vec::with_capacity(256), // Pre-allocate extension data buffer
            defragment_buffer: Vec::new(),
            certificate_verify: false,
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

    /// Explicitly start the handshake process by sending a ClientHello
    pub fn handle_timeout(&mut self, _now: Instant) -> Result<(), Error> {
        // Only process if we're in the initial state
        if matches!(self.state, ClientState::SendClientHello) {
            self.process_input()?;
        }
        Ok(())
    }

    fn process_input(&mut self) -> Result<(), Error> {
        loop {
            let prev_state = self.state;
            self.do_process_input()?;
            if prev_state == self.state {
                break;
            }
        }
        Ok(())
    }

    fn do_process_input(&mut self) -> Result<(), Error> {
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
                // Process incoming application data packets using the engine
                self.engine.process_application_data()?;
                Ok(())
            }
        }
    }

    fn send_client_hello(&mut self) -> Result<(), Error> {
        debug!("Sending ClientHello");
        let client_version = ProtocolVersion::DTLS1_2;
        let session_id = self.session_id.clone().unwrap_or_else(SessionId::empty);
        let cookie = self.cookie.clone().unwrap_or_else(Cookie::empty);

        // Convert Vec<CipherSuite> to ArrayVec<[CipherSuite; 32]>
        let mut cipher_suites = array_vec![[CipherSuite; 32]];

        // Get the client certificate type
        let cert_type = self.engine.crypto_context().signature_algorithm();

        // Get compatible cipher suites
        let compatible_suites = CipherSuite::compatible_with_certificate(cert_type);

        // Filter cipher suites based on the client's private key
        let filtered_suites: Vec<CipherSuite> = compatible_suites
            .iter()
            .filter(|suite| {
                self.engine
                    .crypto_context()
                    .is_cipher_suite_compatible(**suite)
            })
            .cloned()
            .collect();

        cipher_suites.extend(filtered_suites.into_iter().take(32));

        debug!(
            "Sending ClientHello: DTLS version={:?}, cookie_len={}, offering {} cipher suites",
            client_version,
            cookie.len(),
            cipher_suites.len()
        );

        let compression_methods = array_vec![[CompressionMethod; 4] => CompressionMethod::Null];

        // Create ClientHello with all required extensions
        let client_hello = ClientHello::new(
            client_version,
            self.random.clone(),
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
        )
        .with_extensions(&mut self.extension_data);

        self.engine
            .create_handshake(MessageType::ClientHello, |body| {
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

        let Some(mut flight) = self.engine.has_flight(MessageType::ServerHelloDone) else {
            return Ok(());
        };

        while let Some(handshake) = self.engine.next_from_flight(
            &mut flight,
            &mut self.defragment_buffer,
            self.cipher_suite,
        )? {
            // Validate transition using our FSM
            state = state.handle(handshake.header.msg_type)?;

            match handshake.header.msg_type {
                MessageType::HelloVerifyRequest => {
                    let Body::HelloVerifyRequest(hello_verify) = &handshake.body else {
                        continue;
                    };

                    debug!(
                        "Received HelloVerifyRequest with cookie length: {}",
                        hello_verify.cookie.len()
                    );
                    self.cookie = Some(hello_verify.cookie.clone());
                    self.state = ClientState::SendClientHello;
                    self.engine.reset_handshake_seq_no();
                    debug!(
                        "Resetting handshake: will send new ClientHello with cookie (len={})",
                        hello_verify.cookie.len()
                    );
                    return Ok(());
                }

                MessageType::ServerHello => {
                    let Body::ServerHello(server_hello) = &handshake.body else {
                        return Ok(());
                    };

                    debug!(
                        "Received ServerHello with cipher suite: {:?}",
                        server_hello.cipher_suite
                    );
                    let cs = server_hello.cipher_suite;
                    self.cipher_suite = Some(cs);
                    self.session_id = Some(server_hello.session_id.clone());
                    self.server_random = Some(server_hello.random.clone());

                    // Initialize the key exchange based on selected cipher suite
                    self.engine.init_cipher_suite(cs).map_err(|e| {
                        Error::CryptoError(format!("Failed to initialize key exchange: {}", e))
                    })?;

                    // Check for use_srtp extension to get the negotiated SRTP profile
                    if let Some(extensions) = &server_hello.extensions {
                        for extension in extensions {
                            if extension.extension_type == ExtensionType::UseSrtp {
                                // Parse the use_srtp extension to get the selected profile
                                if let Ok((_, use_srtp)) =
                                    UseSrtpExtension::parse(extension.extension_data)
                                {
                                    // Store the first profile as our negotiated profile
                                    if !use_srtp.profiles.is_empty() {
                                        self.negotiated_srtp_profile =
                                            Some(use_srtp.profiles[0].to_srtp_profile());
                                    }
                                }
                            }
                        }
                    }
                }

                MessageType::Certificate => {
                    let Body::Certificate(certificate) = &handshake.body else {
                        return Ok(());
                    };

                    debug!(
                        "Received Certificate with {} certificates",
                        certificate.certificate_list.len()
                    );
                    // Store the certificate chain for validation
                    self.server_certificates.clear();

                    // Convert ASN.1 certificates to byte arrays
                    for (i, cert) in certificate.certificate_list.iter().enumerate() {
                        let cert_data = cert.0.to_vec();
                        debug!("Certificate #{} size: {} bytes", i + 1, cert_data.len());
                        self.server_certificates.push(cert_data);
                    }
                }

                MessageType::ServerKeyExchange => {
                    let Body::ServerKeyExchange(server_key_exchange) = &handshake.body else {
                        return Ok(());
                    };

                    debug!("Received ServerKeyExchange");

                    // Get key exchange algorithm for better logging
                    let key_exchange_alg = match self.cipher_suite {
                        Some(cs) => cs.as_key_exchange_algorithm(),
                        None => KeyExchangeAlgorithm::Unknown,
                    };

                    debug!("ServerKeyExchange using algorithm: {:?}", key_exchange_alg);

                    // Process the server key exchange message
                    self.engine
                        .crypto_context_mut()
                        .process_server_key_exchange(server_key_exchange)
                        .map_err(|e| {
                            Error::CryptoError(format!(
                                "Failed to process server key exchange: {}",
                                e
                            ))
                        })?;
                }

                MessageType::CertificateRequest => {
                    let Body::CertificateRequest(cr) = &handshake.body else {
                        panic!("CertificateRequest message should have been parsed");
                    };

                    debug!("Received CertificateRequest with {} certificate types, {} signature algorithms",
                           cr.certificate_types.len(), cr.supported_signature_algorithms.len());

                    // Check that the hash algorithm that is default fo the PrivateKey in use
                    // is one of the supported by the CertificateRequest
                    let hash_algorithm = self
                        .engine
                        .crypto_context()
                        .private_key_default_hash_algorithm();

                    if !cr.supports_hash_algorithm(hash_algorithm) {
                        return Err(Error::CertificateError(format!(
                            "Unsupported hash algorithm: {:?}",
                            hash_algorithm
                        )));
                    }

                    debug!(
                        "Server supports CertificateVerify hash algorithm: {:?}",
                        hash_algorithm
                    );

                    self.certificate_verify = true;
                }

                MessageType::ServerHelloDone => {
                    debug!("Received ServerHelloDone - handshake message phase complete");
                    return self.handle_server_hello_done();
                }

                _ => {
                    debug!(
                        "Received unexpected message type: {:?}",
                        handshake.header.msg_type
                    );
                    // Unknown or unexpected message type
                    return Err(Error::UnexpectedMessage(format!(
                        "Unexpected message type: {:?}",
                        handshake.header.msg_type
                    )));
                }
            }
        }

        if state != HandshakeState::HandshakePhaseComplete {
            return Err(Error::IncompleteServerHello);
        }

        // No state transition yet, continue waiting for more messages
        Ok(())
    }

    fn handle_server_hello_done(&mut self) -> Result<(), Error> {
        debug!("Handling ServerHelloDone");
        // Validate the server certificate
        if self.server_certificates.is_empty() {
            return Err(Error::CertificateError(
                "No server certificate received".to_string(),
            ));
        }

        // Verify the certificate using the configured verifier
        debug!(
            "Verifying server certificate (size: {} bytes)",
            self.server_certificates[0].len()
        );
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
        debug!("Server certificate verification successful");

        // Send the server certificate as an event
        if !self.server_certificates.is_empty() {
            let cert_data = self.server_certificates[0].clone();
            self.engine.push_peer_cert(cert_data);
        }

        // Transition to next state
        debug!("Transitioning to SendClientCertAndKeys state");
        self.state = ClientState::SendClientCertAndKeys;
        Ok(())
    }

    fn send_client_cert_and_keys(&mut self) -> Result<(), Error> {
        debug!("Preparing to send client certificate and keys");
        self.send_client_certificate()?;
        self.send_client_key_exchange()?;
        if self.certificate_verify {
            self.send_certificate_verify()?;
        }

        debug!("Client key exchange complete, deriving session keys");
        self.derive_and_send_keys()?;

        Ok(())
    }

    fn send_client_certificate(&mut self) -> Result<(), Error> {
        debug!("Sending Certificate");
        // Get the client certificate
        let crypto = self.engine.crypto_context();
        let client_cert = crypto.get_client_certificate();

        // Get certificate size for logging
        let mut temp_buf = Vec::new();
        client_cert.serialize(&mut temp_buf);
        debug!("Client certificate size: {} bytes", temp_buf.len());

        // Store the client certificate data for sending
        let mut cert_data = Vec::new();
        client_cert.serialize(&mut cert_data);

        // Now use the engine with the stored data
        self.engine
            .create_handshake(MessageType::Certificate, |body| {
                body.extend_from_slice(&cert_data);
            })?;

        Ok(())
    }

    fn send_client_key_exchange(&mut self) -> Result<(), Error> {
        debug!("Sending ClientKeyExchange");
        // Just check that a cipher suite exists without binding to unused variable
        if self.cipher_suite.is_none() {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            ));
        }

        let cipher_suite = self.cipher_suite.unwrap();
        let key_exchange_algorithm = cipher_suite.as_key_exchange_algorithm();

        debug!("Using key exchange algorithm: {:?}", key_exchange_algorithm);

        // For ECDHE, get curve info before we create the handshake (to avoid borrow issues)
        let curve_info = if key_exchange_algorithm == KeyExchangeAlgorithm::EECDH {
            self.engine.crypto_context().get_key_exchange_curve_info()
        } else {
            None
        };

        if let Some((curve_type, named_curve)) = &curve_info {
            debug!(
                "Using ECDHE curve info: {:?}, curve: {:?}",
                curve_type, named_curve
            );
        }

        // Generate key exchange data
        debug!("Generating key exchange data");
        let public_key = self
            .engine
            .crypto_context_mut()
            .generate_key_exchange()
            .map_err(|e| Error::CryptoError(format!("Failed to generate key exchange: {}", e)))?;

        debug!("Generated public key size: {} bytes", public_key.len());

        // Send client key exchange message
        self.engine
            .create_handshake(MessageType::ClientKeyExchange, |body| {
                // Create a properly formatted ClientKeyExchange message based on the key exchange algorithm
                let exchange_keys = match key_exchange_algorithm {
                    KeyExchangeAlgorithm::EECDH => {
                        // For ECDHE, use the curve information we retrieved earlier
                        if let Some((curve_type, named_curve)) = curve_info {
                            debug!(
                                "Using ECDHE curve info: {:?}, {:?}",
                                curve_type, named_curve
                            );

                            // Create ClientEcdhKeys with the proper curve information and public key
                            let ecdh_keys =
                                ClientEcdhKeys::new(curve_type, named_curve, &public_key);
                            ExchangeKeys::Ecdh(ecdh_keys)
                        } else {
                            // Fallback if no curve info is available (shouldn't happen)
                            warn!("No curve info available for ECDHE, using fallback");
                            let dh_public = ClientDiffieHellmanPublic::new(
                                PublicValueEncoding::Explicit,
                                &public_key,
                            );
                            ExchangeKeys::DhAnon(dh_public)
                        }
                    }
                    KeyExchangeAlgorithm::EDH => {
                        // For DHE, use the standard encoding
                        let dh_public = ClientDiffieHellmanPublic::new(
                            PublicValueEncoding::Explicit,
                            &public_key,
                        );
                        ExchangeKeys::DhAnon(dh_public)
                    }
                    _ => {
                        // Create a default format for unknown algorithms
                        let dh_public = ClientDiffieHellmanPublic::new(
                            PublicValueEncoding::Explicit,
                            &public_key,
                        );
                        ExchangeKeys::DhAnon(dh_public)
                    }
                };

                // Wrap in ClientKeyExchange and serialize
                let client_key_exchange = ClientKeyExchange::new(exchange_keys);
                client_key_exchange.serialize(body);
            })?;

        Ok(())
    }

    fn derive_and_send_keys(&mut self) -> Result<(), Error> {
        debug!("Deriving keys and sending ChangeCipherSpec");
        let cipher_suite = match self.cipher_suite {
            Some(cs) => cs,
            None => {
                return Err(Error::UnexpectedMessage(
                    "No cipher suite selected".to_string(),
                ))
            }
        };

        debug!("Using cipher suite for key derivation: {:?}", cipher_suite);

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

        debug!(
            "Deriving master secret using client random ({} bytes) and server random ({} bytes)",
            client_random.len(),
            server_random_vec.len()
        );

        // Derive master secret
        self.engine
            .crypto_context_mut()
            .derive_master_secret(&client_random, &server_random_vec)
            .map_err(|e| Error::CryptoError(format!("Failed to derive master secret: {}", e)))?;

        debug!("Master secret derived successfully");

        // Derive the encryption/decryption keys
        debug!("Deriving encryption/decryption keys");
        self.engine
            .crypto_context_mut()
            .derive_keys(cipher_suite, &client_random, &server_random_vec)
            .map_err(|e| Error::CryptoError(format!("Failed to derive keys: {}", e)))?;

        debug!("Encryption/decryption keys derived successfully, sending ChangeCipherSpec");

        // Send change cipher spec
        self.engine
            .create_record(ContentType::ChangeCipherSpec, |body| {
                // Change cipher spec is just a single byte with value 1
                body.push(1);
                None
            })?;

        // Enable client encryption
        self.engine.enable_client_encryption();
        debug!("Client encryption enabled");

        // Send finished message with verify data
        self.send_finished_message()?;

        Ok(())
    }

    fn send_finished_message(&mut self) -> Result<(), Error> {
        debug!("Sending Finished message to complete handshake");
        // Calculate verify data for Finished message using PRF
        let verify_data = self.generate_verify_data(true)?;

        debug!("Generated verify data for Finished message (12 bytes)");

        // Send finished message
        let finished = Finished::new(&verify_data);
        self.engine
            .create_handshake(MessageType::Finished, |body| {
                finished.serialize(body);
            })?;

        Ok(())
    }

    fn generate_verify_data(&self, is_client: bool) -> Result<[u8; 12], Error> {
        debug!(
            "Generating verify data for {}, using handshake hash",
            if is_client { "client" } else { "server" }
        );

        let algorithm = self.cipher_suite.unwrap().hash_algorithm();
        let handshake_hash = self.engine.handshake_hash(algorithm);

        debug!("Handshake hash size: {} bytes", handshake_hash.len());

        let verify_data_vec = self
            .engine
            .crypto_context()
            .generate_verify_data(&handshake_hash, is_client)
            .map_err(|e| Error::CryptoError(format!("Failed to generate verify data: {}", e)))?;

        if verify_data_vec.len() != 12 {
            return Err(Error::CryptoError("Invalid verify data length".to_string()));
        }

        let mut verify_data = [0u8; 12];
        verify_data.copy_from_slice(&verify_data_vec);

        Ok(verify_data)
    }

    fn process_server_finished(&mut self) -> Result<(), Error> {
        // Generate expected verify data before the loop to avoid borrow issues
        let expected = self.generate_verify_data(false)?;
        debug!("Generated expected server verify data, waiting for server Finished message");

        // First check for ChangeCipherSpec record
        if let Some(incoming) = self.engine.next_incoming() {
            for record in incoming.records().iter() {
                if record.record.content_type == ContentType::ChangeCipherSpec {
                    debug!("Received server ChangeCipherSpec, enabling server encryption");
                    // Server changed encryption state
                    self.engine.enable_server_encryption();
                }
            }
        }

        // Wait for server finished message
        let Some(mut flight) = self.engine.has_flight(MessageType::Finished) else {
            debug!("Waiting for server Finished message");
            return Ok(());
        };

        // Start in HandshakePhaseComplete state since we've already received ServerHelloDone
        let mut state = HandshakeState::HandshakePhaseComplete;

        while let Some(handshake) = self.engine.next_from_flight(
            &mut flight,
            &mut self.defragment_buffer,
            self.cipher_suite,
        )? {
            // Update state based on message type
            state = state.handle(handshake.header.msg_type)?;

            debug!(
                "Received handshake message: {:?}, sequence: {}",
                handshake.header.msg_type, handshake.header.message_seq
            );

            if !matches!(handshake.header.msg_type, MessageType::Finished) {
                debug!(
                    "Expected Finished message, got: {:?}",
                    handshake.header.msg_type
                );
                return Err(Error::UnexpectedMessage(format!(
                    "Unexpected message type: {:?}",
                    handshake.header.msg_type
                )));
            }

            let Body::Finished(finished) = &handshake.body else {
                panic!("Finished message should have been parsed");
            };

            debug!("Processing server Finished message, verifying data");

            // If verification fails, return an error
            if finished.verify_data != expected {
                debug!("Server Finished verification failed, data mismatch");
                return Err(Error::SecurityError(
                    "Server Finished verification failed".to_string(),
                ));
            }

            debug!("Server Finished verified successfully, handshake complete, state=Running");
            // Handshake is complete
            self.state = ClientState::Running;

            // Emit Connected event
            self.engine.push_connected();
            debug!("Connection established event sent");

            // Extract and emit SRTP keying material if we have a negotiated profile
            if let Some(profile) = self.negotiated_srtp_profile {
                debug!("Extracting SRTP keying material for profile: {:?}", profile);
                if let Ok(keying_material) = self
                    .engine
                    .crypto_context()
                    .extract_srtp_keying_material(profile)
                {
                    // Emit the keying material event with the negotiated profile
                    debug!(
                        "SRTP keying material extracted ({} bytes) for profile: {:?}",
                        keying_material.len(),
                        profile
                    );
                    self.engine.push_keying_material(keying_material, profile);
                }
            }
        }

        // Continue waiting for server finished
        Ok(())
    }

    /// Send a CertificateVerify message to prove possession of the private key
    fn send_certificate_verify(&mut self) -> Result<(), Error> {
        debug!("Sending CertificateVerify to prove client certificate ownership");

        // The hash algorithm to use is the default for the private key type, not
        // the one negotiated to use with the selected cipher suite. I.e.
        // if we negotiate ECDHE_ECDSA_AES256_GCM_SHA384, we are gogin to use
        // SHA384 for the signature of the main crypto, but not for CertificateVerify
        // where a private key using P256 curve means we use SHA256.
        let hash_alg = self
            .engine
            .crypto_context()
            .private_key_default_hash_algorithm();
        debug!("Using hash algorithm for signature: {:?}", hash_alg);

        // Get the signature algorithm type
        let sig_alg = self.engine.crypto_context().signature_algorithm();
        debug!("Using signature algorithm: {:?}", sig_alg);

        // Create the signature algorithm
        let algorithm = SignatureAndHashAlgorithm::new(hash_alg, sig_alg);

        let handshake_data = self.engine.handshake_data();

        // Sign all handshake messages
        let signature = self
            .engine
            .crypto_context()
            .sign_data(&handshake_data, hash_alg)
            .map_err(|e| Error::CryptoError(format!("Failed to sign handshake messages: {}", e)))?;

        debug!("Generated signature size: {} bytes", signature.len());

        // Create the digitally signed structure
        let digitally_signed = DigitallySigned::new(algorithm, &signature);

        // Create the certificate verify message
        let certificate_verify = CertificateVerify::new(digitally_signed);

        // Send the certificate verify message
        self.engine
            .create_handshake(MessageType::CertificateVerify, |body| {
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
            debug!(
                "Attempted to send application data while not in Running state: {:?}",
                self.state
            );
            return Err(Error::UnexpectedMessage("Not in Running state".to_string()));
        }

        debug!(
            "Sending application data: {} bytes with cipher suite: {:?}",
            data.len(),
            self.cipher_suite.unwrap_or(CipherSuite::Unknown(0))
        );

        // Use the engine's create_record to send application data
        // The encryption is now handled in the engine
        self.engine
            .create_record(ContentType::ApplicationData, |body| {
                body.extend_from_slice(data);
                None
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

impl CipherSuite {
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384 => HashAlgorithm::SHA384,
            CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256 => HashAlgorithm::SHA256,
            CipherSuite::ECDHE_RSA_AES256_GCM_SHA384 => HashAlgorithm::SHA384,
            CipherSuite::ECDHE_RSA_AES128_GCM_SHA256 => HashAlgorithm::SHA256,
            CipherSuite::DHE_RSA_AES256_GCM_SHA384 => HashAlgorithm::SHA384,
            CipherSuite::DHE_RSA_AES128_GCM_SHA256 => HashAlgorithm::SHA256,
            CipherSuite::Unknown(_) => HashAlgorithm::Unknown(0),
        }
    }
}
