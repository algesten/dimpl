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
use tinyvec::{array_vec, ArrayVec};

use crate::buffer::{Buf, ToBuf};
use crate::crypto::{CertVerifier, SrtpProfile};
use crate::engine::Engine;
use crate::message::CipherSuite;
use crate::message::{
    Body, CertificateVerify, ClientDiffieHellmanPublic, ClientEcdhKeys, ClientHello,
    ClientKeyExchange, CompressionMethod, ContentType, Cookie, DigitallySigned, ExchangeKeys,
    ExtensionType, Finished, KeyExchangeAlgorithm, MessageType, ProtocolVersion,
    PublicValueEncoding, Random, SessionId, SignatureAndHashAlgorithm, UseSrtpExtension,
};
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

    /// Storage for extension data
    extension_data: Buf<'static>,

    /// The negotiated SRTP profile (if any)
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Current client state.
    state: ClientState,

    /// Engine in common between server and client.
    engine: Engine,

    /// Server random. Set by ServerHello.
    server_random: Option<Random>,

    /// Server certificates
    server_certificates: Vec<Buf<'static>>,

    /// Buffer for defragmenting handshakes
    defragment_buffer: Buf<'static>,

    /// Whether we requested a CertificateVerify
    certificate_verify: bool,

    /// Whether Extended Master Secret was negotiated
    extended_master_secret: bool,

    /// Captured session hash for Extended Master Secret (RFC 7627)
    /// This is captured after ServerHelloDone to include the correct handshake messages
    captured_session_hash: Option<Vec<u8>>,
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
            state: ClientState::SendClientHello,
            engine,
            server_random: None,
            server_certificates: Vec::with_capacity(3),
            negotiated_srtp_profile: None,
            extension_data: Buf::new(),
            defragment_buffer: Buf::new(),
            certificate_verify: false,
            extended_master_secret: false,
            captured_session_hash: None,
        }
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.engine.parse_packet(packet)?;
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

        let session_id = self.session_id.unwrap_or_else(SessionId::empty);
        let cookie = self.cookie.unwrap_or_else(Cookie::empty);
        let random = self.random;

        self.engine
            .create_handshake(MessageType::ClientHello, |body, engine| {
                handshake_create_client_hello(
                    body,
                    engine,
                    cookie,
                    random,
                    session_id,
                    &mut self.extension_data,
                )
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

        let Some(mut flight) = self.engine.has_complete_message(MessageType::ServerHelloDone) else {
            return Ok(());
        };

        while let Some(handshake) = self
            .engine
            .next_message(&mut flight, &mut self.defragment_buffer)?
        {
            // Validate transition using our FSM
            state = state.handle(handshake.header.msg_type)?;

            match handshake.header.msg_type {
                MessageType::HelloVerifyRequest => {
                    let Body::HelloVerifyRequest(hello_verify) = &handshake.body else {
                        continue;
                    };

                    // Enforce DTLS 1.2 version in HelloVerifyRequest
                    if hello_verify.server_version != ProtocolVersion::DTLS1_2 {
                        return Err(Error::SecurityError(format!(
                            "Unsupported DTLS version in HelloVerifyRequest: {:?}",
                            hello_verify.server_version
                        )));
                    }

                    debug!(
                        "Received HelloVerifyRequest with cookie length: {}",
                        hello_verify.cookie.len()
                    );
                    self.cookie = Some(hello_verify.cookie);
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
                    // Enforce DTLS1.2 version
                    if server_hello.server_version != ProtocolVersion::DTLS1_2 {
                        return Err(Error::SecurityError(format!(
                            "Unsupported DTLS version from server: {:?}",
                            server_hello.server_version
                        )));
                    }

                    // Enforce Null compression only
                    if server_hello.compression_method != CompressionMethod::Null {
                        return Err(Error::SecurityError(format!(
                            "Unsupported compression from server: {:?}",
                            server_hello.compression_method
                        )));
                    }

                    // Enforce cipher suite is known and allowed
                    let cs = server_hello.cipher_suite;
                    if matches!(cs, CipherSuite::Unknown(_)) {
                        return Err(Error::SecurityError(
                            "Server selected unknown cipher suite".to_string(),
                        ));
                    }

                    // Enforce cipher suite is compatible with our private key and allowed by config
                    if !self.engine.crypto_context().is_cipher_suite_compatible(cs) {
                        return Err(Error::SecurityError(format!(
                            "Server selected incompatible cipher suite: {:?}",
                            cs
                        )));
                    }

                    if !self.engine.is_cipher_suite_allowed(cs) {
                        return Err(Error::SecurityError(format!(
                            "Server selected disallowed cipher suite: {:?}",
                            cs
                        )));
                    }

                    // Note: we keep offered suites local; we don't enforce echo here

                    self.engine.set_cipher_suite(cs);
                    self.session_id = Some(server_hello.session_id);
                    self.server_random = Some(server_hello.random);

                    // Check for use_srtp and extended_master_secret extensions
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
                                            Some(use_srtp.profiles[0].into());
                                    }
                                }
                            }

                            // We are to use extended master secret
                            if extension.extension_type == ExtensionType::ExtendedMasterSecret {
                                self.extended_master_secret = true;
                                trace!("Server negotiated Extended Master Secret");
                            }
                        }
                    }

                    // Without extended master secret, in DTLS1.2 a security attack
                    // reusing the same master secret is possible.
                    if !self.extended_master_secret {
                        return Err(Error::SecurityError(
                            "Extended Master Secret not negotiated".to_string(),
                        ));
                    }
                }

                MessageType::Certificate => {
                    let Body::Certificate(certificate) = &handshake.body else {
                        return Ok(());
                    };

                    if certificate.certificate_list.is_empty() {
                        return Err(Error::UnexpectedMessage(
                            "No server certificate received".to_string(),
                        ));
                    }

                    // Convert ASN.1 certificates to byte arrays
                    for (i, cert) in certificate.certificate_list.iter().enumerate() {
                        let cert_data = cert.0.to_vec();
                        trace!("Certificate #{} size: {} bytes", i + 1, cert_data.len());
                        self.server_certificates.push(cert_data.to_buf());
                    }
                }

                MessageType::ServerKeyExchange => {
                    let Body::ServerKeyExchange(server_key_exchange) = &handshake.body else {
                        return Ok(());
                    };

                    let Some(d_signed) = server_key_exchange.signature() else {
                        // We do not support anonymous key exchange
                        return Err(Error::UnexpectedMessage(
                            "ServerKeyExchange without signature".to_string(),
                        ));
                    };

                    // unwrap: is ok because we verify the order of the flight
                    let client_random = self.random;
                    let server_random = self.server_random.unwrap();

                    let mut signed_data = Buf::new();
                    client_random.serialize(&mut signed_data);
                    server_random.serialize(&mut signed_data);
                    server_key_exchange.serialize(&mut signed_data, false);

                    let cipher_suite = self.engine.cipher_suite().ok_or_else(|| {
                        Error::UnexpectedMessage("No cipher suite selected".to_string())
                    })?;

                    // Ensure the server's (hash, signature) pair was offered by the client
                    let offered = SignatureAndHashAlgorithm::supported()
                        .iter()
                        .any(|alg| *alg == d_signed.algorithm);
                    if !offered {
                        return Err(Error::CryptoError(
                            "Signature algorithm not offered by client".to_string(),
                        ));
                    }

                    // Ensure the signature algorithm is compatible with the cipher suite
                    if d_signed.algorithm.signature != cipher_suite.signature_algorithm() {
                        return Err(Error::CryptoError(format!(
                            "Signature algorithm mismatch: {:?} != {:?}",
                            d_signed.algorithm.signature,
                            cipher_suite.signature_algorithm()
                        )));
                    }

                    // unwrap: is ok because we verify the order of the flight
                    let cert_der = self.server_certificates.first().unwrap();

                    self.engine
                        .crypto_context_mut()
                        .verify_signature(&signed_data, d_signed, cert_der)
                        .map_err(|e| {
                            Error::CryptoError(format!(
                                "Failed to verify server key exchange signature: {}",
                                e
                            ))
                        })?;

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
        trace!("Server certificate verification successful");

        // Send the server certificate as an event
        if !self.server_certificates.is_empty() {
            let cert_data = self.server_certificates[0].to_vec();
            self.engine.push_peer_cert(cert_data);
        }

        // Transition to next state
        self.state = ClientState::SendClientCertAndKeys;
        Ok(())
    }

    fn send_client_cert_and_keys(&mut self) -> Result<(), Error> {
        self.send_client_certificate()?;
        self.send_client_key_exchange()?;
        if self.certificate_verify {
            self.send_certificate_verify()?;
        }

        self.derive_and_send_keys()?;

        Ok(())
    }

    fn send_client_certificate(&mut self) -> Result<(), Error> {
        debug!("Sending Certificate");

        // Now use the engine with the stored data
        self.engine
            .create_handshake(MessageType::Certificate, handshake_create_certificate)?;

        Ok(())
    }

    fn send_client_key_exchange(&mut self) -> Result<(), Error> {
        debug!("Sending ClientKeyExchange");

        // Send client key exchange message
        self.engine.create_handshake(
            MessageType::ClientKeyExchange,
            handshake_create_client_key_exchange,
        )?;

        // Capture session hash now for Extended Master Secret (RFC 7627)
        // At this point, the session hash includes: ClientHello, ServerHello, Certificate,
        // ServerKeyExchange, CertificateRequest, ServerHelloDone, Certificate, ClientKeyExchange
        // This is correct per RFC 7627 - session hash should include messages up to and including ClientKeyExchange
        if self.extended_master_secret {
            let cipher_suite = self
                .engine
                .cipher_suite()
                .ok_or_else(|| Error::UnexpectedMessage("No cipher suite selected".to_string()))?;
            let suite_hash = cipher_suite.hash_algorithm();
            self.captured_session_hash = Some(self.engine.handshake_hash(suite_hash));
        }

        Ok(())
    }

    fn derive_and_send_keys(&mut self) -> Result<(), Error> {
        debug!("Deriving keys and sending ChangeCipherSpec");
        let Some(cipher_suite) = self.engine.cipher_suite() else {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            ));
        };

        debug!("Using cipher suite for key derivation: {:?}", cipher_suite);

        let Some(server_random) = &self.server_random else {
            return Err(Error::UnexpectedMessage(
                "No server random available".to_string(),
            ));
        };

        // Extract and format the random values for key derivation
        let mut client_random_buf_b = Buf::new();
        let mut server_random_buf_b = Buf::new();

        // Serialize the random values to raw bytes
        self.random.serialize(&mut client_random_buf_b);
        server_random.serialize(&mut server_random_buf_b);
        let client_random_buf = client_random_buf_b.into_vec();
        let server_random_buf = server_random_buf_b.into_vec();

        // Derive master secret (use EMS if negotiated)
        let suite_hash = cipher_suite.hash_algorithm();

        // Use the captured session hash from when ServerHelloDone was received
        let session_hash = self.captured_session_hash.as_ref().ok_or_else(|| {
            Error::CryptoError(
                "Extended Master Secret negotiated but session hash not captured".to_string(),
            )
        })?;
        debug!(
            "Using captured session hash for Extended Master Secret (length: {})",
            session_hash.len()
        );
        self.engine
            .crypto_context_mut()
            .derive_extended_master_secret(session_hash, suite_hash)
            .map_err(|e| {
                Error::CryptoError(format!("Failed to derive extended master secret: {}", e))
            })?;

        // Derive the encryption/decryption keys
        self.engine
            .crypto_context_mut()
            .derive_keys(cipher_suite, &client_random_buf, &server_random_buf)
            .map_err(|e| Error::CryptoError(format!("Failed to derive keys: {}", e)))?;

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

        self.engine
            .create_handshake(MessageType::Finished, |body, engine| {
                // Calculate verify data for Finished message using PRF
                let verify_data = engine.generate_verify_data(true)?;

                // Send finished message
                let finished = Finished::new(&verify_data);

                debug!("Generated verify data for Finished message (12 bytes)");

                finished.serialize(body);
                Ok(())
            })?;

        Ok(())
    }

    fn process_server_finished(&mut self) -> Result<(), Error> {
        // Generate expected verify data based on current transcript. This may
        // be recomputed if additional handshake messages (e.g., NewSessionTicket)
        // are received before the server's Finished.
        let mut expected = self.engine.generate_verify_data(false)?;

        // Wait for server finished message
        let Some(mut flight) = self.engine.has_complete_message(MessageType::Finished) else {
            return Ok(());
        };

        // Start in AwaitingFinished state since we already received ServerHelloDone
        let mut state = HandshakeState::AwaitingFinished;

        while let Some(handshake) = self
            .engine
            .next_message(&mut flight, &mut self.defragment_buffer)?
        {
            // Update state based on message type
            state = state.handle(handshake.header.msg_type)?;

            if matches!(handshake.header.msg_type, MessageType::NewSessionTicket) {
                debug!("Received NewSessionTicket message, updating expected verify data");
                // Recompute expected verify data now that the transcript includes the ticket
                expected = self.engine.generate_verify_data(false)?;
                continue;
            }

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

            // If verification fails, return an error
            if finished.verify_data != expected {
                return Err(Error::SecurityError(
                    "Server Finished verification failed".to_string(),
                ));
            }

            debug!("Server Finished verified successfully, handshake complete, state=Running");
            // Handshake is complete
            self.state = ClientState::Running;

            // Emit Connected event
            self.engine.push_connected();

            // Extract and emit SRTP keying material if we have a negotiated profile
            if let Some(profile) = self.negotiated_srtp_profile {
                let suite_hash = self.engine.cipher_suite().unwrap().hash_algorithm();
                if let Ok(keying_material) = self
                    .engine
                    .crypto_context()
                    .extract_srtp_keying_material(profile, suite_hash)
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
        debug!("Sending CertificateVerify");

        // Send the certificate verify message
        self.engine.create_handshake(
            MessageType::CertificateVerify,
            handshake_create_certificate_verify,
        )?;

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

    /// Waiting for Finished message
    AwaitingFinished,

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

            // Waiting for the final Finished message
            (HandshakeState::AwaitingFinished, MessageType::NewSessionTicket) => {
                Ok(HandshakeState::AwaitingFinished)
            }
            (HandshakeState::AwaitingFinished, MessageType::Finished) => {
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

fn handshake_create_client_hello(
    body: &mut Buf<'static>,
    engine: &mut Engine,
    cookie: Cookie,
    random: Random,
    session_id: SessionId,
    extension_data: &mut Buf<'static>,
) -> Result<(), Error> {
    let client_version = ProtocolVersion::DTLS1_2;

    // Get the client certificate type
    let cert_type = engine.crypto_context().signature_algorithm();

    // Get compatible cipher suites for our certificate type
    let compatible_suites = CipherSuite::compatible_with_certificate(cert_type);

    // Offer only suites that are both allowed by Config and compatible with our key
    let cipher_suites: ArrayVec<[CipherSuite; 32]> = compatible_suites
        .iter()
        .copied()
        .filter(|suite| engine.is_cipher_suite_allowed(*suite))
        .filter(|suite| engine.crypto_context().is_cipher_suite_compatible(*suite))
        .take(32)
        .collect();

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
        random,
        session_id,
        cookie,
        cipher_suites,
        compression_methods,
    )
    .with_extensions(extension_data);

    client_hello.serialize(body);
    Ok(())
}

fn handshake_create_certificate(body: &mut Buf<'static>, engine: &mut Engine) -> Result<(), Error> {
    let crypto = engine.crypto_context();
    let client_cert = crypto.get_client_certificate();
    client_cert.serialize(body);
    Ok(())
}

fn handshake_create_client_key_exchange(
    body: &mut Buf<'static>,
    engine: &mut Engine,
) -> Result<(), Error> {
    // Just check that a cipher suite exists without binding to unused variable
    let Some(cipher_suite) = engine.cipher_suite() else {
        return Err(Error::UnexpectedMessage(
            "No cipher suite selected".to_string(),
        ));
    };
    let key_exchange_algorithm = cipher_suite.as_key_exchange_algorithm();

    debug!("Using key exchange algorithm: {:?}", key_exchange_algorithm);

    // For ECDHE, get curve info before we create the handshake (to avoid borrow issues)
    let curve_info = if key_exchange_algorithm == KeyExchangeAlgorithm::EECDH {
        engine.crypto_context().get_key_exchange_curve_info()
    } else {
        None
    };

    // Generate key exchange data
    let public_key = engine
        .crypto_context_mut()
        .maybe_init_key_exchange()
        .map_err(|e| Error::CryptoError(format!("Failed to generate key exchange: {}", e)))?
        .to_vec();

    debug!("Generated public key size: {} bytes", public_key.len());

    // Create a properly formatted ClientKeyExchange message based on the key exchange algorithm
    let exchange_keys = match key_exchange_algorithm {
        KeyExchangeAlgorithm::EECDH => {
            // For ECDHE, use the curve information we retrieved earlier
            let Some((curve_type, named_curve)) = curve_info else {
                unreachable!("No curve info available for ECDHE");
            };

            debug!(
                "Using ECDHE curve info: {:?}, {:?}",
                curve_type, named_curve
            );

            // Create ClientEcdhKeys with the proper curve information and public key
            let ecdh_keys = ClientEcdhKeys::new(curve_type, named_curve, &public_key);
            ExchangeKeys::Ecdh(ecdh_keys)
        }
        KeyExchangeAlgorithm::EDH => {
            // For DHE, use the standard encoding
            let dh_public =
                ClientDiffieHellmanPublic::new(PublicValueEncoding::Explicit, &public_key);
            ExchangeKeys::DhAnon(dh_public)
        }
        _ => {
            // Create a default format for unknown algorithms
            let dh_public =
                ClientDiffieHellmanPublic::new(PublicValueEncoding::Explicit, &public_key);
            ExchangeKeys::DhAnon(dh_public)
        }
    };

    // Wrap in ClientKeyExchange and serialize
    let client_key_exchange = ClientKeyExchange::new(exchange_keys);

    client_key_exchange.serialize(body);

    Ok(())
}

fn handshake_create_certificate_verify(
    body: &mut Buf<'static>,
    engine: &mut Engine,
) -> Result<(), Error> {
    // The hash algorithm to use is the default for the private key type, not
    // the one negotiated to use with the selected cipher suite. I.e.
    // if we negotiate ECDHE_ECDSA_AES256_GCM_SHA384, we are gogin to use
    // SHA384 for the signature of the main crypto, but not for CertificateVerify
    // where a private key using P256 curve means we use SHA256.
    let hash_alg = engine.crypto_context().private_key_default_hash_algorithm();
    debug!("Using hash algorithm for signature: {:?}", hash_alg);

    // Get the signature algorithm type
    let sig_alg = engine.crypto_context().signature_algorithm();
    debug!("Using signature algorithm: {:?}", sig_alg);

    // Create the signature algorithm
    let algorithm = SignatureAndHashAlgorithm::new(hash_alg, sig_alg);

    let handshake_data = engine.handshake_data();

    // Sign all handshake messages
    let signature = engine
        .crypto_context()
        .sign_data(handshake_data, hash_alg)
        .map_err(|e| Error::CryptoError(format!("Failed to sign handshake messages: {}", e)))?;

    debug!("Generated signature size: {} bytes", signature.len());

    // Create the digitally signed structure
    let digitally_signed = DigitallySigned::new(algorithm, &signature);

    // Create the certificate verify message
    let certificate_verify = CertificateVerify::new(digitally_signed);

    certificate_verify.serialize(body);
    Ok(())
}
