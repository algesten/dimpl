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
// This implementation is a Sans-IO DTLS client.

use std::collections::VecDeque;
use std::time::Instant;

use arrayvec::ArrayVec;

use crate::buffer::{Buf, ToBuf};
use crate::engine::Engine;
use crate::message::{Body, CertificateVerify, ClientEcdhKeys, ClientHello, ClientKeyExchange};
use crate::message::{CompressionMethod, ContentType, Cookie, DigitallySigned, ExchangeKeys};
use crate::message::{ExtensionType, Finished, KeyExchangeAlgorithm, MessageType, ProtocolVersion};
use crate::message::{Random, SessionId, SignatureAndHashAlgorithm, UseSrtpExtension};
use crate::{CipherSuite, Error, KeyingMaterial, Output, Server, SrtpProfile};

/// DTLS client
pub struct Client {
    /// Current client state.
    state: State,

    /// Engine in common between server and client.
    engine: Engine,

    /// Random unique data (with gmt timestamp). Used for signature checks.
    random: Option<Random>,

    /// SessionId is set by the server and only sent by the client if we
    /// are reusing a session (key renegotiation).
    session_id: Option<SessionId>,

    /// Cookie is sent by the server in the optional HelloVerifyRequest.
    /// It might remain null if there is no HelloVerifyRequest.
    cookie: Option<Cookie>,

    /// Storage for extension data
    extension_data: Buf,

    /// The negotiated SRTP profile (if any)
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Server random. Set by ServerHello.
    server_random: Option<Random>,

    /// Server certificates
    server_certificates: Vec<Buf>,

    /// Buffer for defragmenting handshakes
    defragment_buffer: Buf,

    /// Whether we requested a CertificateVerify
    certificate_verify: bool,

    /// Captured session hash for Extended Master Secret (RFC 7627)
    /// This is captured after ServerHelloDone to include the correct handshake messages
    captured_session_hash: Option<Vec<u8>>,

    /// The last now we seen
    last_now: Option<Instant>,

    /// Local events
    local_events: VecDeque<LocalEvent>,

    /// Data that is sent before we are connected.
    queued_data: Vec<Buf>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LocalEvent {
    PeerCert,
    Connected,
    KeyingMaterial(ArrayVec<u8, 128>, SrtpProfile),
}

impl Client {
    pub(crate) fn new_with_engine(mut engine: Engine) -> Client {
        engine.set_client(true);

        Client {
            state: State::SendClientHello,
            engine,
            random: None,
            session_id: None,
            cookie: None,
            extension_data: Buf::new(),
            negotiated_srtp_profile: None,
            server_random: None,
            server_certificates: Vec::with_capacity(3),
            defragment_buffer: Buf::new(),
            certificate_verify: false,
            captured_session_hash: None,
            last_now: None,
            local_events: VecDeque::new(),
            queued_data: Vec::new(),
        }
    }

    pub fn into_server(self) -> Server {
        Server::new_with_engine(self.engine)
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.engine.parse_packet(packet)?;
        self.make_progress()?;
        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        let last_now = self
            .last_now
            .expect("need handle_timeout before poll_output");

        if let Some(event) = self.local_events.pop_front() {
            return event.into_output(buf, &self.server_certificates);
        }

        self.engine.poll_output(buf, last_now)
    }

    /// Explicitly start the handshake process by sending a ClientHello
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.last_now = Some(now);
        if self.random.is_none() {
            self.random = Some(Random::new(now));
        }
        self.engine.handle_timeout(now)?;
        self.make_progress()?;
        Ok(())
    }

    /// Send application data when the client is in the Running state
    ///
    /// This should only be called when the client is in the Running state,
    /// after the handshake is complete.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::AwaitApplicationData {
            self.queued_data.push(data.to_buf());
            return Ok(());
        }

        // Use the engine's create_record to send application data
        // The encryption is now handled in the engine
        self.engine
            .create_record(ContentType::ApplicationData, 1, false, |body| {
                body.extend_from_slice(data);
            })?;

        Ok(())
    }

    fn make_progress(&mut self) -> Result<(), Error> {
        loop {
            let prev_state = self.state;

            let new_state = prev_state.make_progress(self)?;
            if prev_state != new_state {
                self.state = new_state;
                trace!("{:?} -> {:?}", prev_state, new_state);
            } else {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    SendClientHello,
    AwaitHelloVerifyRequest,
    AwaitServerHello,
    AwaitCertificate,
    AwaitServerKeyExchange,
    AwaitCertificateRequest,
    AwaitServerHelloDone,
    SendCertificate,
    SendClientKeyExchange,
    SendCertificateVerify,
    SendChangeCipherSpec,
    SendFinished,
    AwaitChangeCipherSpec,
    AwaitNewSessionTicket,
    AwaitFinished,
    AwaitApplicationData,
}

impl State {
    fn make_progress(self, client: &mut Client) -> Result<Self, Error> {
        match self {
            State::SendClientHello => self.send_client_hello(client),
            State::AwaitHelloVerifyRequest => self.await_hello_verify_request(client),
            State::AwaitServerHello => self.await_server_hello(client),
            State::AwaitCertificate => self.await_certificate(client),
            State::AwaitServerKeyExchange => self.await_server_key_exchange(client),
            State::AwaitCertificateRequest => self.await_certificate_request(client),
            State::AwaitServerHelloDone => self.await_server_hello_done(client),
            State::SendCertificate => self.send_certificate(client),
            State::SendClientKeyExchange => self.send_client_key_exchange(client),
            State::SendCertificateVerify => self.send_certificate_verify(client),
            State::SendChangeCipherSpec => self.send_change_cipher_spec(client),
            State::SendFinished => self.send_finished(client),
            State::AwaitChangeCipherSpec => self.await_change_cipher_spec(client),
            State::AwaitNewSessionTicket => self.await_new_session_ticket(client),
            State::AwaitFinished => self.await_finished(client),
            State::AwaitApplicationData => self.await_application_data(client),
        }
    }

    fn send_client_hello(self, client: &mut Client) -> Result<Self, Error> {
        let session_id = client.session_id.unwrap_or_else(SessionId::empty);
        let cookie = client.cookie.unwrap_or_else(Cookie::empty);
        // unwrap: is ok because we set the random in handle_timeout
        let random = client.random.unwrap();

        // Determine flight number: 1 for initial CH, 3 for retransmit with cookie
        let flight_no = if client.cookie.is_none() { 1 } else { 3 };
        client.engine.flight_begin(flight_no);

        client
            .engine
            .create_handshake(MessageType::ClientHello, |body, engine| {
                handshake_create_client_hello(
                    body,
                    engine,
                    cookie,
                    random,
                    session_id,
                    &mut client.extension_data,
                )
            })?;

        let can_hello_verify = client.cookie.is_none();

        if can_hello_verify {
            Ok(Self::AwaitHelloVerifyRequest)
        } else {
            Ok(Self::AwaitServerHello)
        }
    }

    fn await_hello_verify_request(self, client: &mut Client) -> Result<Self, Error> {
        let has_hello = client
            .engine
            .has_complete_handshake(MessageType::ServerHello);

        // Got ServerHello, skip HelloVerifyRequest
        if has_hello {
            return Ok(Self::AwaitServerHello);
        }

        let maybe = client.engine.next_handshake(
            MessageType::HelloVerifyRequest,
            &mut client.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            // Stay in this state
            return Ok(self);
        };

        let Body::HelloVerifyRequest(h) = handshake.body else {
            unreachable!()
        };

        // Enforce DTLS 1.2 version in HelloVerifyRequest
        if h.server_version != ProtocolVersion::DTLS1_2 {
            return Err(Error::SecurityError(format!(
                "Unsupported DTLS version in HelloVerifyRequest: {:?}",
                h.server_version
            )));
        }

        debug!(
            "Received HelloVerifyRequest with cookie length: {}",
            h.cookie.len()
        );

        // Set cookie for next ClientHello
        client.cookie = Some(h.cookie);

        // HelloVerifyRequest exchange must not be part of the handshake transcript.
        // Reset transcript so the following ClientHello (with cookie) starts a fresh transcript
        // matching the server's expectation.
        trace!("Resetting handshake transcript after HelloVerifyRequest");
        client.engine.transcript_reset();

        // Redo ClientHello, now with cookie.
        Ok(Self::SendClientHello)
    }

    fn await_server_hello(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client
            .engine
            .next_handshake(MessageType::ServerHello, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::ServerHello(server_hello) = &handshake.body else {
            unreachable!()
        };

        debug!(
            "Received ServerHello with cipher suite: {:?}",
            server_hello.cipher_suite
        );

        // Enforce DTLS version
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
        let is_compatible = client
            .engine
            .crypto_context()
            .is_cipher_suite_compatible(cs);

        if !is_compatible {
            return Err(Error::SecurityError(format!(
                "Server selected incompatible cipher suite: {:?}",
                cs
            )));
        }

        if !client.engine.is_cipher_suite_allowed(cs) {
            return Err(Error::SecurityError(format!(
                "Server selected disallowed cipher suite: {:?}",
                cs
            )));
        }

        // Note: we keep offered suites local; we don't enforce echo here
        client.engine.set_cipher_suite(cs);
        client.session_id = Some(server_hello.session_id);
        client.server_random = Some(server_hello.random);

        let mut extended_master_secret = false;

        // Check for use_srtp and extended_master_secret extensions
        let Some(extensions) = &server_hello.extensions else {
            return Err(Error::IncompleteServerHello);
        };

        for extension in extensions {
            if extension.extension_type == ExtensionType::UseSrtp {
                // Parse the use_srtp extension to get the selected profile
                if let Ok((_, use_srtp)) = UseSrtpExtension::parse(extension.extension_data) {
                    // Store the first profile as our negotiated profile
                    if !use_srtp.profiles.is_empty() {
                        client.negotiated_srtp_profile = Some(use_srtp.profiles[0].into());
                        trace!(
                            "ServerHello UseSRTP extension processed; selected profile: {:?}",
                            client.negotiated_srtp_profile
                        );
                    }
                } else {
                    warn!("Failed to parse UseSrtp extension");
                }
            }

            // We are to use extended master secret
            if extension.extension_type == ExtensionType::ExtendedMasterSecret {
                extended_master_secret = true;
                trace!("Server negotiated Extended Master Secret");
            }
        }

        // Without extended master secret, in DTLS1.2 a security attack
        // reusing the same master secret is possible.
        if !extended_master_secret {
            return Err(Error::SecurityError(
                "Extended Master Secret not negotiated".to_string(),
            ));
        }

        if let Some(profile) = client.negotiated_srtp_profile {
            debug!("Negotiated SRTP profile: {:?}", profile);
        }
        trace!("Extended Master Secret enabled");

        Ok(Self::AwaitCertificate)
    }

    fn await_certificate(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client
            .engine
            .next_handshake(MessageType::Certificate, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::Certificate(certificate) = &handshake.body else {
            unreachable!()
        };

        if certificate.certificate_list.is_empty() {
            return Err(Error::UnexpectedMessage(
                "No server certificate received".to_string(),
            ));
        }

        debug!(
            "Received Certificate message with {} certificate(s)",
            certificate.certificate_list.len()
        );

        // Convert ASN.1 certificates to byte arrays
        for (i, cert) in certificate.certificate_list.iter().enumerate() {
            let cert_data = cert.0.to_vec();
            trace!("Certificate #{} size: {} bytes", i + 1, cert_data.len());
            client.server_certificates.push(cert_data.to_buf());
        }

        Ok(Self::AwaitServerKeyExchange)
    }

    fn await_server_key_exchange(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client.engine.next_handshake(
            MessageType::ServerKeyExchange,
            &mut client.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::ServerKeyExchange(server_key_exchange) = &handshake.body else {
            unreachable!()
        };

        let Some(d_signed) = server_key_exchange.signature() else {
            // We do not support anonymous key exchange
            return Err(Error::UnexpectedMessage(
                "ServerKeyExchange without signature".to_string(),
            ));
        };

        // unwrap: is ok because we verify the order of the flight
        let client_random = client.random.unwrap();
        let server_random = client.server_random.unwrap();

        let mut signed_data = Buf::new();
        client_random.serialize(&mut signed_data);
        server_random.serialize(&mut signed_data);
        server_key_exchange.serialize(&mut signed_data, false);

        let cipher_suite = client
            .engine
            .cipher_suite()
            .ok_or_else(|| Error::UnexpectedMessage("No cipher suite selected".to_string()))?;

        // Ensure the server's (hash, signature) pair was offered by the client
        let offered = SignatureAndHashAlgorithm::supported().contains(&d_signed.algorithm);
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
        let cert_der = client.server_certificates.first().unwrap();

        client
            .engine
            .crypto_context_mut()
            .verify_signature(&signed_data, d_signed, cert_der)
            .map_err(|e| {
                Error::CryptoError(format!(
                    "Failed to verify server key exchange signature: {}",
                    e
                ))
            })?;

        trace!(
            "ServerKeyExchange signature verified: {:?}",
            d_signed.algorithm
        );

        // Process the server key exchange message
        client
            .engine
            .crypto_context_mut()
            .process_server_key_exchange(server_key_exchange)
            .map_err(|e| {
                Error::CryptoError(format!("Failed to process server key exchange: {}", e))
            })?;

        Ok(Self::AwaitCertificateRequest)
    }

    fn await_certificate_request(self, client: &mut Client) -> Result<Self, Error> {
        let has_done = client
            .engine
            .has_complete_handshake(MessageType::ServerHelloDone);

        if has_done {
            return Ok(Self::AwaitServerHelloDone);
        }

        let maybe = client.engine.next_handshake(
            MessageType::CertificateRequest,
            &mut client.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            // stay in same state
            return Ok(self);
        };

        let Body::CertificateRequest(cr) = &handshake.body else {
            unreachable!()
        };

        // Check that the hash algorithm that is default fo the PrivateKey in use
        // is one of the supported by the CertificateRequest
        let hash_algorithm = client
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

        debug!("Received CertificateRequest; enabling client authentication path");
        client.certificate_verify = true;

        Ok(Self::AwaitServerHelloDone)
    }

    fn await_server_hello_done(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client
            .engine
            .next_handshake(MessageType::ServerHelloDone, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // stay in same state
            return Ok(self);
        };

        let Body::ServerHelloDone = handshake.body else {
            unreachable!()
        };

        trace!("Received ServerHelloDone");

        // Validate the server certificate
        if client.server_certificates.is_empty() {
            return Err(Error::CertificateError(
                "No server certificate received".to_string(),
            ));
        }

        // Send the server certificate as an event
        if !client.server_certificates.is_empty() {
            client.local_events.push_back(LocalEvent::PeerCert);
        }

        if client.certificate_verify {
            Ok(Self::SendCertificate)
        } else {
            Ok(Self::SendClientKeyExchange)
        }
    }

    fn send_certificate(self, client: &mut Client) -> Result<Self, Error> {
        debug!("Sending Certificate");

        // Start/restart flight timer for client Flight 5
        client.engine.flight_begin(5);

        // Now use the engine with the stored data
        client
            .engine
            .create_handshake(MessageType::Certificate, handshake_create_certificate)?;

        Ok(Self::SendClientKeyExchange)
    }

    fn send_client_key_exchange(self, client: &mut Client) -> Result<Self, Error> {
        trace!("Sending ClientKeyExchange");

        // Start/restart flight timer only if this flight did not start with Certificate
        if !client.certificate_verify {
            client.engine.flight_begin(5);
        }

        // Send client key exchange message
        client.engine.create_handshake(
            MessageType::ClientKeyExchange,
            handshake_create_client_key_exchange,
        )?;

        // Capture session hash now for Extended Master Secret (RFC 7627)
        // At this point, the session hash includes: ClientHello, ServerHello, Certificate,
        // ServerKeyExchange, CertificateRequest, ServerHelloDone, Certificate, ClientKeyExchange
        // This is correct per RFC 7627 - session hash should include messages up to and including ClientKeyExchange
        let cipher_suite = client
            .engine
            .cipher_suite()
            .ok_or_else(|| Error::UnexpectedMessage("No cipher suite selected".to_string()))?;

        let suite_hash = cipher_suite.hash_algorithm();
        client.captured_session_hash = Some(client.engine.transcript_hash(suite_hash));

        if client.certificate_verify {
            Ok(Self::SendCertificateVerify)
        } else {
            Ok(Self::SendChangeCipherSpec)
        }
    }

    fn send_certificate_verify(self, client: &mut Client) -> Result<Self, Error> {
        debug!("Sending CertificateVerify");

        // Send the certificate verify message
        client.engine.create_handshake(
            MessageType::CertificateVerify,
            handshake_create_certificate_verify,
        )?;

        Ok(Self::SendChangeCipherSpec)
    }

    fn send_change_cipher_spec(self, client: &mut Client) -> Result<Self, Error> {
        Self::derive_keys(client)?;

        // Send change cipher spec
        trace!("Sending ChangeCipherSpec");
        client
            .engine
            .create_record(ContentType::ChangeCipherSpec, 0, true, |body| {
                // Change cipher spec is just a single byte with value 1
                body.push(1);
            })?;

        Ok(Self::SendFinished)
    }

    fn derive_keys(client: &mut Client) -> Result<(), Error> {
        trace!("Deriving keys");
        let Some(cipher_suite) = client.engine.cipher_suite() else {
            return Err(Error::UnexpectedMessage(
                "No cipher suite selected".to_string(),
            ));
        };

        trace!("Using cipher suite for key derivation: {:?}", cipher_suite);

        let Some(server_random) = &client.server_random else {
            return Err(Error::UnexpectedMessage(
                "No server random available".to_string(),
            ));
        };

        // Extract and format the random values for key derivation
        let mut client_random_buf_b = Buf::new();
        let mut server_random_buf_b = Buf::new();

        // Serialize the random values to raw bytes
        // unwrap: is ok because we set the random in handle_timeout
        client.random.unwrap().serialize(&mut client_random_buf_b);
        server_random.serialize(&mut server_random_buf_b);
        let client_random_buf = client_random_buf_b.into_vec();
        let server_random_buf = server_random_buf_b.into_vec();

        // Derive master secret (use EMS if negotiated)
        let suite_hash = cipher_suite.hash_algorithm();

        // Use the captured session hash from when ServerHelloDone was received
        let session_hash = client.captured_session_hash.as_ref().ok_or_else(|| {
            Error::CryptoError(
                "Extended Master Secret negotiated but session hash not captured".to_string(),
            )
        })?;
        trace!(
            "Using captured session hash for Extended Master Secret (length: {})",
            session_hash.len()
        );
        client
            .engine
            .crypto_context_mut()
            .derive_extended_master_secret(session_hash, suite_hash)
            .map_err(|e| {
                Error::CryptoError(format!("Failed to derive extended master secret: {}", e))
            })?;

        // Derive the encryption/decryption keys
        client
            .engine
            .crypto_context_mut()
            .derive_keys(cipher_suite, &client_random_buf, &server_random_buf)
            .map_err(|e| Error::CryptoError(format!("Failed to derive keys: {}", e)))?;

        Ok(())
    }

    fn send_finished(self, client: &mut Client) -> Result<Self, Error> {
        trace!("Sending Finished message to complete handshake");

        client
            .engine
            .create_handshake(MessageType::Finished, |body, engine| {
                // Calculate verify data for Finished message using PRF
                let verify_data = engine.generate_verify_data(true)?;

                // Send finished message
                let finished = Finished::new(&verify_data);

                debug!("Generated verify data for Finished message (12 bytes)");

                finished.serialize(body);
                Ok(())
            })?;

        Ok(Self::AwaitChangeCipherSpec)
    }

    fn await_change_cipher_spec(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client.engine.next_record(ContentType::ChangeCipherSpec);

        let Some(_) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        // Drop any extra CCS resends to avoid being blocked
        trace!("Dropping any pending CCS resends from peer");
        client.engine.drop_pending_ccs();

        // Expect every record to be decrypted from now on.
        trace!("Received ChangeCipherSpec; enabling peer encryption");
        client.engine.enable_peer_encryption()?;

        Ok(Self::AwaitNewSessionTicket)
    }

    fn await_new_session_ticket(self, client: &mut Client) -> Result<Self, Error> {
        let has_finished = client.engine.has_complete_handshake(MessageType::Finished);

        if has_finished {
            return Ok(Self::AwaitFinished);
        }

        let maybe = client
            .engine
            .next_handshake(MessageType::NewSessionTicket, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::NewSessionTicket(_t) = handshake.body else {
            unreachable!()
        };

        // TODO(martin): handle ticket for restart

        trace!("Received NewSessionTicket");

        Ok(Self::AwaitFinished)
    }

    fn await_finished(self, client: &mut Client) -> Result<Self, Error> {
        // Generate expected verify data based on current transcript.
        // This must be done before next_handshake() below since
        // it should not include Finished itself.
        let expected = client.engine.generate_verify_data(false)?;

        let maybe = client
            .engine
            .next_handshake(MessageType::Finished, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // stay in same state
            return Ok(self);
        };

        let Body::Finished(finished) = &handshake.body else {
            panic!("Finished message should have been parsed");
        };

        // If verification fails, return an error
        trace!(
            "Finished.verify_data received len={}, expected len={}",
            finished.verify_data.len(),
            expected.len()
        );
        if finished.verify_data != expected {
            return Err(Error::SecurityError(
                "Server Finished verification failed".to_string(),
            ));
        }

        trace!("Server Finished verified successfully");

        // Receiving server Finished implicitly acks our Flight 5; stop resends
        client.engine.flight_stop_resend_timers();

        // Emit Connected event
        client.local_events.push_back(LocalEvent::Connected);

        // Extract and emit SRTP keying material if we have a negotiated profile
        if let Some(profile) = client.negotiated_srtp_profile {
            let suite_hash = client.engine.cipher_suite().unwrap().hash_algorithm();

            if let Ok(keying_material) = client
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
                // expect should be correct here since we negotiated the profile
                let profile = client
                    .negotiated_srtp_profile
                    .expect("SRTP profile should be negotiated");
                client
                    .local_events
                    .push_back(LocalEvent::KeyingMaterial(keying_material, profile));
            }
        }

        client.engine.release_application_data();

        debug!("Handshake complete; ready for application data");

        Ok(Self::AwaitApplicationData)
    }

    fn await_application_data(self, client: &mut Client) -> Result<Self, Error> {
        if !client.queued_data.is_empty() {
            debug!(
                "Sending queued application data: {}",
                client.queued_data.len()
            );
            for data in client.queued_data.drain(..) {
                client
                    .engine
                    .create_record(ContentType::ApplicationData, 1, false, |body| {
                        body.extend_from_slice(&data);
                    })?;
            }
        }

        Ok(self)
    }
}

fn handshake_create_client_hello(
    body: &mut Buf,
    engine: &mut Engine,
    cookie: Cookie,
    random: Random,
    session_id: SessionId,
    extension_data: &mut Buf,
) -> Result<(), Error> {
    let client_version = ProtocolVersion::DTLS1_2;

    // Get the client certificate type
    let cert_type = engine.crypto_context().signature_algorithm();

    // Get compatible cipher suites for our certificate type
    let compatible_suites = CipherSuite::compatible_with_certificate(cert_type);

    // Offer only suites that are both allowed by Config and compatible with our key
    let cipher_suites: ArrayVec<CipherSuite, 32> = compatible_suites
        .iter()
        .copied()
        .filter(|suite| {
            let is_allowed = engine.is_cipher_suite_allowed(*suite);
            let is_compatible = engine.crypto_context().is_cipher_suite_compatible(*suite);
            is_allowed && is_compatible
        })
        .take(32)
        .collect();

    debug!(
        "Sending ClientHello: DTLS version={:?}, cookie_len={}, offering {} cipher suites",
        client_version,
        cookie.len(),
        cipher_suites.len()
    );

    let mut compression_methods = ArrayVec::new();
    compression_methods.push(CompressionMethod::Null);

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

fn handshake_create_certificate(body: &mut Buf, engine: &mut Engine) -> Result<(), Error> {
    let crypto = engine.crypto_context();
    let client_cert = crypto.get_client_certificate();
    client_cert.serialize(body);
    Ok(())
}

fn handshake_create_client_key_exchange(body: &mut Buf, engine: &mut Engine) -> Result<(), Error> {
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

    trace!("Generated public key size: {} bytes", public_key.len());

    // Create a properly formatted ClientKeyExchange message based on the key exchange algorithm
    let exchange_keys = match key_exchange_algorithm {
        KeyExchangeAlgorithm::EECDH => {
            // For ECDHE, use the curve information we retrieved earlier
            let Some((curve_type, named_curve)) = curve_info else {
                unreachable!("No curve info available for ECDHE");
            };

            trace!(
                "Using ECDHE curve info: {:?}, {:?}",
                curve_type,
                named_curve
            );

            // Create ClientEcdhKeys with the proper curve information and public key
            let ecdh_keys = ClientEcdhKeys::new(curve_type, named_curve, &public_key);
            ExchangeKeys::Ecdh(ecdh_keys)
        }
        _ => {
            return Err(Error::SecurityError(
                "Unsupported key exchange algorithm".to_string(),
            ));
        }
    };

    // Wrap in ClientKeyExchange and serialize
    let client_key_exchange = ClientKeyExchange::new(exchange_keys);

    client_key_exchange.serialize(body);

    Ok(())
}

fn handshake_create_certificate_verify(body: &mut Buf, engine: &mut Engine) -> Result<(), Error> {
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

    let handshake_data = engine.transcript();

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

impl LocalEvent {
    pub fn into_output<'a>(self, buf: &'a mut [u8], peer_certs: &[Buf]) -> Output<'a> {
        match self {
            LocalEvent::PeerCert => {
                let l = peer_certs[0].len();
                assert!(
                    l <= buf.len(),
                    "Output buffer too small for peer certificate"
                );
                buf[..l].copy_from_slice(&peer_certs[0]);
                Output::PeerCert(&buf[..l])
            }
            LocalEvent::Connected => Output::Connected,
            LocalEvent::KeyingMaterial(m, profile) => {
                let l = m.len();
                assert!(
                    l <= buf.len(),
                    "Output buffer too small for keying material"
                );
                buf[..l].copy_from_slice(&m);
                let km = KeyingMaterial::new(&buf[..l]);
                Output::KeyingMaterial(km, profile)
            }
        }
    }
}
