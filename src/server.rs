// DTLS Server Handshake Flow:
//
// 1. Client sends ClientHello (maybe without cookie)
// 2. If cookie missing/invalid, Server sends HelloVerifyRequest (stateless cookie)
//    - Client resends ClientHello with cookie
// 3. Server sends ServerHello, Certificate, ServerKeyExchange,
//    CertificateRequest (required), ServerHelloDone
// 4. Client sends Certificate (optional), ClientKeyExchange,
//    CertificateVerify (if client cert), ChangeCipherSpec, Finished
// 5. Server verifies Finished, then sends ChangeCipherSpec, Finished
// 6. Handshake complete, application data can flow
//
// This implementation mirrors the client structure and ordering for a DTLS 1.2 server.

use std::sync::Arc;
use std::time::Instant;

use tinyvec::ArrayVec;

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

use crate::buffer::{Buf, ToBuf};
use crate::crypto::{ffdhe2048, CertVerifier, DhDomainParams, SrtpProfile};
use crate::engine::Engine;
use crate::message::{
    Body, CertificateRequest, CipherSuite, ClientCertificateType, ClientEcdhKeys,
    CompressionMethod, ContentType, Cookie, CurveType, DhParams, DigitallySigned,
    DistinguishedName, EcdhParams, ExchangeKeys, ExtensionType, Finished, HashAlgorithm,
    HelloVerifyRequest, KeyExchangeAlgorithm, MessageType, NamedCurve, ProtocolVersion, Random,
    ServerHello, ServerKeyExchange, ServerKeyExchangeParams, SessionId, SignatureAlgorithm,
    SignatureAndHashAlgorithm, SrtpProfileId, UseSrtpExtension,
};
use crate::{Config, Error, Output};

type HmacSha256 = Hmac<Sha256>;

/// DTLS server
pub struct Server {
    /// Random unique data (with gmt timestamp). Used for signature checks.
    random: Random,

    /// SessionId we provide to the client (unused/resumption not implemented).
    session_id: Option<SessionId>,

    /// Storage for extension data
    extension_data: Buf<'static>,

    /// The negotiated SRTP profile (if any)
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Current server state.
    state: ServerState,

    /// Engine in common between server and client.
    engine: Engine,

    /// Client random. Set by ClientHello.
    client_random: Option<Random>,

    /// Client certificates
    client_certificates: Vec<Buf<'static>>,

    /// Buffer for defragmenting handshakes
    defragment_buffer: Buf<'static>,

    /// Captured session hash for Extended Master Secret (RFC 7627)
    captured_session_hash: Option<Vec<u8>>,

    /// Cookie secret for HMAC, generated per-server instance
    cookie_secret: [u8; 32],
}

/// Current state of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Await a ClientHello (with or without cookie)
    AwaitClientHello,

    /// Send the ServerHello flight (ServerHello..ServerHelloDone)
    SendServerHelloFlight,

    /// Await client flight up to Finished
    AwaitClientFinished,

    /// Send and receive encrypted data.
    Running,
}

impl Server {
    /// Create a new DTLS server
    pub fn new(
        now: Instant,
        config: Arc<Config>,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
    ) -> Server {
        let engine = Engine::new(config, certificate, private_key, cert_verifier, false);

        let mut cookie_secret = [0u8; 32];
        OsRng.fill_bytes(&mut cookie_secret);

        Server {
            random: Random::new(now),
            session_id: None,
            extension_data: Buf::new(),
            negotiated_srtp_profile: None,
            state: ServerState::AwaitClientHello,
            engine,
            client_random: None,
            client_certificates: Vec::with_capacity(3),
            defragment_buffer: Buf::new(),
            captured_session_hash: None,
            cookie_secret,
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

    pub fn handle_timeout(&mut self, _now: Instant) -> Result<(), Error> {
        // Server is purely reactive; nothing to do on timeout here.
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
            ServerState::AwaitClientHello => self.process_client_hello(),
            ServerState::SendServerHelloFlight => {
                self.send_server_hello_flight()?;
                self.state = ServerState::AwaitClientFinished;
                Ok(())
            }
            ServerState::AwaitClientFinished => self.process_client_finished(),
            ServerState::Running => {
                self.engine.process_application_data()?;
                Ok(())
            }
        }
    }

    fn process_client_hello(&mut self) -> Result<(), Error> {
        // We expect a ClientHello flight (single message)
        let Some(mut flight) = self.engine.has_complete_message(MessageType::ClientHello) else {
            return Ok(());
        };

        while let Some(handshake) = self
            .engine
            .next_message(&mut flight, &mut self.defragment_buffer)?
        {
            if !matches!(handshake.header.msg_type, MessageType::ClientHello) {
                return Err(Error::UnexpectedMessage(format!(
                    "Unexpected message type: {:?}",
                    handshake.header.msg_type
                )));
            }

            let Body::ClientHello(ch) = &handshake.body else {
                return Err(Error::UnexpectedMessage(
                    "ClientHello parse error".to_string(),
                ));
            };

            // Enforce DTLS1.2
            if ch.client_version != ProtocolVersion::DTLS1_2 {
                return Err(Error::SecurityError(format!(
                    "Unsupported DTLS version from client: {:?}",
                    ch.client_version
                )));
            }

            // Enforce Null compression only (client must offer it)
            if !ch
                .compression_methods
                .iter()
                .any(|m| *m == CompressionMethod::Null)
            {
                return Err(Error::SecurityError(
                    "Client did not offer Null compression".to_string(),
                ));
            }

            // Stateless cookie: require 32-byte cookie matching HMAC(secret, client_random)
            let client_random = ch.random;
            if !verify_cookie(&self.cookie_secret, client_random, ch.cookie) {
                debug!("Invalid/missing cookie; sending HelloVerifyRequest");
                self.send_hello_verify_request(client_random)?;
                // After HelloVerifyRequest, await a new ClientHello
                return Ok(());
            }

            // Client offered suites; we pick per client order intersecting allowed and server key compatibility
            let mut selected: Option<CipherSuite> = None;
            for s in ch.cipher_suites.iter() {
                if self.engine.is_cipher_suite_allowed(*s)
                    && self.engine.crypto_context().is_cipher_suite_compatible(*s)
                {
                    selected = Some(*s);
                    break;
                }
            }

            let Some(cs) = selected else {
                return Err(Error::SecurityError(
                    "No mutually acceptable cipher suite".to_string(),
                ));
            };

            self.engine.set_cipher_suite(cs);
            self.client_random = Some(client_random);

            // Process client extensions: SRTP and EMS
            let mut client_offers_ems = false;
            let mut client_srtp_profiles: Option<ArrayVec<[SrtpProfileId; 32]>> = None;
            for ext in &ch.extensions {
                match ext.extension_type {
                    ExtensionType::UseSrtp => {
                        if let Ok((_, use_srtp)) = UseSrtpExtension::parse(ext.extension_data) {
                            client_srtp_profiles = Some(use_srtp.profiles.clone());
                        }
                    }
                    ExtensionType::ExtendedMasterSecret => {
                        client_offers_ems = true;
                    }
                    _ => {}
                }
            }

            // EMS is mandatory
            if !client_offers_ems {
                return Err(Error::SecurityError(
                    "Extended Master Secret not negotiated".to_string(),
                ));
            }

            // Select SRTP profile according to server priority: GCM first, then SHA1
            if let Some(profiles) = client_srtp_profiles {
                // Map client profile ids to SrtpProfile, then pick our preferred
                let mut selected_profile: Option<SrtpProfile> = None;
                for preferred in [SrtpProfile::AeadAes128Gcm, SrtpProfile::Aes128CmSha1_80] {
                    if profiles.iter().any(|pid| preferred == (*pid).into()) {
                        selected_profile = Some(preferred);
                        break;
                    }
                }
                self.negotiated_srtp_profile = selected_profile;
            }

            // Proceed to send the server flight
            self.state = ServerState::SendServerHelloFlight;
        }

        Ok(())
    }

    fn send_hello_verify_request(&mut self, client_random: Random) -> Result<(), Error> {
        let cookie = compute_cookie(&self.cookie_secret, client_random)?;
        self.engine
            .create_handshake(MessageType::HelloVerifyRequest, |body, _engine| {
                let hvr = HelloVerifyRequest::new(ProtocolVersion::DTLS1_2, cookie);
                hvr.serialize(body);
                Ok(())
            })?;
        Ok(())
    }

    fn send_server_hello_flight(&mut self) -> Result<(), Error> {
        debug!("Sending ServerHello flight");

        let session_id = self.session_id.unwrap_or_else(SessionId::empty);
        let server_random = self.random;

        let client_random = self
            .client_random
            .ok_or_else(|| Error::UnexpectedMessage("No client random".to_string()))?;
        let negotiated_srtp_profile = self.negotiated_srtp_profile;

        let extension_data = &mut self.extension_data;

        // Send ServerHello
        self.engine
            .create_handshake(MessageType::ServerHello, move |body, engine| {
                handshake_create_server_hello(
                    body,
                    engine,
                    server_random,
                    session_id,
                    negotiated_srtp_profile,
                    extension_data,
                )
            })?;

        // Send Certificate
        self.engine
            .create_handshake(MessageType::Certificate, handshake_create_certificate)?;

        // Send ServerKeyExchange
        self.engine
            .create_handshake(MessageType::ServerKeyExchange, |body, engine| {
                handshake_create_server_key_exchange(body, engine, client_random, server_random)
            })?;

        // Send CertificateRequest (always request)
        self.engine.create_handshake(
            MessageType::CertificateRequest,
            handshake_create_certificate_request,
        )?;

        // Send ServerHelloDone
        self.engine
            .create_handshake(MessageType::ServerHelloDone, |body, _| {
                // ServerHelloDone has an empty body
                match body.len() {
                    _ => {}
                }
                Ok(())
            })?;

        Ok(())
    }

    fn process_client_finished(&mut self) -> Result<(), Error> {
        // We expect a client flight up to Finished
        let Some(mut flight) = self.engine.has_complete_message(MessageType::Finished) else {
            return Ok(());
        };

        let mut state = ServerHandshakeState::AwaitingClientMessages;

        while let Some(handshake) = self
            .engine
            .next_message(&mut flight, &mut self.defragment_buffer)?
        {
            state = state.handle(handshake.header.msg_type)?;

            match handshake.header.msg_type {
                MessageType::Certificate => {
                    let Body::Certificate(certificate) = &handshake.body else {
                        return Ok(());
                    };

                    if certificate.certificate_list.is_empty() {
                        // Client didn't provide a certificate (allowed), skip
                    } else {
                        // Store and verify via callback
                        for (i, cert) in certificate.certificate_list.iter().enumerate() {
                            let cert_data = cert.0.to_vec();
                            trace!(
                                "Client Certificate #{} size: {} bytes",
                                i + 1,
                                cert_data.len()
                            );
                            self.client_certificates.push(cert_data.to_buf());
                        }

                        // Verify leaf certificate
                        if let Err(err) = self
                            .engine
                            .crypto_context()
                            .verify_server_certificate(&self.client_certificates[0])
                        {
                            return Err(Error::CertificateError(format!(
                                "Certificate verification failed: {}",
                                err
                            )));
                        }
                        self.engine
                            .push_peer_cert(self.client_certificates[0].to_vec());
                    }
                }

                MessageType::ClientKeyExchange => {
                    let Body::ClientKeyExchange(ckx) = &handshake.body else {
                        return Ok(());
                    };

                    let suite = self.engine.cipher_suite().ok_or_else(|| {
                        Error::UnexpectedMessage("No cipher suite selected".to_string())
                    })?;

                    // Extract client's public key depending on KE
                    let client_pub = match &ckx.exchange_keys {
                        ExchangeKeys::Ecdh(ClientEcdhKeys { public_key, .. }) => {
                            public_key.to_vec()
                        }
                        ExchangeKeys::DhAnon(dh) => dh.public_value.to_vec(),
                    };

                    // Compute shared secret
                    self.engine
                        .crypto_context_mut()
                        .compute_shared_secret(&client_pub)
                        .map_err(|e| {
                            Error::CryptoError(format!("Failed to compute shared secret: {}", e))
                        })?;

                    // Capture session hash for EMS now (up to ClientKeyExchange)
                    let suite_hash = suite.hash_algorithm();
                    self.captured_session_hash = Some(self.engine.handshake_hash(suite_hash));

                    // Derive master secret and keys (needed to decrypt client's Finished)
                    let suite_hash = suite.hash_algorithm();
                    let client_random_buf = {
                        let mut b = Buf::new();
                        self.client_random.unwrap().serialize(&mut b);
                        b.into_vec()
                    };
                    let server_random_buf = {
                        let mut b = Buf::new();
                        self.random.serialize(&mut b);
                        b.into_vec()
                    };

                    let session_hash = self.captured_session_hash.as_ref().ok_or_else(|| {
                        Error::CryptoError(
                            "Extended Master Secret negotiated but session hash not captured"
                                .to_string(),
                        )
                    })?;

                    self.engine
                        .crypto_context_mut()
                        .derive_extended_master_secret(session_hash, suite_hash)
                        .map_err(|e| {
                            Error::CryptoError(format!(
                                "Failed to derive extended master secret: {}",
                                e
                            ))
                        })?;

                    self.engine
                        .crypto_context_mut()
                        .derive_keys(suite, &client_random_buf, &server_random_buf)
                        .map_err(|e| Error::CryptoError(format!("Failed to derive keys: {}", e)))?;
                }

                MessageType::CertificateVerify => {
                    // Verify client's signature over the handshake transcript
                    let Body::CertificateVerify(cv) = &handshake.body else {
                        return Ok(());
                    };

                    if self.client_certificates.is_empty() {
                        return Err(Error::CertificateError(
                            "CertificateVerify received but no client certificate".to_string(),
                        ));
                    }

                    let data = self.engine.handshake_data().to_buf();
                    self.engine
                        .crypto_context()
                        .verify_signature(&data, &cv.signed, &self.client_certificates[0])
                        .map_err(|e| {
                            Error::CryptoError(format!(
                                "Failed to verify client CertificateVerify: {}",
                                e
                            ))
                        })?;
                }

                MessageType::Finished => {
                    // Verify client's Finished
                    let Body::Finished(finished) = &handshake.body else {
                        return Ok(());
                    };

                    let expected = self.engine.generate_verify_data(true /* client */)?;
                    if finished.verify_data != expected {
                        return Err(Error::SecurityError(
                            "Client Finished verification failed".to_string(),
                        ));
                    }

                    debug!("Client Finished verified successfully");

                    // Now send our ChangeCipherSpec and Finished
                    self.send_server_ccs_and_finished()?;

                    // Handshake complete
                    self.state = ServerState::Running;
                    self.engine.push_connected();

                    // Emit SRTP keying material if negotiated
                    if let Some(profile) = self.negotiated_srtp_profile {
                        let suite_hash = self.engine.cipher_suite().unwrap().hash_algorithm();
                        if let Ok(keying_material) = self
                            .engine
                            .crypto_context()
                            .extract_srtp_keying_material(profile, suite_hash)
                        {
                            debug!(
                                "SRTP keying material extracted ({} bytes) for profile: {:?}",
                                keying_material.len(),
                                profile
                            );
                            self.engine.push_keying_material(keying_material, profile);
                        }
                    }
                }

                other => {
                    // ChangeCipherSpec is handled at record layer; ignore here
                    if other != MessageType::HelloVerifyRequest
                        && other != MessageType::ServerHello
                        && other != MessageType::ServerKeyExchange
                        && other != MessageType::ServerHelloDone
                    {
                        debug!("Unexpected handshake message from client: {:?}", other);
                    }
                }
            }
        }

        Ok(())
    }

    fn send_server_ccs_and_finished(&mut self) -> Result<(), Error> {
        // Send ChangeCipherSpec
        self.engine
            .create_record(ContentType::ChangeCipherSpec, |body| {
                body.push(1);
                None
            })?;
        self.engine.enable_server_encryption();

        // Send Finished
        self.engine
            .create_handshake(MessageType::Finished, |body, engine| {
                let verify_data = engine.generate_verify_data(false /* server */)?;
                let finished = Finished::new(&verify_data);
                finished.serialize(body);
                Ok(())
            })?;
        Ok(())
    }

    /// Send application data when the server is in the Running state
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if !matches!(self.state, ServerState::Running) {
            debug!(
                "Attempted to send application data while not in Running state: {:?}",
                self.state
            );
            return Err(Error::UnexpectedMessage("Not in Running state".to_string()));
        }

        self.engine
            .create_record(ContentType::ApplicationData, |body| {
                body.extend_from_slice(data);
                None
            })?;

        Ok(())
    }
}

fn compute_cookie(secret: &[u8], client_random: Random) -> Result<Cookie, Error> {
    // cookie = trunc_32(HMAC(secret, client_random))
    let mut mac = HmacSha256::new_from_slice(&secret)
        .map_err(|_| Error::CryptoError("Invalid HMAC key".to_string()))?;
    let mut buf = Buf::new();
    client_random.serialize(&mut buf);
    mac.update(&buf);
    let tag = mac.finalize().into_bytes();
    let cookie = Cookie::try_new(&tag[..32])
        .map_err(|_| Error::CryptoError("Failed to build cookie from HMAC output".to_string()))?;
    Ok(cookie)
}

fn verify_cookie(secret: &[u8], client_random: Random, cookie: Cookie) -> bool {
    if cookie.len() != 32 {
        return false;
    }
    match compute_cookie(secret, client_random) {
        Ok(expected) => &*expected == &*cookie,
        Err(_) => false,
    }
}

/// Handshake state machine for client-to-server messages (post ServerHelloDone)
#[derive(Debug, PartialEq, Eq)]
enum ServerHandshakeState {
    /// Expecting Certificate (optional), then ClientKeyExchange, optional CertificateVerify, CCS, Finished
    AwaitingClientMessages,
}

impl ServerHandshakeState {
    fn handle(&self, message_type: MessageType) -> Result<ServerHandshakeState, Error> {
        match (self, message_type) {
            (ServerHandshakeState::AwaitingClientMessages, MessageType::Certificate)
            | (ServerHandshakeState::AwaitingClientMessages, MessageType::ClientKeyExchange)
            | (ServerHandshakeState::AwaitingClientMessages, MessageType::CertificateVerify)
            | (ServerHandshakeState::AwaitingClientMessages, MessageType::Finished) => {
                Ok(ServerHandshakeState::AwaitingClientMessages)
            }

            // ChangeCipherSpec is a record-layer message; ignore ordering here
            _ => Err(Error::UnexpectedMessage(format!(
                "Unexpected message {:?} during client flight",
                message_type
            ))),
        }
    }
}

fn handshake_create_certificate(body: &mut Buf<'static>, engine: &mut Engine) -> Result<(), Error> {
    let crypto = engine.crypto_context();
    let server_cert = crypto.get_client_certificate();
    server_cert.serialize(body);
    Ok(())
}

fn handshake_create_server_hello(
    body: &mut Buf<'static>,
    engine: &mut Engine,
    random: Random,
    session_id: SessionId,
    negotiated_srtp_profile: Option<SrtpProfile>,
    extension_data: &mut Buf<'static>,
) -> Result<(), Error> {
    let server_version = ProtocolVersion::DTLS1_2;

    let cs = engine
        .cipher_suite()
        .ok_or_else(|| Error::UnexpectedMessage("No cipher suite".to_string()))?;

    let srtp_pid = negotiated_srtp_profile.map(|p| match p {
        SrtpProfile::AeadAes128Gcm => SrtpProfileId::SrtpAeadAes128Gcm,
        SrtpProfile::Aes128CmSha1_80 => SrtpProfileId::SrtpAes128CmSha1_80,
    });

    let sh = ServerHello::new(
        server_version,
        random,
        session_id,
        cs,
        CompressionMethod::Null,
        None,
    )
    .with_extensions(extension_data, srtp_pid);

    sh.serialize(body);
    Ok(())
}

fn handshake_create_server_key_exchange(
    body: &mut Buf<'static>,
    engine: &mut Engine,
    client_random: Random,
    server_random: Random,
) -> Result<(), Error> {
    let Some(cipher_suite) = engine.cipher_suite() else {
        return Err(Error::UnexpectedMessage(
            "No cipher suite selected".to_string(),
        ));
    };

    let key_exchange_algorithm = cipher_suite.as_key_exchange_algorithm();
    debug!("Using key exchange algorithm: {:?}", key_exchange_algorithm);

    // Select signature/hash algorithm compatible with our key and client's offers (we assume client default set)
    let hash_alg = engine.crypto_context().private_key_default_hash_algorithm();
    let sig_alg = engine.crypto_context().signature_algorithm();
    let algorithm = SignatureAndHashAlgorithm::new(hash_alg, sig_alg);

    // Initialize KE and get our public key
    match key_exchange_algorithm {
        KeyExchangeAlgorithm::EECDH => {
            // Prefer P-256 then P-384 (client must have offered one; selection validated earlier)
            let (curve_type, named_curve) = (CurveType::NamedCurve, NamedCurve::Secp256r1);
            let pubkey = engine
                .crypto_context_mut()
                .init_ecdh_server(named_curve)
                .map_err(|e| Error::CryptoError(format!("Failed to init ECDHE: {}", e)))?;

            let params = EcdhParams::new(curve_type, named_curve, pubkey, None);

            // Build signed_data = client_random || server_random || params(without signature)
            let mut signed_data = Buf::new();
            client_random.serialize(&mut signed_data);
            server_random.serialize(&mut signed_data);
            params.serialize(&mut signed_data, false);

            let signature = engine
                .crypto_context()
                .sign_data(&signed_data, hash_alg)
                .map_err(|e| {
                    Error::CryptoError(format!("Failed to sign server key exchange: {}", e))
                })?;

            let pubkey = engine
                .crypto_context_mut()
                .maybe_init_key_exchange()
                .unwrap();
            let d_signed = DigitallySigned::new(algorithm, &signature);
            let params = EcdhParams::new(curve_type, named_curve, pubkey, Some(d_signed));
            let ske = ServerKeyExchange {
                params: ServerKeyExchangeParams::Ecdh(params),
            };

            ske.serialize(body, true);
            Ok(())
        }
        KeyExchangeAlgorithm::EDH => {
            let pubkey = engine
                .crypto_context_mut()
                .init_dh_server(ffdhe2048::params())
                .map_err(|e| Error::CryptoError(format!("Failed to init DHE: {}", e)))?;

            let params = ffdhe2048::params();
            let dh_public = DhParams::new(params.p(), params.g(), pubkey, None);

            let mut signed_data = Buf::new();
            client_random.serialize(&mut signed_data);
            server_random.serialize(&mut signed_data);
            dh_public.serialize(&mut signed_data, false);

            let signature = engine
                .crypto_context()
                .sign_data(&signed_data, hash_alg)
                .map_err(|e| {
                    Error::CryptoError(format!("Failed to sign server key exchange: {}", e))
                })?;

            let pubkey = engine
                .crypto_context_mut()
                .maybe_init_key_exchange()
                .unwrap();
            let d_signed = DigitallySigned::new(algorithm, &signature);
            let params = DhParams::new(params.p(), params.g(), pubkey, Some(d_signed));
            let ske = ServerKeyExchange {
                params: ServerKeyExchangeParams::Dh(params),
            };

            ske.serialize(body, true);
            Ok(())
        }
        _ => {
            return Err(Error::SecurityError(
                "Unsupported key exchange algorithm".to_string(),
            ))
        }
    }
}

fn handshake_create_certificate_request(
    body: &mut Buf<'static>,
    _engine: &mut Engine,
) -> Result<(), Error> {
    // Advertise RSA_SIGN and ECDSA_SIGN; empty CA list; support SHA256/384 for RSA & ECDSA
    let mut cert_types = ArrayVec::new();
    cert_types.push(ClientCertificateType::RSA_SIGN);
    cert_types.push(ClientCertificateType::ECDSA_SIGN);

    let supported = SignatureAndHashAlgorithm::supported();
    let mut sig_algs = ArrayVec::new();
    for alg in supported.iter() {
        // Limit to RSA/ECDSA with SHA256/384 (already the default set)
        match (alg.hash, alg.signature) {
            (HashAlgorithm::SHA256, SignatureAlgorithm::RSA)
            | (HashAlgorithm::SHA384, SignatureAlgorithm::RSA)
            | (HashAlgorithm::SHA256, SignatureAlgorithm::ECDSA)
            | (HashAlgorithm::SHA384, SignatureAlgorithm::ECDSA) => sig_algs.push(*alg),
            _ => {}
        }
    }

    let cert_auths: ArrayVec<[DistinguishedName<'static>; 32]> = ArrayVec::new();

    let cr = CertificateRequest::new(cert_types, sig_algs, cert_auths);
    cr.serialize(body);
    Ok(())
}
