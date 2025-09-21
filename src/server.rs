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
    HelloVerifyRequest, KeyExchangeAlgorithm, MessageType, NamedCurve, NamedGroup, ProtocolVersion,
    Random, ServerHello, ServerKeyExchange, ServerKeyExchangeParams, SessionId, SignatureAlgorithm,
    SignatureAlgorithmsExtension, SignatureAndHashAlgorithm, SrtpProfileId,
    SupportedGroupsExtension, UseSrtpExtension,
};
use crate::{Client, Config, Error, Output};

type HmacSha256 = Hmac<Sha256>;

/// DTLS server
pub struct Server {
    /// Current server state.
    state: State,

    /// Engine in common between server and client.
    engine: Engine,

    /// Start time of the server
    start: Instant,

    /// Random unique data (with gmt timestamp). Used for signature checks.
    random: Random,

    /// SessionId we provide to the client (unused/resumption not implemented).
    session_id: Option<SessionId>,

    /// Cookie secret for HMAC, generated per-server instance
    cookie_secret: [u8; 32],

    /// Storage for extension data
    extension_data: Buf<'static>,

    /// The negotiated SRTP profile (if any)
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Client's offered supported_groups (if any)
    client_supported_groups: Option<ArrayVec<[NamedGroup; 16]>>,

    /// Client's offered signature_algorithms (if any)
    client_signature_algorithms: Option<ArrayVec<[SignatureAndHashAlgorithm; 32]>>,

    /// Client random. Set by ClientHello.
    client_random: Option<Random>,

    /// Client certificates
    client_certificates: Vec<Buf<'static>>,

    /// Buffer for defragmenting handshakes
    defragment_buffer: Buf<'static>,

    /// Captured session hash for Extended Master Secret (RFC 7627)
    captured_session_hash: Option<Vec<u8>>,
}

/// Current state of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitClientHello,
    SendServerHello,
    SendCertificate,
    SendServerKeyExchange,
    SendCertificateRequest,
    SendServerHelloDone,
    AwaitCertificate,
    AwaitClientKeyExchange,
    AwaitCertificateVerify,
    AwaitChangeCipherSpec,
    AwaitFinished,
    SendChangeCipherSpec,
    SendFinished,
    AwaitApplicationData,
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
        let engine = Engine::new(config, certificate, private_key, cert_verifier);
        Self::new_with_engine(now, engine)
    }

    pub(crate) fn new_with_engine(now: Instant, mut engine: Engine) -> Server {
        engine.set_client(false);

        let mut cookie_secret = [0u8; 32];
        OsRng.fill_bytes(&mut cookie_secret);

        Server {
            state: State::AwaitClientHello,
            engine,
            start: now,
            random: Random::new(now),
            session_id: None,
            cookie_secret,
            extension_data: Buf::new(),
            negotiated_srtp_profile: None,
            client_supported_groups: None,
            client_signature_algorithms: None,
            client_random: None,
            client_certificates: Vec::with_capacity(3),
            defragment_buffer: Buf::new(),
            captured_session_hash: None,
        }
    }

    pub fn into_client(self) -> Client {
        Client::new_with_engine(self.start, self.engine)
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.engine.parse_packet(packet)?;
        self.make_progress()?;
        Ok(())
    }

    pub fn poll_output(&mut self) -> Output {
        self.engine.poll_output()
    }

    pub fn handle_timeout(&mut self, _now: Instant) -> Result<(), Error> {
        self.make_progress()?;
        Ok(())
    }

    /// Send application data when the server is in the Running state
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::AwaitApplicationData {
            return Err(Error::UnexpectedMessage("Server not connected".to_string()));
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

impl State {
    fn make_progress(self, server: &mut Server) -> Result<Self, Error> {
        match self {
            State::AwaitClientHello => self.await_client_hello(server),
            State::SendServerHello => self.send_server_hello(server),
            State::SendCertificate => self.send_certificate(server),
            State::SendServerKeyExchange => self.send_server_key_exchange(server),
            State::SendCertificateRequest => self.send_certificate_request(server),
            State::SendServerHelloDone => self.send_server_hello_done(server),
            State::AwaitCertificate => self.await_certificate(server),
            State::AwaitClientKeyExchange => self.await_client_key_exchange(server),
            State::AwaitCertificateVerify => self.await_certificate_verify(server),
            State::AwaitChangeCipherSpec => self.await_change_cipher_spec(server),
            State::AwaitFinished => self.await_finished(server),
            State::SendChangeCipherSpec => self.send_change_cipher_spec(server),
            State::SendFinished => self.send_finished(server),
            State::AwaitApplicationData => self.await_application_data(server),
        }
    }

    fn await_client_hello(self, server: &mut Server) -> Result<Self, Error> {
        let maybe = server
            .engine
            .next_handshake(MessageType::ClientHello, &mut server.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::ClientHello(ch) = handshake.body else {
            unreachable!()
        };

        // Enforce DTLS1.2
        if ch.client_version != ProtocolVersion::DTLS1_2 {
            return Err(Error::SecurityError(format!(
                "Unsupported DTLS version from client: {:?}",
                ch.client_version
            )));
        }

        // Enforce Null compression only (client must offer it)
        let has_null = ch
            .compression_methods.contains(&CompressionMethod::Null);
        if !has_null {
            return Err(Error::SecurityError(
                "Client did not offer Null compression".to_string(),
            ));
        }

        // Stateless cookie: require 32-byte cookie matching HMAC(secret, client_random)
        let client_random = ch.random;
        if !verify_cookie(&server.cookie_secret, client_random, ch.cookie) {
            debug!("Invalid/missing cookie; sending HelloVerifyRequest");

            let cookie = compute_cookie(&server.cookie_secret, client_random)?;
            server
                .engine
                .create_handshake(MessageType::HelloVerifyRequest, |body, _engine| {
                    let hvr = HelloVerifyRequest::new(ProtocolVersion::DTLS1_2, cookie);
                    hvr.serialize(body);
                    Ok(())
                })?;

            // The HelloVerifyRequest exchange is not part of the main handshake transcript.
            // Clear transcript so subsequent CertificateVerify/Finished cover only the real handshake.
            server.engine.reset_handshake_transcript();

            // After HelloVerifyRequest, await a new ClientHello
            return Ok(self);
        }

        // Client offered suites; we pick per client order intersecting allowed and server key compatibility
        let mut selected: Option<CipherSuite> = None;
        for s in ch.cipher_suites.iter() {
            let is_allowed = server.engine.is_cipher_suite_allowed(*s);
            let is_compatible = server
                .engine
                .crypto_context()
                .is_cipher_suite_compatible(*s);
            if is_allowed && is_compatible {
                selected = Some(*s);
                break;
            }
        }

        let Some(cs) = selected else {
            return Err(Error::SecurityError(
                "No mutually acceptable cipher suite".to_string(),
            ));
        };

        server.engine.set_cipher_suite(cs);
        server.client_random = Some(client_random);

        // Process client extensions: SRTP, EMS, SupportedGroups and SignatureAlgorithms
        let mut client_offers_ems = false;
        let mut client_srtp_profiles: Option<ArrayVec<[SrtpProfileId; 32]>> = None;
        let mut client_supported_groups: Option<ArrayVec<[NamedGroup; 16]>> = None;
        let mut client_signature_algorithms: Option<ArrayVec<[SignatureAndHashAlgorithm; 32]>> =
            None;
        for ext in ch.extensions {
            match ext.extension_type {
                ExtensionType::UseSrtp => {
                    if let Ok((_, use_srtp)) = UseSrtpExtension::parse(ext.extension_data) {
                        client_srtp_profiles = Some(use_srtp.profiles);
                    }
                }
                ExtensionType::ExtendedMasterSecret => {
                    client_offers_ems = true;
                }
                ExtensionType::SupportedGroups => {
                    if let Ok((_, groups)) = SupportedGroupsExtension::parse(ext.extension_data) {
                        client_supported_groups = Some(groups.groups);
                    }
                }
                ExtensionType::SignatureAlgorithms => {
                    if let Ok((_, sigs)) = SignatureAlgorithmsExtension::parse(ext.extension_data) {
                        client_signature_algorithms = Some(sigs.supported_signature_algorithms);
                    }
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
            server.negotiated_srtp_profile = selected_profile;
        }

        // Store client's offers for later selection
        server.client_supported_groups = client_supported_groups;
        server.client_signature_algorithms = client_signature_algorithms;

        // Proceed to send the server flight
        Ok(Self::SendServerHello)
    }

    fn send_server_hello(self, server: &mut Server) -> Result<Self, Error> {
        debug!("Sending ServerHello");

        let session_id = server.session_id.unwrap_or_else(SessionId::empty);
        let server_random = server.random;
        let negotiated_srtp_profile = server.negotiated_srtp_profile;
        let extension_data = &mut server.extension_data;

        // Send ServerHello
        server
            .engine
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

        Ok(Self::SendCertificate)
    }

    fn send_certificate(self, server: &mut Server) -> Result<Self, Error> {
        debug!("Sending Certificate");

        server
            .engine
            .create_handshake(MessageType::Certificate, handshake_create_certificate)?;

        Ok(Self::SendServerKeyExchange)
    }

    fn send_server_key_exchange(self, server: &mut Server) -> Result<Self, Error> {
        debug!("Sending ServerKeyExchange");

        let client_random = server
            .client_random
            .ok_or_else(|| Error::UnexpectedMessage("No client random".to_string()))?;
        let server_random = server.random;

        // Select ECDHE curve from client offers (prefer P-256, then P-384). If none present, default to P-256.
        let selected_named_curve = select_named_curve(server.client_supported_groups.as_ref());

        // Select signature/hash for SKE by intersecting client's list with our key type (prefer SHA256, then SHA384)
        let selected_signature = select_ske_signature_algorithm(
            server.client_signature_algorithms.as_ref(),
            server.engine.crypto_context().signature_algorithm(),
        );

        server
            .engine
            .create_handshake(MessageType::ServerKeyExchange, |body, engine| {
                handshake_create_server_key_exchange(
                    body,
                    engine,
                    client_random,
                    server_random,
                    selected_named_curve,
                    selected_signature,
                )
            })?;

        if server.engine.config().require_client_certificate {
            Ok(Self::SendCertificateRequest)
        } else {
            Ok(Self::SendServerHelloDone)
        }
    }

    fn send_certificate_request(self, server: &mut Server) -> Result<Self, Error> {
        debug!("Sending CertificateRequest");
        // Select CertificateRequest.signature_algorithms as intersection of client's list and our supported
        let sig_algs =
            select_certificate_request_sig_algs(server.client_signature_algorithms.as_ref());

        server
            .engine
            .create_handshake(MessageType::CertificateRequest, move |body, _| {
                handshake_serialize_certificate_request(body, &sig_algs)
            })?;

        Ok(Self::SendServerHelloDone)
    }

    fn send_server_hello_done(self, server: &mut Server) -> Result<Self, Error> {
        debug!("Sending ServerHelloDone");

        server
            .engine
            .create_handshake(MessageType::ServerHelloDone, |_, _| {
                Ok(())
            })?;

        if server.engine.config().require_client_certificate {
            Ok(Self::AwaitCertificate)
        } else {
            Ok(Self::AwaitClientKeyExchange)
        }
    }

    fn await_certificate(self, server: &mut Server) -> Result<Self, Error> {
        let maybe = server
            .engine
            .next_handshake(MessageType::Certificate, &mut server.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::Certificate(certificate) = &handshake.body else {
            unreachable!()
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
                server.client_certificates.push(cert_data.to_buf());
            }

            // Verify leaf certificate (client auth policy)
            if let Err(err) = server
                .engine
                .crypto_context()
                .verify_peer_certificate(&server.client_certificates[0])
            {
                return Err(Error::CertificateError(format!(
                    "Certificate verification failed: {}",
                    err
                )));
            }
            server
                .engine
                .push_peer_cert(server.client_certificates[0].to_vec());
        }

        Ok(Self::AwaitClientKeyExchange)
    }

    fn await_client_key_exchange(self, server: &mut Server) -> Result<Self, Error> {
        let maybe = server.engine.next_handshake(
            MessageType::ClientKeyExchange,
            &mut server.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::ClientKeyExchange(ckx) = &handshake.body else {
            unreachable!()
        };

        let suite = server
            .engine
            .cipher_suite()
            .ok_or_else(|| Error::UnexpectedMessage("No cipher suite selected".to_string()))?;

        // Extract client's public key depending on KE
        let client_pub = match &ckx.exchange_keys {
            ExchangeKeys::Ecdh(ClientEcdhKeys { public_key, .. }) => public_key.to_vec(),
            ExchangeKeys::DhAnon(dh) => dh.public_value.to_vec(),
        };

        // Compute shared secret
        server
            .engine
            .crypto_context_mut()
            .compute_shared_secret(&client_pub)
            .map_err(|e| Error::CryptoError(format!("Failed to compute shared secret: {}", e)))?;

        // Capture session hash for EMS now (up to ClientKeyExchange)
        let suite_hash = suite.hash_algorithm();
        server.captured_session_hash = Some(server.engine.handshake_hash(suite_hash));

        // Derive master secret and keys (needed to decrypt client's Finished)
        let suite_hash = suite.hash_algorithm();
        let client_random_buf = {
            let mut b = Buf::new();
            server.client_random.unwrap().serialize(&mut b);
            b.into_vec()
        };
        let server_random_buf = {
            let mut b = Buf::new();
            server.random.serialize(&mut b);
            b.into_vec()
        };

        let session_hash = server.captured_session_hash.as_ref().ok_or_else(|| {
            Error::CryptoError(
                "Extended Master Secret negotiated but session hash not captured".to_string(),
            )
        })?;

        server
            .engine
            .crypto_context_mut()
            .derive_extended_master_secret(session_hash, suite_hash)
            .map_err(|e| {
                Error::CryptoError(format!("Failed to derive extended master secret: {}", e))
            })?;

        server
            .engine
            .crypto_context_mut()
            .derive_keys(suite, &client_random_buf, &server_random_buf)
            .map_err(|e| Error::CryptoError(format!("Failed to derive keys: {}", e)))?;

        if !server.client_certificates.is_empty() {
            Ok(Self::AwaitCertificateVerify)
        } else {
            Ok(Self::AwaitChangeCipherSpec)
        }
    }

    fn await_certificate_verify(self, server: &mut Server) -> Result<Self, Error> {
        // Get handshake data BEFORE processing CertificateVerify message
        // According to TLS spec, signature is over all handshake messages up to but not including CertificateVerify
        let data = server.engine.handshake_data().to_buf();

        let maybe = server.engine.next_handshake(
            MessageType::CertificateVerify,
            &mut server.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        let Body::CertificateVerify(cv) = &handshake.body else {
            unreachable!()
        };

        if server.client_certificates.is_empty() {
            return Err(Error::CertificateError(
                "CertificateVerify received but no client certificate".to_string(),
            ));
        }

        server
            .engine
            .crypto_context()
            .verify_signature(&data, &cv.signed, &server.client_certificates[0])
            .map_err(|e| {
                Error::CryptoError(format!("Failed to verify client CertificateVerify: {}", e))
            })?;

        Ok(Self::AwaitChangeCipherSpec)
    }

    fn await_change_cipher_spec(self, server: &mut Server) -> Result<Self, Error> {
        let maybe = server.engine.next_record(ContentType::ChangeCipherSpec);

        let Some(_) = maybe else {
            // Stay in same state
            return Ok(self);
        };

        // Expect every record to be decrypted from now on.
        server.engine.enable_peer_encryption()?;

        Ok(Self::AwaitFinished)
    }

    fn await_finished(self, server: &mut Server) -> Result<Self, Error> {
        // Generate expected verify data based on current transcript.
        // This must be done before next_handshake() below since
        // it should not include Finished itself.
        let expected = server.engine.generate_verify_data(true /* client */)?;

        let maybe = server
            .engine
            .next_handshake(MessageType::Finished, &mut server.defragment_buffer)?;

        let Some(handshake) = maybe else {
            // stay in same state
            return Ok(self);
        };

        let Body::Finished(finished) = &handshake.body else {
            panic!("Finished message should have been parsed");
        };

        if finished.verify_data != expected {
            return Err(Error::SecurityError(
                "Client Finished verification failed".to_string(),
            ));
        }

        debug!("Client Finished verified successfully");

        Ok(Self::SendChangeCipherSpec)
    }

    fn send_change_cipher_spec(self, server: &mut Server) -> Result<Self, Error> {
        debug!("Sending ChangeCipherSpec");

        // Send ChangeCipherSpec
        server
            .engine
            .create_record(ContentType::ChangeCipherSpec, |body| {
                body.push(1);
                None
            })?;
        server.engine.enable_server_encryption();

        Ok(Self::SendFinished)
    }

    fn send_finished(self, server: &mut Server) -> Result<Self, Error> {
        debug!("Sending Finished message to complete handshake");

        server
            .engine
            .create_handshake(MessageType::Finished, |body, engine| {
                let verify_data = engine.generate_verify_data(false /* server */)?;
                let finished = Finished::new(&verify_data);
                finished.serialize(body);
                Ok(())
            })?;

        // Handshake complete
        server.engine.push_connected();

        // Emit SRTP keying material if negotiated
        if let Some(profile) = server.negotiated_srtp_profile {
            let suite_hash = server.engine.cipher_suite().unwrap().hash_algorithm();
            if let Ok(keying_material) = server
                .engine
                .crypto_context()
                .extract_srtp_keying_material(profile, suite_hash)
            {
                debug!(
                    "SRTP keying material extracted ({} bytes) for profile: {:?}",
                    keying_material.len(),
                    profile
                );
                server.engine.push_keying_material(keying_material, profile);
            }
        }

        Ok(Self::AwaitApplicationData)
    }

    fn await_application_data(self, server: &mut Server) -> Result<Self, Error> {
        // Process incoming application data packets using the engine
        server.engine.process_application_data()?;

        Ok(self)
    }
}

fn compute_cookie(secret: &[u8], client_random: Random) -> Result<Cookie, Error> {
    // cookie = trunc_32(HMAC(secret, client_random))
    let mut mac = HmacSha256::new_from_slice(secret)
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
        Ok(expected) => *expected == *cookie,
        Err(_) => false,
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
    named_curve: NamedCurve,
    algorithm: SignatureAndHashAlgorithm,
) -> Result<(), Error> {
    let Some(cipher_suite) = engine.cipher_suite() else {
        return Err(Error::UnexpectedMessage(
            "No cipher suite selected".to_string(),
        ));
    };

    let key_exchange_algorithm = cipher_suite.as_key_exchange_algorithm();
    debug!("Using key exchange algorithm: {:?}", key_exchange_algorithm);

    // Use hash part from selected algorithm
    let hash_alg = algorithm.hash;

    match key_exchange_algorithm {
        KeyExchangeAlgorithm::EECDH => {
            let (curve_type, named_curve) = (CurveType::NamedCurve, named_curve);
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

            // unwrap: safe because init_ecdh_server() above sets key_exchange = Some(...).
            // If that failed, we returned Err earlier and never reach this point.
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
                .sign_data(&signed_data, algorithm.hash)
                .map_err(|e| {
                    Error::CryptoError(format!("Failed to sign server key exchange: {}", e))
                })?;

            // unwrap: safe because init_dh_server() above sets key_exchange = Some(...).
            // If that failed, we returned Err earlier and never reach this point.
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
            Err(Error::SecurityError(
                "Unsupported key exchange algorithm".to_string(),
            ))
        }
    }
}

fn handshake_serialize_certificate_request(
    body: &mut Buf<'static>,
    sig_algs: &ArrayVec<[SignatureAndHashAlgorithm; 32]>,
) -> Result<(), Error> {
    // Advertise RSA_SIGN and ECDSA_SIGN; empty CA list
    let mut cert_types = ArrayVec::new();
    cert_types.push(ClientCertificateType::RSA_SIGN);
    cert_types.push(ClientCertificateType::ECDSA_SIGN);

    // If intersection is empty (e.g., client didn't advertise), fall back to our supported set
    // Build the selected list with the capacity expected by CertificateRequest
    let mut selected: ArrayVec<[SignatureAndHashAlgorithm; 32]> = ArrayVec::new();
    if sig_algs.is_empty() {
        let fallback = SignatureAndHashAlgorithm::supported();
        for alg in fallback.iter() {
            selected.push(*alg);
        }
    } else {
        for alg in sig_algs.iter() {
            selected.push(*alg);
        }
    }

    let cert_auths: ArrayVec<[DistinguishedName<'static>; 32]> = ArrayVec::new();

    let cr = CertificateRequest::new(cert_types, selected, cert_auths);
    cr.serialize(body);
    Ok(())
}

fn select_named_curve(client_groups: Option<&ArrayVec<[NamedGroup; 16]>>) -> NamedCurve {
    // Server preference order
    let preferred = [NamedGroup::Secp256r1, NamedGroup::Secp384r1];
    if let Some(groups) = client_groups {
        for p in preferred.iter() {
            if groups.iter().any(|g| g == p) {
                if let Some(curve) = map_named_group_to_named_curve(*p) {
                    return curve;
                }
            }
        }
    }
    // Fallback if client did not advertise groups or only unsupported ones
    NamedCurve::Secp256r1
}

fn map_named_group_to_named_curve(group: NamedGroup) -> Option<NamedCurve> {
    match group {
        NamedGroup::Secp256r1 => Some(NamedCurve::Secp256r1),
        NamedGroup::Secp384r1 => Some(NamedCurve::Secp384r1),
        _ => None,
    }
}

fn select_ske_signature_algorithm(
    client_algs: Option<&ArrayVec<[SignatureAndHashAlgorithm; 32]>>,
    our_sig: SignatureAlgorithm,
) -> SignatureAndHashAlgorithm {
    // Our hash preference order
    let hash_pref = [HashAlgorithm::SHA256, HashAlgorithm::SHA384];

    if let Some(list) = client_algs {
        for h in hash_pref.iter() {
            if let Some(chosen) = list
                .iter()
                .find(|alg| alg.signature == our_sig && alg.hash == *h)
            {
                return *chosen;
            }
        }
    }

    // Fallback to our default hash for our key type
    let hash = engine_default_hash_for_sig(our_sig);
    SignatureAndHashAlgorithm::new(hash, our_sig)
}

fn engine_default_hash_for_sig(sig: SignatureAlgorithm) -> HashAlgorithm {
    match sig {
        SignatureAlgorithm::RSA => HashAlgorithm::SHA256,
        SignatureAlgorithm::ECDSA => HashAlgorithm::SHA256,
        _ => HashAlgorithm::SHA256,
    }
}

fn select_certificate_request_sig_algs(
    client_algs: Option<&ArrayVec<[SignatureAndHashAlgorithm; 32]>>,
) -> ArrayVec<[SignatureAndHashAlgorithm; 32]> {
    // Our supported set (RSA/ECDSA with SHA256/384)
    let ours = SignatureAndHashAlgorithm::supported();

    // Build intersection preserving client preference order
    let mut out = ArrayVec::new();
    if let Some(list) = client_algs {
        for alg in list.iter() {
            if ours
                .iter()
                .any(|a| a.hash == alg.hash && a.signature == alg.signature)
            {
                out.push(*alg);
            }
        }
    }
    out
}
