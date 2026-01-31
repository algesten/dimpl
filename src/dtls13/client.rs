// DTLS 1.3 Client Handshake Flow (RFC 9147):
//
// 1. Client sends ClientHello (plaintext, epoch 0)
// 2. Server may respond with HelloRetryRequest (special ServerHello with magic random)
//    - If so, Client replaces transcript with message_hash and sends new ClientHello
// 3. Server sends ServerHello (plaintext, epoch 0)
//    - Client derives handshake secrets, installs recv handshake keys, enables peer encryption
// 4. Server sends EncryptedExtensions (encrypted, epoch 2)
// 5. Server sends CertificateRequest (optional, encrypted, epoch 2)
// 6. Server sends Certificate (encrypted, epoch 2)
// 7. Server sends CertificateVerify (encrypted, epoch 2)
// 8. Server sends Finished (encrypted, epoch 2)
//    - Client derives application secrets, installs application keys
//    - Client installs send handshake keys for its own flight
// 9. Client sends Certificate (if requested, encrypted, epoch 2)
// 10. Client sends CertificateVerify (if cert present, encrypted, epoch 2)
// 11. Client sends Finished (encrypted, epoch 2)
// 12. Handshake complete, application data flows on epoch 3
//
// This implementation is a Sans-IO DTLS 1.3 client.

use std::collections::VecDeque;
use std::time::Instant;

use arrayvec::ArrayVec;
use subtle::ConstantTimeEq;

use crate::buffer::Buf;
use crate::buffer::ToBuf;
use crate::crypto::{ActiveKeyExchange, SrtpProfile};
use crate::dtls13::engine::Engine;
use crate::dtls13::message::{
    Body, ClientHello, CompressionMethod, ContentType, Cookie, Dtls13CipherSuite, Extension,
    ExtensionType, KeyShareHelloRetryRequest, KeyShareServerHello, MessageType, NamedGroup,
    ProtocolVersion, Random, SessionId, SignatureAlgorithmsExtension, SignatureScheme,
    SupportedGroupsExtension, SupportedVersionsClientHello, SupportedVersionsServerHello,
    UseSrtpExtension,
};
use crate::{Error, KeyingMaterial, Output};

/// DTLS 1.3 client
pub struct Client {
    /// Current client state.
    state: State,

    /// Engine in common between server and client.
    engine: Engine,

    /// Random unique data. Used for ClientHello.
    random: Option<Random>,

    /// Legacy session ID echoed from ServerHello.
    session_id: Option<SessionId>,

    /// Storage for extension data
    extension_data: Buf,

    /// The negotiated SRTP profile (if any)
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Server certificates
    server_certificates: Vec<Buf>,

    /// Buffer for defragmenting handshakes
    defragment_buffer: Buf,

    /// Whether the server requested client authentication
    client_auth_requested: bool,

    /// The last now we seen
    last_now: Option<Instant>,

    /// Local events
    local_events: VecDeque<LocalEvent>,

    /// Data that is sent before we are connected.
    queued_data: Vec<Buf>,

    /// Active key exchange state (ECDHE)
    active_key_exchange: Option<Box<dyn ActiveKeyExchange>>,

    /// Whether we received a HelloRetryRequest
    hello_retry: bool,

    /// Group selected by HRR for retry
    hrr_selected_group: Option<NamedGroup>,

    /// Saved shared secret for deriving application secrets later
    shared_secret: Option<Buf>,

    /// Saved handshake secret for deriving application secrets
    handshake_secret: Option<Buf>,

    /// Client handshake traffic secret (for client Finished)
    client_hs_traffic_secret: Option<Buf>,

    /// Server handshake traffic secret (for server Finished verification)
    server_hs_traffic_secret: Option<Buf>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LocalEvent {
    PeerCert,
    Connected,
    KeyingMaterial(ArrayVec<u8, 88>, SrtpProfile),
}

impl Client {
    pub(crate) fn new_with_engine(mut engine: Engine) -> Client {
        engine.set_client(true);

        Client {
            state: State::SendClientHello,
            engine,
            random: None,
            session_id: None,
            extension_data: Buf::new(),
            negotiated_srtp_profile: None,
            server_certificates: Vec::with_capacity(3),
            defragment_buffer: Buf::new(),
            client_auth_requested: false,
            last_now: None,
            local_events: VecDeque::new(),
            queued_data: Vec::new(),
            active_key_exchange: None,
            hello_retry: false,
            hrr_selected_group: None,
            shared_secret: None,
            handshake_secret: None,
            client_hs_traffic_secret: None,
            server_hs_traffic_secret: None,
        }
    }

    pub(crate) fn state_name(&self) -> &'static str {
        self.state.name()
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
            self.random = Some(Random::new(&mut self.engine.rng));
        }
        self.engine.handle_timeout(now)?;
        self.make_progress()?;
        Ok(())
    }

    /// Send application data when the client is connected.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::AwaitApplicationData {
            self.queued_data.push(data.to_buf());
            return Ok(());
        }

        self.engine
            .create_ciphertext_record(ContentType::ApplicationData, 3, false, |body| {
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
    AwaitServerHello,
    AwaitEncryptedExtensions,
    AwaitCertificateRequest,
    AwaitCertificate,
    AwaitCertificateVerify,
    AwaitFinished,
    SendCertificate,
    SendCertificateVerify,
    SendFinished,
    AwaitApplicationData,
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::SendClientHello => "SendClientHello",
            State::AwaitServerHello => "AwaitServerHello",
            State::AwaitEncryptedExtensions => "AwaitEncryptedExtensions",
            State::AwaitCertificateRequest => "AwaitCertificateRequest",
            State::AwaitCertificate => "AwaitCertificate",
            State::AwaitCertificateVerify => "AwaitCertificateVerify",
            State::AwaitFinished => "AwaitFinished",
            State::SendCertificate => "SendCertificate",
            State::SendCertificateVerify => "SendCertificateVerify",
            State::SendFinished => "SendFinished",
            State::AwaitApplicationData => "AwaitApplicationData",
        }
    }

    fn make_progress(self, client: &mut Client) -> Result<Self, Error> {
        match self {
            State::SendClientHello => self.send_client_hello(client),
            State::AwaitServerHello => self.await_server_hello(client),
            State::AwaitEncryptedExtensions => self.await_encrypted_extensions(client),
            State::AwaitCertificateRequest => self.await_certificate_request(client),
            State::AwaitCertificate => self.await_certificate(client),
            State::AwaitCertificateVerify => self.await_certificate_verify(client),
            State::AwaitFinished => self.await_finished(client),
            State::SendCertificate => self.send_certificate(client),
            State::SendCertificateVerify => self.send_certificate_verify(client),
            State::SendFinished => self.send_finished(client),
            State::AwaitApplicationData => self.await_application_data(client),
        }
    }

    fn send_client_hello(self, client: &mut Client) -> Result<Self, Error> {
        // unwrap: is ok because we set the random in handle_timeout
        let random = client.random.unwrap();

        // Determine flight number: 1 for initial CH, 3 for HRR retry
        let flight_no = if client.hello_retry { 3 } else { 1 };
        client.engine.flight_begin(flight_no);

        // Generate key exchange for the first supported group (or HRR-selected group)
        let group = if let Some(hrr_group) = client.hrr_selected_group {
            hrr_group
        } else {
            // Use the first supported group from the provider
            let provider = client.engine.config().crypto_provider();
            provider
                .kx_groups
                .first()
                .map(|g| g.name())
                .ok_or_else(|| Error::CryptoError("No supported key exchange groups".to_string()))?
        };

        let kx_group = client.engine.find_kx_group(group).ok_or_else(|| {
            Error::CryptoError(format!("Key exchange group not found: {:?}", group))
        })?;

        let kx_buf = client.engine.pop_buffer();
        let key_exchange = kx_group
            .start_exchange(kx_buf)
            .map_err(|e| Error::CryptoError(format!("Failed to start key exchange: {}", e)))?;

        // Build the key_share extension data into extension_data buffer
        client.extension_data.clear();

        // Serialize extensions into extension_data
        let pub_key = key_exchange.pub_key();
        let pub_key_start = client.extension_data.len();
        client.extension_data.extend_from_slice(pub_key);
        let pub_key_end = client.extension_data.len();

        client.active_key_exchange = Some(key_exchange);

        client
            .engine
            .create_handshake(MessageType::ClientHello, |body, engine| {
                handshake_create_client_hello(
                    body,
                    engine,
                    random,
                    group,
                    pub_key_start..pub_key_end,
                    &client.extension_data,
                )
            })?;

        Ok(Self::AwaitServerHello)
    }

    fn await_server_hello(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client
            .engine
            .next_handshake(MessageType::ServerHello, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        let Body::ServerHello(ref server_hello) = handshake.body else {
            unreachable!()
        };

        // Check for HelloRetryRequest (magic random)
        if server_hello.is_hello_retry_request() {
            debug!("Received HelloRetryRequest");

            // Extract selected group from key_share extension
            if let Some(ref extensions) = server_hello.extensions {
                for ext in extensions {
                    if ext.extension_type == ExtensionType::KeyShare {
                        let ext_data = ext.extension_data(&client.defragment_buffer);
                        if let Ok((_, hrr_ks)) = KeyShareHelloRetryRequest::parse(ext_data) {
                            client.hrr_selected_group = Some(hrr_ks.selected_group);
                        }
                    }
                }
            }

            // Replace transcript with message_hash per RFC 8446 Section 4.4.1
            client.engine.replace_transcript_with_message_hash();
            client.hello_retry = true;

            // Drop the old key exchange
            client.active_key_exchange = None;

            return Ok(Self::SendClientHello);
        }

        debug!(
            "Received ServerHello with cipher suite: {:?}",
            server_hello.cipher_suite
        );

        // Validate cipher suite
        let cs = server_hello.cipher_suite;
        if matches!(cs, Dtls13CipherSuite::Unknown(_)) {
            return Err(Error::SecurityError(
                "Server selected unknown cipher suite".to_string(),
            ));
        }

        if !client.engine.is_cipher_suite_allowed(cs) {
            return Err(Error::SecurityError(format!(
                "Server selected disallowed cipher suite: {:?}",
                cs
            )));
        }

        client.engine.set_cipher_suite(cs);
        client.session_id = Some(server_hello.legacy_session_id);

        // Validate supported_versions extension
        let mut supported_version_ok = false;
        let mut server_key_share: Option<(NamedGroup, std::ops::Range<usize>)> = None;

        let Some(ref extensions) = server_hello.extensions else {
            return Err(Error::IncompleteServerHello);
        };

        for ext in extensions {
            match ext.extension_type {
                ExtensionType::SupportedVersions => {
                    let ext_data = ext.extension_data(&client.defragment_buffer);
                    if let Ok((_, sv)) = SupportedVersionsServerHello::parse(ext_data) {
                        if sv.selected_version == ProtocolVersion::DTLS1_3 {
                            supported_version_ok = true;
                        }
                    }
                }
                ExtensionType::KeyShare => {
                    let ext_data = ext.extension_data(&client.defragment_buffer);
                    if let Ok((_, ks)) = KeyShareServerHello::parse(ext_data, 0) {
                        // The key_exchange data is at offset 0 within ext_data, but
                        // we stored it into defragment_buffer. We need the actual bytes.
                        let ke_bytes = ks.entry.key_exchange(ext_data);
                        // Store the group and a copy of the key exchange bytes
                        let ke_start = client.extension_data.len();
                        client.extension_data.extend_from_slice(ke_bytes);
                        let ke_end = client.extension_data.len();
                        server_key_share = Some((ks.entry.group, ke_start..ke_end));
                    }
                }
                _ => {}
            }
        }

        if !supported_version_ok {
            return Err(Error::SecurityError(
                "Server did not negotiate DTLS 1.3 via supported_versions".to_string(),
            ));
        }

        let Some((server_group, ke_range)) = server_key_share else {
            return Err(Error::SecurityError(
                "Server did not provide key_share extension".to_string(),
            ));
        };

        // Complete ECDHE key exchange
        let key_exchange = client
            .active_key_exchange
            .take()
            .ok_or_else(|| Error::CryptoError("No active key exchange".to_string()))?;

        if key_exchange.group() != server_group {
            return Err(Error::SecurityError(format!(
                "Server key share group mismatch: {:?} != {:?}",
                server_group,
                key_exchange.group()
            )));
        }

        let peer_pub_key = &client.extension_data[ke_range];
        let mut shared_secret = Buf::new();
        key_exchange
            .complete(peer_pub_key, &mut shared_secret)
            .map_err(|e| Error::CryptoError(format!("ECDHE completion failed: {}", e)))?;

        // Derive handshake secrets
        let (c_hs_traffic, s_hs_traffic) =
            client.engine.derive_handshake_secrets(&shared_secret)?;

        // Save handshake secret for later application key derivation
        let handshake_secret = client.engine.derive_handshake_secret(&shared_secret)?;
        client.handshake_secret = Some(handshake_secret);
        client.shared_secret = Some(shared_secret);

        // Save traffic secrets for Finished verification and client flight
        let mut s_hs_copy = Buf::new();
        s_hs_copy.extend_from_slice(&s_hs_traffic);
        client.server_hs_traffic_secret = Some(s_hs_copy);
        let mut c_hs_copy = Buf::new();
        c_hs_copy.extend_from_slice(&c_hs_traffic);
        client.client_hs_traffic_secret = Some(c_hs_copy);

        // Install handshake keys (recv for server messages, send installed later)
        client
            .engine
            .install_handshake_keys(&c_hs_traffic, &s_hs_traffic)?;

        // Enable peer encryption for server's epoch 2 messages
        client.engine.enable_peer_encryption()?;

        Ok(Self::AwaitEncryptedExtensions)
    }

    fn await_encrypted_extensions(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client.engine.next_handshake(
            MessageType::EncryptedExtensions,
            &mut client.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        let Body::EncryptedExtensions(ref ee) = handshake.body else {
            unreachable!()
        };

        // Process extensions
        for ext in &ee.extensions {
            if ext.extension_type == ExtensionType::UseSrtp {
                let ext_data = ext.extension_data(&client.defragment_buffer);
                if let Ok((_, use_srtp)) = UseSrtpExtension::parse(ext_data) {
                    if !use_srtp.profiles.is_empty() {
                        client.negotiated_srtp_profile = Some(use_srtp.profiles[0].into());
                        trace!(
                            "EncryptedExtensions UseSRTP; selected profile: {:?}",
                            client.negotiated_srtp_profile
                        );
                    }
                }
            }
        }

        Ok(Self::AwaitCertificateRequest)
    }

    fn await_certificate_request(self, client: &mut Client) -> Result<Self, Error> {
        // CertificateRequest is optional. Check if Certificate is available instead.
        let has_cert = client
            .engine
            .has_complete_handshake(MessageType::Certificate);

        if has_cert {
            return Ok(Self::AwaitCertificate);
        }

        let maybe = client.engine.next_handshake(
            MessageType::CertificateRequest,
            &mut client.defragment_buffer,
        )?;

        let Some(_handshake) = maybe else {
            return Ok(self);
        };

        // CertificateRequest received - we'll send client Certificate + CertificateVerify
        debug!("Received CertificateRequest; enabling client authentication path");
        client.client_auth_requested = true;

        Ok(Self::AwaitCertificate)
    }

    fn await_certificate(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client
            .engine
            .next_handshake(MessageType::Certificate, &mut client.defragment_buffer)?;

        let Some(ref handshake) = maybe else {
            return Ok(self);
        };

        let Body::Certificate(ref certificate) = handshake.body else {
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

        // Extract certificate data before dropping handshake
        let cert_ranges: ArrayVec<_, 32> = certificate
            .certificate_list
            .iter()
            .map(|entry| entry.cert.as_slice(&client.defragment_buffer).to_vec())
            .collect();

        drop(maybe);

        for (i, cert_data) in cert_ranges.iter().enumerate() {
            trace!("Certificate #{} size: {} bytes", i + 1, cert_data.len());
            let mut buf = Buf::new();
            buf.extend_from_slice(cert_data);
            client.server_certificates.push(buf);
        }

        // Emit PeerCert event
        if !client.server_certificates.is_empty() {
            client.local_events.push_back(LocalEvent::PeerCert);
        }

        Ok(Self::AwaitCertificateVerify)
    }

    fn await_certificate_verify(self, client: &mut Client) -> Result<Self, Error> {
        let maybe = client.engine.next_handshake(
            MessageType::CertificateVerify,
            &mut client.defragment_buffer,
        )?;

        let Some(ref handshake) = maybe else {
            return Ok(self);
        };

        let Body::CertificateVerify(ref cv) = handshake.body else {
            unreachable!()
        };

        let scheme = cv.signed.scheme;
        let signature = cv.signed.signature(&client.defragment_buffer);

        // Build the signed content per RFC 8446 Section 4.4.3:
        // 0x20 * 64 || "TLS 1.3, server CertificateVerify\0" || transcript_hash
        let mut signed_content = Buf::new();
        signed_content.extend_from_slice(&[0x20u8; 64]);
        signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");

        // Transcript hash up to (but not including) CertificateVerify is already in
        // the transcript at this point because next_handshake added the Certificate.
        // But CertificateVerify was also added. We need the hash BEFORE CertificateVerify.
        // Actually, next_handshake already added CertificateVerify to transcript.
        // We need to compute the hash of the transcript excluding CertificateVerify.
        //
        // However, the way defragment works, the transcript is updated during
        // next_handshake. So at this point the transcript INCLUDES CertificateVerify.
        // We need to back out the CertificateVerify from the transcript.
        //
        // The correct approach: compute transcript hash BEFORE consuming CertificateVerify.
        // But our architecture consumes it then verifies. We need to compute hash beforehand.
        //
        // Actually, per RFC 8446 4.4.3, the hash used for CertificateVerify is the
        // transcript hash of all messages up to but NOT including CertificateVerify.
        // Since next_handshake adds the message to the transcript, we've already
        // committed it. We need to save the transcript hash before consuming CV.
        //
        // Let's fix this: we need to capture transcript hash before processing CV.
        // This means we need to compute it before calling next_handshake for CV.

        // WORKAROUND: The transcript currently includes CertificateVerify.
        // We need the hash *before* CertificateVerify was added.
        // We can reconstruct by removing the CertificateVerify bytes from transcript.
        // CertificateVerify transcript entry: msg_type(1) + length(3) + body
        let cv_transcript_len = 1 + 3 + (2 + 2 + signature.len()); // scheme(2) + sig_len(2) + sig
        let transcript_before_cv_len = client.engine.transcript.len() - cv_transcript_len;
        let transcript_before_cv = &client.engine.transcript[..transcript_before_cv_len];

        // Hash the transcript before CertificateVerify
        let hash = client
            .engine
            .cipher_suite()
            // unwrap: cipher_suite is set by AwaitServerHello
            .unwrap()
            .hash_algorithm();
        let mut hash_ctx = client
            .engine
            .config()
            .crypto_provider()
            .hash_provider
            .create_hash(hash);
        hash_ctx.update(transcript_before_cv);
        let mut transcript_hash = Buf::new();
        hash_ctx.clone_and_finalize(&mut transcript_hash);

        signed_content.extend_from_slice(&transcript_hash);

        // Copy signature data since we need to drop handshake reference
        let signature_copy = signature.to_vec();

        drop(maybe);

        // Verify the signature
        let cert_der = client.server_certificates.first().ok_or_else(|| {
            Error::CertificateError("No server certificate for verification".to_string())
        })?;

        let (hash_alg, sig_alg) = signature_scheme_to_components(scheme);

        client.engine.verify_signature(
            cert_der,
            &signed_content,
            &signature_copy,
            hash_alg,
            sig_alg,
        )?;

        trace!("Server CertificateVerify verified: {:?}", scheme);

        Ok(Self::AwaitFinished)
    }

    fn await_finished(self, client: &mut Client) -> Result<Self, Error> {
        // Compute expected verify_data BEFORE consuming Finished
        // (verify_data uses transcript hash up to but not including Finished)
        let server_hs_secret = client
            .server_hs_traffic_secret
            .as_ref()
            .ok_or_else(|| Error::CryptoError("No server handshake traffic secret".to_string()))?;
        let expected_verify_data = client.engine.compute_verify_data(server_hs_secret)?;

        let maybe = client
            .engine
            .next_handshake(MessageType::Finished, &mut client.defragment_buffer)?;

        let Some(ref handshake) = maybe else {
            return Ok(self);
        };

        let Body::Finished(ref finished) = handshake.body else {
            unreachable!()
        };

        let verify_data = finished.verify_data(&client.defragment_buffer);

        trace!(
            "Finished.verify_data received len={}, expected len={}",
            verify_data.len(),
            expected_verify_data.len()
        );

        // Constant-time comparison
        let is_eq: bool = verify_data.ct_eq(&*expected_verify_data).into();
        if !is_eq {
            return Err(Error::SecurityError(
                "Server Finished verification failed".to_string(),
            ));
        }

        trace!("Server Finished verified successfully");

        drop(maybe);

        // Derive application secrets from handshake secret + transcript through server Finished
        let handshake_secret = client.handshake_secret.as_ref().ok_or_else(|| {
            Error::CryptoError("No handshake secret for application key derivation".to_string())
        })?;

        let (c_ap_traffic, s_ap_traffic) =
            client.engine.derive_application_secrets(handshake_secret)?;

        // Install application keys
        client
            .engine
            .install_application_keys(&c_ap_traffic, &s_ap_traffic)?;

        // Install send handshake keys for client's epoch 2 flight
        let client_hs_secret = client
            .client_hs_traffic_secret
            .as_ref()
            .ok_or_else(|| Error::CryptoError("No client handshake traffic secret".to_string()))?;
        client
            .engine
            .install_send_handshake_keys(client_hs_secret)?;

        if client.client_auth_requested {
            Ok(Self::SendCertificate)
        } else {
            Ok(Self::SendFinished)
        }
    }

    fn send_certificate(self, client: &mut Client) -> Result<Self, Error> {
        debug!("Sending Certificate");

        client
            .engine
            .create_handshake(MessageType::Certificate, |body, engine| {
                handshake_create_certificate(body, engine)
            })?;

        Ok(Self::SendCertificateVerify)
    }

    fn send_certificate_verify(self, client: &mut Client) -> Result<Self, Error> {
        debug!("Sending CertificateVerify");

        client
            .engine
            .create_handshake(MessageType::CertificateVerify, |body, engine| {
                handshake_create_certificate_verify(body, engine)
            })?;

        Ok(Self::SendFinished)
    }

    fn send_finished(self, client: &mut Client) -> Result<Self, Error> {
        trace!("Sending Finished message to complete handshake");

        let client_hs_secret = client.client_hs_traffic_secret.as_ref().ok_or_else(|| {
            Error::CryptoError("No client handshake traffic secret for Finished".to_string())
        })?;
        let mut client_hs_secret_copy = Buf::new();
        client_hs_secret_copy.extend_from_slice(client_hs_secret);
        let client_hs_secret = client_hs_secret_copy;

        client
            .engine
            .create_handshake(MessageType::Finished, |body, engine| {
                let verify_data = engine.compute_verify_data(&client_hs_secret)?;
                body.extend_from_slice(&verify_data);
                Ok(())
            })?;

        // Stop flight timers - handshake complete
        client.engine.flight_stop_resend_timers();

        // Emit Connected event
        client.local_events.push_back(LocalEvent::Connected);

        // Extract and emit SRTP keying material if negotiated
        if let Some(profile) = client.negotiated_srtp_profile {
            if let Ok((keying_material, profile)) =
                client.engine.extract_srtp_keying_material(profile)
            {
                debug!(
                    "SRTP keying material extracted ({} bytes) for profile: {:?}",
                    keying_material.len(),
                    profile
                );
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
                client.engine.create_ciphertext_record(
                    ContentType::ApplicationData,
                    3,
                    false,
                    |body| {
                        body.extend_from_slice(&data);
                    },
                )?;
            }
        }

        Ok(self)
    }
}

// =========================================================================
// Helper Functions
// =========================================================================

fn handshake_create_client_hello(
    body: &mut Buf,
    engine: &mut Engine,
    random: Random,
    kx_group: NamedGroup,
    pub_key_range: std::ops::Range<usize>,
    extension_data: &Buf,
) -> Result<(), Error> {
    let legacy_version = ProtocolVersion::DTLS1_2;
    let legacy_session_id = SessionId::empty();
    // DTLS 1.3: legacy_cookie MUST be zero length
    let legacy_cookie = Cookie::empty();

    // Cipher suites from provider
    let provider = engine.config().crypto_provider();
    let cipher_suites: ArrayVec<Dtls13CipherSuite, 3> = provider
        .dtls13_cipher_suites
        .iter()
        .map(|cs| cs.suite())
        .take(3)
        .collect();

    debug!(
        "Sending ClientHello: offering {} cipher suites",
        cipher_suites.len()
    );

    let mut compression_methods = ArrayVec::new();
    compression_methods.push(CompressionMethod::Null);

    // Build extensions
    let mut extensions: ArrayVec<Extension, 5> = ArrayVec::new();
    let mut ext_buf = Buf::new();

    // 1. supported_versions extension (DTLS 1.3)
    let sv_start = ext_buf.len();
    let mut versions = ArrayVec::new();
    versions.push(ProtocolVersion::DTLS1_3);
    let sv = SupportedVersionsClientHello { versions };
    sv.serialize(&mut ext_buf);
    let sv_end = ext_buf.len();
    extensions.push(Extension {
        extension_type: ExtensionType::SupportedVersions,
        extension_data_range: sv_start..sv_end,
    });

    // 2. supported_groups extension
    let sg_start = ext_buf.len();
    let groups: ArrayVec<NamedGroup, 4> = provider.kx_groups.iter().map(|g| g.name()).collect();
    let sg = SupportedGroupsExtension { groups };
    sg.serialize(&mut ext_buf);
    let sg_end = ext_buf.len();
    extensions.push(Extension {
        extension_type: ExtensionType::SupportedGroups,
        extension_data_range: sg_start..sg_end,
    });

    // 3. key_share extension
    let ks_start = ext_buf.len();
    let pub_key_bytes = &extension_data[pub_key_range];
    // Write key_share_client_hello inline
    let entry_len = 2 + 2 + pub_key_bytes.len(); // group(2) + ke_len(2) + ke_data
    ext_buf.extend_from_slice(&(entry_len as u16).to_be_bytes()); // client_shares length
    ext_buf.extend_from_slice(&kx_group.as_u16().to_be_bytes());
    ext_buf.extend_from_slice(&(pub_key_bytes.len() as u16).to_be_bytes());
    ext_buf.extend_from_slice(pub_key_bytes);
    let ks_end = ext_buf.len();
    extensions.push(Extension {
        extension_type: ExtensionType::KeyShare,
        extension_data_range: ks_start..ks_end,
    });

    // 4. signature_algorithms extension
    let sa_start = ext_buf.len();
    let sa = SignatureAlgorithmsExtension::default();
    sa.serialize(&mut ext_buf);
    let sa_end = ext_buf.len();
    extensions.push(Extension {
        extension_type: ExtensionType::SignatureAlgorithms,
        extension_data_range: sa_start..sa_end,
    });

    // 5. use_srtp extension
    let srtp_start = ext_buf.len();
    let use_srtp = UseSrtpExtension::default();
    use_srtp.serialize(&mut ext_buf);
    let srtp_end = ext_buf.len();
    extensions.push(Extension {
        extension_type: ExtensionType::UseSrtp,
        extension_data_range: srtp_start..srtp_end,
    });

    let client_hello = ClientHello {
        legacy_version,
        random,
        legacy_session_id,
        legacy_cookie,
        cipher_suites,
        legacy_compression_methods: compression_methods,
        extensions,
    };

    client_hello.serialize(&ext_buf, body);
    Ok(())
}

fn handshake_create_certificate(body: &mut Buf, engine: &mut Engine) -> Result<(), Error> {
    // TLS 1.3 Certificate message format:
    // certificate_request_context<0..255>
    body.push(0); // empty context

    let cert_der = engine.certificate_der();
    let cert_len = cert_der.len();

    // certificate_list<0..2^24-1>
    // Each entry: cert_data<1..2^24-1> + extensions<0..2^16-1>
    let entry_len = 3 + cert_len + 2; // cert_len_field(3) + cert + ext_len(2)
    let total_len = entry_len;
    body.extend_from_slice(&(total_len as u32).to_be_bytes()[1..]); // 3-byte length

    // cert_data
    body.extend_from_slice(&(cert_len as u32).to_be_bytes()[1..]); // 3-byte length
    body.extend_from_slice(cert_der);

    // extensions (empty)
    body.extend_from_slice(&0u16.to_be_bytes());

    Ok(())
}

fn handshake_create_certificate_verify(body: &mut Buf, engine: &mut Engine) -> Result<(), Error> {
    // Build signed content: 0x20*64 || "TLS 1.3, client CertificateVerify\0" || transcript_hash
    let mut signed_content = Buf::new();
    signed_content.extend_from_slice(&[0x20u8; 64]);
    signed_content.extend_from_slice(b"TLS 1.3, client CertificateVerify\0");

    let mut transcript_hash = Buf::new();
    engine.transcript_hash(&mut transcript_hash);
    signed_content.extend_from_slice(&transcript_hash);

    // Sign with our private key
    let hash_alg = engine.signing_key().hash_algorithm();
    let sig_alg = engine.signing_key().algorithm();

    let mut signature = Buf::new();
    engine
        .signing_key()
        .sign(&signed_content, &mut signature)
        .map_err(|e| Error::CryptoError(format!("Failed to sign CertificateVerify: {}", e)))?;

    // Determine the SignatureScheme from hash_alg + sig_alg
    let scheme = match (sig_alg, hash_alg) {
        (crate::types::SignatureAlgorithm::ECDSA, crate::types::HashAlgorithm::SHA256) => {
            SignatureScheme::ECDSA_SECP256R1_SHA256
        }
        (crate::types::SignatureAlgorithm::ECDSA, crate::types::HashAlgorithm::SHA384) => {
            SignatureScheme::ECDSA_SECP384R1_SHA384
        }
        (crate::types::SignatureAlgorithm::RSA, crate::types::HashAlgorithm::SHA256) => {
            SignatureScheme::RSA_PSS_RSAE_SHA256
        }
        _ => {
            return Err(Error::CryptoError(format!(
                "Unsupported signature algorithm: {:?}/{:?}",
                sig_alg, hash_alg
            )))
        }
    };

    // Write CertificateVerify: scheme(2) + signature_len(2) + signature
    body.extend_from_slice(&scheme.as_u16().to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(&signature);

    Ok(())
}

/// Map a TLS 1.3 SignatureScheme to the (HashAlgorithm, SignatureAlgorithm) pair
/// needed by the SignatureVerifier trait.
fn signature_scheme_to_components(
    scheme: SignatureScheme,
) -> (
    crate::types::HashAlgorithm,
    crate::types::SignatureAlgorithm,
) {
    use crate::types::{HashAlgorithm, SignatureAlgorithm};
    match scheme {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            (HashAlgorithm::SHA256, SignatureAlgorithm::ECDSA)
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            (HashAlgorithm::SHA384, SignatureAlgorithm::ECDSA)
        }
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            (HashAlgorithm::SHA512, SignatureAlgorithm::ECDSA)
        }
        SignatureScheme::ED25519 => (HashAlgorithm::SHA512, SignatureAlgorithm::ECDSA),
        SignatureScheme::RSA_PSS_RSAE_SHA256 => (HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PSS_RSAE_SHA384 => (HashAlgorithm::SHA384, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PSS_RSAE_SHA512 => (HashAlgorithm::SHA512, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PSS_PSS_SHA256 => (HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PSS_PSS_SHA384 => (HashAlgorithm::SHA384, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PSS_PSS_SHA512 => (HashAlgorithm::SHA512, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PKCS1_SHA256 => (HashAlgorithm::SHA256, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PKCS1_SHA384 => (HashAlgorithm::SHA384, SignatureAlgorithm::RSA),
        SignatureScheme::RSA_PKCS1_SHA512 => (HashAlgorithm::SHA512, SignatureAlgorithm::RSA),
        _ => (HashAlgorithm::SHA256, SignatureAlgorithm::ECDSA),
    }
}

// =========================================================================
// Standard Trait Impls
// =========================================================================

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
                Output::KeyingMaterial(KeyingMaterial::new(&m), profile)
            }
        }
    }
}
