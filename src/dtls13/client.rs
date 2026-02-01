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
use crate::dtls13::message::Asn1Cert;
use crate::dtls13::message::Body;
use crate::dtls13::message::Certificate;
use crate::dtls13::message::CertificateEntry;
use crate::dtls13::message::ClientHello;
use crate::dtls13::message::CompressionMethod;
use crate::dtls13::message::ContentType;
use crate::dtls13::message::Cookie;
use crate::dtls13::message::DistinguishedName;
use crate::dtls13::message::Dtls13CipherSuite;
use crate::dtls13::message::Extension;
use crate::dtls13::message::ExtensionType;
use crate::dtls13::message::KeyShareClientHello;
use crate::dtls13::message::KeyShareEntry;
use crate::dtls13::message::KeyShareHelloRetryRequest;
use crate::dtls13::message::KeyShareServerHello;
use crate::dtls13::message::KeyUpdateRequest;
use crate::dtls13::message::MessageType;
use crate::dtls13::message::NamedGroup;
use crate::dtls13::message::ProtocolVersion;
use crate::dtls13::message::Random;
use crate::dtls13::message::SessionId;
use crate::dtls13::message::SignatureAlgorithmsExtension;
use crate::dtls13::message::SignatureScheme;
use crate::dtls13::message::SupportedGroupsExtension;
use crate::dtls13::message::SupportedVersionsClientHello;
use crate::dtls13::message::SupportedVersionsServerHello;
use crate::dtls13::message::UseSrtpExtension;
use crate::dtls13::Server;
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

    /// Saved certificate_request_context from server's CertificateRequest
    cert_request_context: Option<Buf>,

    /// Cookie received from HRR, to echo in the retry ClientHello
    saved_cookie: Option<Buf>,

    /// The last now we seen
    last_now: Instant,

    /// Local events
    local_events: VecDeque<LocalEvent>,

    /// Data that is sent before we are connected.
    queued_data: Vec<Buf>,

    /// Whether we need to respond with our own KeyUpdate
    pending_key_update_response: bool,

    /// Active key exchange state (ECDHE)
    active_key_exchange: Option<Box<dyn ActiveKeyExchange>>,

    /// Whether we received a HelloRetryRequest
    hello_retry: bool,

    /// Group selected by HRR for retry
    hrr_selected_group: Option<NamedGroup>,

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
    pub(crate) fn new_with_engine(mut engine: Engine, now: Instant) -> Client {
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
            cert_request_context: None,
            saved_cookie: None,
            last_now: now,
            local_events: VecDeque::new(),
            queued_data: Vec::new(),
            pending_key_update_response: false,
            active_key_exchange: None,
            hello_retry: false,
            hrr_selected_group: None,
            handshake_secret: None,
            client_hs_traffic_secret: None,
            server_hs_traffic_secret: None,
        }
    }

    /// Create a client from a hybrid ClientHello probe.
    ///
    /// Injects the hybrid's transcript and ECDHE state into a fresh engine,
    /// then starts in `AwaitServerHello`. The engine's handshake sequence
    /// number is advanced to 1 (one CH has been sent). The hybrid CH was
    /// already sent on the wire by `ClientPending`, so no record is
    /// enqueued for output.
    pub(crate) fn new_from_hybrid(
        hybrid: crate::detect::HybridClientHello,
        config: std::sync::Arc<crate::Config>,
        certificate: crate::DtlsCertificate,
        now: Instant,
    ) -> Client {
        let mut engine = Engine::new(config, certificate);
        engine.set_client(true);

        // Inject transcript + sequence state from the hybrid CH that was
        // already sent on the wire by ClientPending.
        engine.inject_hybrid_client_hello(&hybrid.transcript_bytes);

        Client {
            state: State::AwaitServerHello,
            engine,
            random: Some(hybrid.random),
            session_id: None,
            extension_data: Buf::new(),
            negotiated_srtp_profile: None,
            server_certificates: Vec::with_capacity(3),
            defragment_buffer: Buf::new(),
            client_auth_requested: false,
            cert_request_context: None,
            saved_cookie: None,
            last_now: now,
            local_events: VecDeque::new(),
            queued_data: Vec::new(),
            pending_key_update_response: false,
            active_key_exchange: Some(hybrid.active_key_exchange),
            hello_retry: false,
            hrr_selected_group: None,
            handshake_secret: None,
            client_hs_traffic_secret: None,
            server_hs_traffic_secret: None,
        }
    }

    pub fn into_server(self) -> Server {
        Server::new_with_engine(self.engine, self.last_now)
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
        if let Some(event) = self.local_events.pop_front() {
            return event.into_output(buf, &self.server_certificates);
        }

        self.engine.poll_output(buf, self.last_now)
    }

    /// Explicitly start the handshake process by sending a ClientHello
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.last_now = now;
        if self.random.is_none() {
            self.random = Some(Random::new(&mut self.engine.rng));
        }
        self.engine.handle_timeout(now)?;
        self.make_progress()?;
        Ok(())
    }

    fn initiate_key_update(&mut self) -> Result<(), Error> {
        self.engine
            .create_key_update(KeyUpdateRequest::UpdateRequested)
    }

    /// Send application data when the client is connected.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::AwaitApplicationData {
            self.queued_data.push(data.to_buf());
            return Ok(());
        }

        let epoch = self.engine.app_send_epoch();
        self.engine.create_ciphertext_record(
            ContentType::ApplicationData,
            epoch,
            false,
            |body| {
                body.extend_from_slice(data);
            },
        )?;

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

        // Store cookie data in extension_data if we have one from HRR
        let cookie_range = if let Some(ref cookie) = client.saved_cookie {
            let cookie_start = client.extension_data.len();
            client.extension_data.extend_from_slice(cookie);
            let cookie_end = client.extension_data.len();
            Some(cookie_start..cookie_end)
        } else {
            None
        };

        client
            .engine
            .create_handshake(MessageType::ClientHello, |body, engine| {
                handshake_create_client_hello(
                    body,
                    engine,
                    random,
                    group,
                    pub_key_start..pub_key_end,
                    cookie_range.clone(),
                    &client.extension_data,
                )
            })?;

        Ok(Self::AwaitServerHello)
    }

    fn await_server_hello(self, client: &mut Client) -> Result<Self, Error> {
        // Save transcript length so we can roll back if a stale HRR
        // retransmission arrives after we already processed one.
        let transcript_len_before = client.engine.transcript.len();

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
            if client.hello_retry {
                // Stale retransmission of the HRR we already processed.
                // Roll back the transcript and silently discard. The CH2
                // flight will be retransmitted by the normal flight timeout
                // mechanism if the server hasn't responded.
                debug!("Discarding stale HRR retransmission");
                client.engine.transcript.resize(transcript_len_before, 0);
                return Ok(self);
            }

            debug!("Received HelloRetryRequest");

            // Extract selected group and cookie from HRR extensions
            if let Some(ref extensions) = server_hello.extensions {
                for ext in extensions {
                    match ext.extension_type {
                        ExtensionType::KeyShare => {
                            let ext_data = ext.extension_data(&client.defragment_buffer);
                            if let Ok((_, hrr_ks)) = KeyShareHelloRetryRequest::parse(ext_data) {
                                client.hrr_selected_group = Some(hrr_ks.selected_group);
                            }
                        }
                        ExtensionType::Cookie => {
                            let ext_data = ext.extension_data(&client.defragment_buffer);
                            // Cookie extension format: cookie<1..2^16-1> (u16 length prefix)
                            if ext_data.len() >= 2 {
                                let cookie_len =
                                    u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                                if ext_data.len() >= 2 + cookie_len {
                                    let mut cookie = Buf::new();
                                    cookie.extend_from_slice(&ext_data[..2 + cookie_len]);
                                    client.saved_cookie = Some(cookie);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Validate HRR cipher suite
            if !client
                .engine
                .is_cipher_suite_allowed(server_hello.cipher_suite)
            {
                return Err(Error::SecurityError(
                    "HRR selected disallowed cipher suite".into(),
                ));
            }
            client.engine.set_cipher_suite(server_hello.cipher_suite);

            // Validate HRR supported_versions
            let mut hrr_version_ok = false;
            if let Some(ref extensions) = server_hello.extensions {
                for ext in extensions {
                    if ext.extension_type == ExtensionType::SupportedVersions {
                        let ext_data = ext.extension_data(&client.defragment_buffer);
                        if let Ok((_, sv)) = SupportedVersionsServerHello::parse(ext_data) {
                            hrr_version_ok = sv.selected_version == ProtocolVersion::DTLS1_3;
                        }
                    }
                }
            }
            if !hrr_version_ok {
                return Err(Error::SecurityError("HRR did not select DTLS 1.3".into()));
            }

            // Replace transcript with message_hash per RFC 8446 Section 4.4.1.
            // The HRR was already appended to the transcript by next_handshake().
            // We must hash only CH1, then re-append the HRR bytes.
            let hrr_bytes = client.engine.transcript[transcript_len_before..].to_vec();
            client.engine.transcript.resize(transcript_len_before, 0);
            client.engine.replace_transcript_with_message_hash();
            client.engine.transcript.extend_from_slice(&hrr_bytes);
            client.engine.advance_peer_handshake_seq();
            client.engine.reset_for_hello_retry();
            client.hello_retry = true;

            // Drop the old key exchange
            client.active_key_exchange = None;

            return Ok(Self::SendClientHello);
        }

        // Validate legacy_version (must be DTLS 1.2)
        if server_hello.legacy_version != ProtocolVersion::DTLS1_2 {
            return Err(Error::SecurityError(
                "ServerHello legacy_version must be DTLS 1.2".into(),
            ));
        }

        // Validate legacy_compression_method (must be null)
        if server_hello.legacy_compression_method != CompressionMethod::Null {
            return Err(Error::SecurityError(
                "ServerHello compression must be null".into(),
            ));
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
        let mut shared_secret = client.engine.pop_buffer();
        key_exchange
            .complete(peer_pub_key, &mut shared_secret)
            .map_err(|e| Error::CryptoError(format!("ECDHE completion failed: {}", e)))?;

        // Derive handshake secrets
        let (c_hs_traffic, s_hs_traffic) =
            client.engine.derive_handshake_secrets(&shared_secret)?;

        // Save handshake secret for later application key derivation
        let handshake_secret = client.engine.derive_handshake_secret(&shared_secret)?;
        client.handshake_secret = Some(handshake_secret);
        client.engine.push_buffer(shared_secret);

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

        client.engine.advance_peer_handshake_seq();
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

        client.engine.advance_peer_handshake_seq();
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

        let Some(ref handshake) = maybe else {
            return Ok(self);
        };

        // Parse CertificateRequest body
        let Body::CertificateRequest(ref range) = handshake.body else {
            unreachable!()
        };
        let cr_range = range.clone();
        drop(maybe);
        let cr_data = &client.defragment_buffer[cr_range.clone()];
        let context = parse_certificate_request(cr_data, cr_range.start)?;
        if let Some(ctx) = context {
            client.cert_request_context = Some(ctx);
        }

        // CertificateRequest received - we'll send client Certificate + CertificateVerify
        debug!("Received CertificateRequest; enabling client authentication path");
        client.client_auth_requested = true;

        client.engine.advance_peer_handshake_seq();
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

        if !certificate.context_range.is_empty() {
            return Err(Error::SecurityError(
                "Server certificate context must be empty".into(),
            ));
        }

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

        client.engine.advance_peer_handshake_seq();
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

        let (hash_alg, sig_alg) = signature_scheme_to_components(scheme)?;

        client.engine.verify_signature(
            cert_der,
            &signed_content,
            &signature_copy,
            hash_alg,
            sig_alg,
        )?;

        trace!("Server CertificateVerify verified: {:?}", scheme);

        client.engine.advance_peer_handshake_seq();
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

        client.engine.advance_peer_handshake_seq();

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

        // Note: send handshake keys were already installed by install_handshake_keys()
        // after ServerHello. Do NOT reinstall them here — that would reset hs_send_seq
        // to 0, colliding with ACK records already sent on epoch 2.

        if client.client_auth_requested {
            Ok(Self::SendCertificate)
        } else {
            Ok(Self::SendFinished)
        }
    }

    fn send_certificate(self, client: &mut Client) -> Result<Self, Error> {
        debug!("Sending Certificate");

        // Start a new flight for the client's Certificate/CertificateVerify/Finished.
        // This clears the old ClientHello flight from flight_saved_records.
        client.engine.flight_begin(5);

        let has_cert = !client.engine.certificate_der().is_empty();

        if has_cert {
            let context = client.cert_request_context.as_deref().unwrap_or(&[]);
            let context = context.to_vec(); // clone so we don't borrow client

            client
                .engine
                .create_handshake(MessageType::Certificate, |body, engine| {
                    handshake_create_certificate(body, engine, &context)
                })?;

            Ok(Self::SendCertificateVerify)
        } else {
            // No client certificate: send empty Certificate and skip CertificateVerify
            let context = client.cert_request_context.as_deref().unwrap_or(&[]);
            let context = context.to_vec();

            client
                .engine
                .create_handshake(MessageType::Certificate, |body, _engine| {
                    // certificate_request_context
                    body.push(context.len() as u8);
                    body.extend_from_slice(&context);
                    // empty certificate_list (3-byte zero length)
                    body.extend_from_slice(&[0, 0, 0]);
                    Ok(())
                })?;

            Ok(Self::SendFinished)
        }
    }

    fn send_certificate_verify(self, client: &mut Client) -> Result<Self, Error> {
        debug!("Sending CertificateVerify");

        client
            .engine
            .create_handshake(MessageType::CertificateVerify, |body, engine| {
                handshake_create_certificate_verify(
                    body,
                    engine,
                    b"TLS 1.3, client CertificateVerify\0",
                )
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

        // Don't stop flight timers here - the server needs to receive our Finished.
        // Timers will stop when we receive an ACK from the server confirming it
        // received our epoch-2 flight.

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
        // Auto-trigger KeyUpdate when AEAD encryption limit is reached
        if client.engine.needs_key_update() && !client.engine.is_key_update_in_flight() {
            client.initiate_key_update()?;
        }

        // Send queued application data
        if !client.queued_data.is_empty() {
            let epoch = client.engine.app_send_epoch();
            debug!(
                "Sending queued application data: {}",
                client.queued_data.len()
            );
            for data in client.queued_data.drain(..) {
                client.engine.create_ciphertext_record(
                    ContentType::ApplicationData,
                    epoch,
                    false,
                    |body| {
                        body.extend_from_slice(&data);
                    },
                )?;
            }
        }

        // Send pending KeyUpdate response before processing new KeyUpdates
        if client.pending_key_update_response {
            client
                .engine
                .create_key_update(KeyUpdateRequest::UpdateNotRequested)?;
            client.pending_key_update_response = false;
        }

        // Check for incoming KeyUpdate
        if client.engine.has_complete_handshake(MessageType::KeyUpdate) {
            let maybe = client.engine.next_handshake_no_transcript(
                MessageType::KeyUpdate,
                &mut client.defragment_buffer,
            )?;

            if let Some(handshake) = maybe {
                let Body::KeyUpdate(request) = handshake.body else {
                    unreachable!()
                };

                // Install new recv keys
                client.engine.update_recv_keys()?;

                // ACK the KeyUpdate record
                client.engine.send_ack()?;

                // If peer requested us to update, schedule our own KeyUpdate
                if request == KeyUpdateRequest::UpdateRequested {
                    client.pending_key_update_response = true;
                }

                client.engine.advance_peer_handshake_seq();
                debug!("Received KeyUpdate (request={:?})", request);
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
    cookie_range: Option<std::ops::Range<usize>>,
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
    let mut extensions: ArrayVec<Extension, 8> = ArrayVec::new();
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
    let mut entries = ArrayVec::new();
    entries.push(KeyShareEntry {
        group: kx_group,
        key_exchange_range: pub_key_range,
    });
    let ks = KeyShareClientHello { entries };
    ks.serialize(extension_data, &mut ext_buf);
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

    // 6. cookie extension (echo from HRR if present)
    if let Some(cookie_range) = cookie_range {
        let cookie_start = ext_buf.len();
        // Cookie data already includes the u16 length prefix from the HRR
        ext_buf.extend_from_slice(&extension_data[cookie_range]);
        let cookie_end = ext_buf.len();
        extensions.push(Extension {
            extension_type: ExtensionType::Cookie,
            extension_data_range: cookie_start..cookie_end,
        });
    }

    // 7. padding extension (RFC 7685) — pad ClientHello to fill the MTU,
    // reducing the server-to-client amplification factor.
    let mtu = engine.config().mtu();
    let record_header = 13; // DTLSPlaintext header
    let handshake_header = 12; // DTLS handshake header
    let body_without_padding = 2 // legacy_version
        + 32 // random
        + 1 + legacy_session_id.len()
        + 1 + legacy_cookie.len()
        + 2 + cipher_suites.len() * 2
        + 1 + compression_methods.len()
        + 2 // extensions_len
        + extensions.len() * 4 // type(2) + len(2) per extension
        + ext_buf.len(); // all extension data
    let total_without_padding = record_header + handshake_header + body_without_padding;
    let deficit = mtu.saturating_sub(total_without_padding);
    if deficit >= 4 {
        let pad_data_len = deficit - 4;
        let pad_start = ext_buf.len();
        for _ in 0..pad_data_len {
            ext_buf.push(0);
        }
        let pad_end = ext_buf.len();
        extensions.push(Extension {
            extension_type: ExtensionType::Padding,
            extension_data_range: pad_start..pad_end,
        });
    }

    let mut client_hello = ClientHello::new(
        legacy_version,
        random,
        legacy_session_id,
        legacy_cookie,
        cipher_suites,
        compression_methods,
    );
    client_hello.extensions = extensions;

    client_hello.serialize(&ext_buf, body);
    Ok(())
}

pub(crate) fn handshake_create_certificate(
    body: &mut Buf,
    engine: &mut Engine,
    context: &[u8],
) -> Result<(), Error> {
    // Build a source buffer: context bytes then cert DER
    let mut src = Buf::new();
    let context_start = src.len();
    src.extend_from_slice(context);
    let context_end = src.len();

    let cert_start = src.len();
    src.extend_from_slice(engine.certificate_der());
    let cert_end = src.len();

    let mut certificate_list = ArrayVec::new();
    certificate_list.push(CertificateEntry {
        cert: Asn1Cert(cert_start..cert_end),
        extensions_range: 0..0,
    });

    let certificate = Certificate {
        context_range: context_start..context_end,
        certificate_list,
    };

    certificate.serialize(&src, body);
    Ok(())
}

pub(crate) fn handshake_create_certificate_verify(
    body: &mut Buf,
    engine: &mut Engine,
    context_string: &[u8],
) -> Result<(), Error> {
    // Build signed content: 0x20*64 || context_string || transcript_hash
    let mut signed_content = Buf::new();
    signed_content.extend_from_slice(&[0x20u8; 64]);
    signed_content.extend_from_slice(context_string);

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
pub(crate) fn signature_scheme_to_components(
    scheme: SignatureScheme,
) -> Result<
    (
        crate::types::HashAlgorithm,
        crate::types::SignatureAlgorithm,
    ),
    crate::Error,
> {
    use crate::types::{HashAlgorithm, SignatureAlgorithm};
    match scheme {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            Ok((HashAlgorithm::SHA256, SignatureAlgorithm::ECDSA))
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            Ok((HashAlgorithm::SHA384, SignatureAlgorithm::ECDSA))
        }
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            Ok((HashAlgorithm::SHA512, SignatureAlgorithm::ECDSA))
        }
        SignatureScheme::ED25519 => Err(Error::SecurityError(
            "ED25519 not yet supported by crypto provider".into(),
        )),
        SignatureScheme::RSA_PSS_RSAE_SHA256 => {
            Ok((HashAlgorithm::SHA256, SignatureAlgorithm::RSA))
        }
        SignatureScheme::RSA_PSS_RSAE_SHA384 => {
            Ok((HashAlgorithm::SHA384, SignatureAlgorithm::RSA))
        }
        SignatureScheme::RSA_PSS_RSAE_SHA512 => {
            Ok((HashAlgorithm::SHA512, SignatureAlgorithm::RSA))
        }
        SignatureScheme::RSA_PSS_PSS_SHA256 => Ok((HashAlgorithm::SHA256, SignatureAlgorithm::RSA)),
        SignatureScheme::RSA_PSS_PSS_SHA384 => Ok((HashAlgorithm::SHA384, SignatureAlgorithm::RSA)),
        SignatureScheme::RSA_PSS_PSS_SHA512 => Ok((HashAlgorithm::SHA512, SignatureAlgorithm::RSA)),
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512 => Err(Error::SecurityError(
            "RSA PKCS1v1.5 not allowed in TLS 1.3".into(),
        )),
        _ => Err(Error::SecurityError(format!(
            "Unsupported signature scheme: {:?}",
            scheme
        ))),
    }
}

/// Parse a TLS 1.3 CertificateRequest message (RFC 8446 Section 4.3.2).
///
/// Extracts the certificate_request_context and parses extensions including
/// certificate_authorities. Returns the context if non-empty.
fn parse_certificate_request(cr_data: &[u8], base_offset: usize) -> Result<Option<Buf>, Error> {
    if cr_data.is_empty() {
        return Ok(None);
    }

    // certificate_request_context<0..255>
    let context_len = cr_data[0] as usize;
    let mut pos = 1;
    let mut context = None;
    if context_len > 0 {
        if cr_data.len() < 1 + context_len {
            return Err(Error::UnexpectedMessage(
                "CertificateRequest context truncated".into(),
            ));
        }
        let mut ctx = Buf::new();
        ctx.extend_from_slice(&cr_data[pos..pos + context_len]);
        context = Some(ctx);
        pos += context_len;
    }

    // extensions<2..2^16-1>
    if cr_data.len() < pos + 2 {
        return Ok(context);
    }
    let ext_len = u16::from_be_bytes([cr_data[pos], cr_data[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    if cr_data.len() < ext_end {
        return Err(Error::UnexpectedMessage(
            "CertificateRequest extensions truncated".into(),
        ));
    }

    // Parse individual extensions
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([cr_data[pos], cr_data[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([cr_data[pos + 2], cr_data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_data_len > ext_end {
            break;
        }

        if ext_type == ExtensionType::CertificateAuthorities.as_u16() {
            // Parse certificate_authorities: DistinguishedName<3..2^16-1>
            let ca_data = &cr_data[pos..pos + ext_data_len];
            if ca_data.len() >= 2 {
                let list_len = u16::from_be_bytes([ca_data[0], ca_data[1]]) as usize;
                let list_data = &ca_data[2..];
                if list_data.len() >= list_len {
                    let ca_base = base_offset + pos + 2;
                    let mut rest = &list_data[..list_len];
                    while !rest.is_empty() {
                        let offset =
                            ca_base + (rest.as_ptr() as usize - list_data.as_ptr() as usize);
                        match DistinguishedName::parse(rest, offset) {
                            Ok((r, _dn)) => rest = r,
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        pos += ext_data_len;
    }

    Ok(context)
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
