// DTLS 1.3 Server Handshake Flow (RFC 9147):
//
// 1. Server receives ClientHello (with supported_versions, key_share extensions)
// 2. Server may send HelloRetryRequest with cookie (stateless retry)
//    - If so, Client sends another ClientHello with the cookie
// 3. Server sends ServerHello, then encrypted:
//    EncryptedExtensions, (CertificateRequest), Certificate, CertificateVerify, Finished
// 4. Server receives encrypted: (Certificate, CertificateVerify), Finished from client
// 5. Handshake complete, application data can flow
//
// Key differences from DTLS 1.2:
// - No ChangeCipherSpec
// - No ServerKeyExchange / ClientKeyExchange (key_share extension instead)
// - No ServerHelloDone
// - Most of server flight is encrypted after ServerHello
// - HelloRetryRequest replaces HelloVerifyRequest for cookies
//
// This implementation is a Sans-IO DTLS 1.3 server.

use std::collections::VecDeque;
use std::time::Instant;

use arrayvec::ArrayVec;
use rand::random;
use subtle::ConstantTimeEq;

use super::engine::Engine;
use crate::buffer::{Buf, ToBuf};
use crate::crypto::CipherSuite;
use crate::event::LocalEvent;
use crate::message::Body;
use crate::message::CompressionMethod;
use crate::message::ContentType;
use crate::message::CookieExtension;
use crate::message::Extension;
use crate::message::ExtensionType;
use crate::message::MessageType;
use crate::message::NamedGroup;
use crate::message::ProtocolVersion;
use crate::message::Random;
use crate::message::ServerHello;
use crate::message::SessionId;
use crate::message::SignatureAlgorithmsExtension;
use crate::message::SignatureAndHashAlgorithm;
use crate::message::SupportedGroupsExtension;
use crate::message::SupportedVersionsServerHello;
use crate::message::UseSrtpExtension;
use crate::{Error, Output, SrtpProfile};

/// Type alias for DTLS 1.3 cipher keys result (cipher, IV, SN key).
type Dtls13CipherResult = Option<(Box<dyn crate::crypto::Cipher>, [u8; 12], [u8; 16])>;

/// DTLS 1.3 server state machine.
pub struct Server13 {
    /// Current server state.
    state: State,

    /// Engine in common between server and client.
    engine: Engine,

    /// The last now we seen
    last_now: Option<Instant>,

    /// Local events to emit
    local_events: VecDeque<LocalEvent>,

    /// Data that is sent before we are connected.
    queued_data: Vec<Buf>,

    /// Server random value.
    random: Option<Random>,

    /// Session ID (legacy, but needed for compatibility).
    session_id: SessionId,

    /// Cookie secret for HMAC (stateless retry).
    cookie_secret: [u8; 32],

    /// Client random from ClientHello.
    client_random: Option<Random>,

    /// Client certificates received.
    client_certificates: Vec<Buf>,

    /// Buffer for defragmenting handshakes.
    defragment_buffer: Buf,

    /// Whether we requested client certificate.
    certificate_requested: bool,

    /// The negotiated SRTP profile (if any).
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Selected cipher suite.
    selected_cipher_suite: Option<CipherSuite>,

    /// Selected named group for key exchange.
    selected_group: Option<NamedGroup>,

    /// Client's supported groups.
    client_supported_groups: Option<ArrayVec<NamedGroup, 16>>,

    /// Client's signature algorithms.
    client_signature_algorithms: Option<ArrayVec<SignatureAndHashAlgorithm, 32>>,

    /// Server's key share (public key).
    server_key_share: Option<Buf>,

    /// ECDHE shared secret (stored for key derivation).
    shared_secret: Option<Buf>,

    /// Server handshake traffic secret (for Finished verification).
    server_hs_traffic_secret: Option<Buf>,

    /// Client handshake traffic secret (for verifying client Finished).
    client_hs_traffic_secret: Option<Buf>,
}

impl Server13 {
    /// Create a new DTLS 1.3 server.
    pub fn new(
        config: std::sync::Arc<crate::Config>,
        certificate: crate::DtlsCertificate,
    ) -> Server13 {
        let engine = Engine::new(config, certificate);
        Self::new_with_engine(engine)
    }

    pub(crate) fn new_with_engine(mut engine: Engine) -> Server13 {
        engine.set_client(false);
        engine.set_dtls13(true); // DTLS 1.3 transcript format

        let cookie_secret: [u8; 32] = random();

        Server13 {
            state: State::AwaitClientHello,
            engine,
            last_now: None,
            local_events: VecDeque::new(),
            queued_data: Vec::new(),
            random: None,
            session_id: SessionId::empty(),
            cookie_secret,
            client_random: None,
            client_certificates: Vec::with_capacity(3),
            defragment_buffer: Buf::new(),
            certificate_requested: false,
            negotiated_srtp_profile: None,
            selected_cipher_suite: None,
            selected_group: None,
            client_supported_groups: None,
            client_signature_algorithms: None,
            server_key_share: None,
            shared_secret: None,
            server_hs_traffic_secret: None,
            client_hs_traffic_secret: None,
        }
    }

    /// Convert this server into a DTLS 1.3 client (role switch).
    pub fn into_client(self) -> super::client::Client13 {
        super::client::Client13::new_with_engine(self.engine)
    }

    /// Process an incoming DTLS packet.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.engine.parse_packet(packet)?;
        self.make_progress()?;
        Ok(())
    }

    /// Poll for pending output from the DTLS engine.
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        let last_now = self
            .last_now
            .expect("need handle_timeout before poll_output");

        if let Some(event) = self.local_events.pop_front() {
            return event.into_output(buf, &self.client_certificates);
        }

        self.engine.poll_output(buf, last_now)
    }

    /// Handle time-based events such as retransmission timers.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.last_now = Some(now);
        if self.random.is_none() {
            self.random = Some(Random::new(now));
        }
        self.engine.handle_timeout(now)?;
        self.make_progress()?;
        Ok(())
    }

    /// Send application data when the server is connected.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            self.queued_data.push(data.to_buf());
            return Ok(());
        }

        if self.engine.has_dtls13_send_keys() {
            // Use DTLS 1.3 record encryption (epoch 3)
            // Fragment data if larger than max record size
            let max_fragment = self.engine.max_dtls13_app_data_fragment_size();
            for chunk in data.chunks(max_fragment) {
                self.engine
                    .create_record_dtls13(ContentType::ApplicationData, |body| {
                        body.extend_from_slice(chunk);
                    })?;
            }
        } else {
            // Fallback to DTLS 1.2 style
            self.engine
                .create_record(ContentType::ApplicationData, 1, false, |body| {
                    body.extend_from_slice(data);
                })?;
        }

        Ok(())
    }

    /// Get the number of completed outgoing KeyUpdates (our send keys updated).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn key_updates_sent(&self) -> u32 {
        self.engine.key_updates_sent()
    }

    /// Get the number of processed incoming KeyUpdates (our receive keys updated).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn key_updates_received(&self) -> u32 {
        self.engine.key_updates_received()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_flight_epoch2_saved(&self) -> usize {
        self.engine.test_dtls13_flight_epoch2_saved()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_flight_epoch2_acked(&self) -> usize {
        self.engine.test_dtls13_flight_epoch2_acked()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_epoch2_sent(&self) -> (u32, usize) {
        self.engine.test_dtls13_handshake_ack_epoch2_sent()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_epoch2_received(&self) -> (u32, usize, usize) {
        self.engine.test_dtls13_handshake_ack_epoch2_received()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_deadline(&self) -> Option<Instant> {
        self.engine.test_dtls13_handshake_ack_deadline()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_has_gap_in_incoming(&self) -> bool {
        self.engine.test_dtls13_has_gap_in_incoming()
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_dtls13_handshake_ack_help_needed(&self) -> bool {
        self.engine.test_dtls13_handshake_ack_help_needed()
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
    /// Await initial ClientHello
    AwaitClientHello,
    /// Send HelloRetryRequest (if needed for cookie or key_share)
    SendHelloRetryRequest,
    /// Send ServerHello
    SendServerHello,
    /// Send EncryptedExtensions (encrypted)
    SendEncryptedExtensions,
    /// Send CertificateRequest (optional, encrypted)
    SendCertificateRequest,
    /// Send server Certificate (encrypted)
    SendCertificate,
    /// Send server CertificateVerify (encrypted)
    SendCertificateVerify,
    /// Send server Finished (encrypted)
    SendFinished,
    /// Await client Certificate (if requested)
    AwaitCertificate,
    /// Await client CertificateVerify (if Certificate received)
    AwaitCertificateVerify,
    /// Await client Finished
    AwaitFinished,
    /// Handshake complete, ready for application data
    Connected,
}

impl State {
    fn make_progress(self, server: &mut Server13) -> Result<Self, Error> {
        match self {
            State::AwaitClientHello => self.await_client_hello(server),
            State::SendHelloRetryRequest => self.send_hello_retry_request(server),
            State::SendServerHello => self.send_server_hello(server),
            State::SendEncryptedExtensions => self.send_encrypted_extensions(server),
            State::SendCertificateRequest => self.send_certificate_request(server),
            State::SendCertificate => self.send_certificate(server),
            State::SendCertificateVerify => self.send_certificate_verify(server),
            State::SendFinished => self.send_finished(server),
            State::AwaitCertificate => self.await_certificate(server),
            State::AwaitCertificateVerify => self.await_certificate_verify(server),
            State::AwaitFinished => self.await_finished(server),
            State::Connected => self.connected(server),
        }
    }

    fn await_client_hello(self, server: &mut Server13) -> Result<Self, Error> {
        let maybe = server
            .engine
            .next_handshake(MessageType::ClientHello, &mut server.defragment_buffer)?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        let Body::ClientHello(ch) = handshake.body else {
            unreachable!()
        };

        // In TLS 1.3, server MUST echo the client's legacy_session_id
        server.session_id = ch.session_id;

        // In DTLS 1.3, legacy_version is 0xFEFD (DTLS 1.2)
        if ch.client_version != ProtocolVersion::DTLS1_2 {
            return Err(Error::SecurityError(format!(
                "Invalid legacy_version in ClientHello: {:?}",
                ch.client_version
            )));
        }

        // Enforce Null compression only
        let has_null = ch.compression_methods.contains(&CompressionMethod::Null);
        if !has_null {
            return Err(Error::SecurityError(
                "Client did not offer Null compression".to_string(),
            ));
        }

        trace!(
            "ClientHello: offered_suites={}, extensions={}",
            ch.cipher_suites.len(),
            ch.extensions.len()
        );

        // Store client random
        let client_random = ch.random;
        server.client_random = Some(client_random);

        // Parse extensions
        let mut supported_versions_ok = false;
        let mut client_key_share: Option<(NamedGroup, Buf)> = None;
        let mut client_supported_groups: Option<ArrayVec<NamedGroup, 16>> = None;
        let mut client_signature_algorithms: Option<ArrayVec<SignatureAndHashAlgorithm, 32>> = None;
        let mut client_srtp_profiles: Option<ArrayVec<crate::message::SrtpProfileId, 32>> = None;
        let mut cookie_data: Option<Buf> = None;

        for ext in &ch.extensions {
            match ext.extension_type {
                ExtensionType::SupportedVersions => {
                    let ext_data = ext.extension_data(&server.defragment_buffer);
                    if let Ok((_, sv)) =
                        crate::message::SupportedVersionsClientHello::parse(ext_data)
                    {
                        // Check if client supports DTLS 1.3 (0xFEFC)
                        if sv.versions.contains(&ProtocolVersion::DTLS1_3) {
                            supported_versions_ok = true;
                        }
                    }
                }
                ExtensionType::KeyShare => {
                    let ext_data = ext.extension_data(&server.defragment_buffer);
                    if let Ok((_, ks)) = crate::message::KeyShareClientHello::parse(ext_data, 0) {
                        // Pick first supported group
                        for entry in &ks.entries {
                            if is_supported_group(entry.group) {
                                let key_bytes = entry.key_exchange(ext_data);
                                client_key_share = Some((entry.group, Buf::from_slice(key_bytes)));
                                break;
                            }
                        }
                    }
                }
                ExtensionType::SupportedGroups => {
                    let ext_data = ext.extension_data(&server.defragment_buffer);
                    if let Ok((_, groups)) = SupportedGroupsExtension::parse(ext_data) {
                        client_supported_groups = Some(groups.groups);
                    }
                }
                ExtensionType::SignatureAlgorithms => {
                    let ext_data = ext.extension_data(&server.defragment_buffer);
                    if let Ok((_, sigs)) = SignatureAlgorithmsExtension::parse(ext_data) {
                        client_signature_algorithms = Some(sigs.supported_signature_algorithms);
                    }
                }
                ExtensionType::UseSrtp => {
                    let ext_data = ext.extension_data(&server.defragment_buffer);
                    if let Ok((_, use_srtp)) = UseSrtpExtension::parse(ext_data) {
                        client_srtp_profiles = Some(use_srtp.profiles);
                    }
                }
                ExtensionType::Cookie => {
                    let ext_data = ext.extension_data(&server.defragment_buffer);
                    if let Ok((_, cookie)) = CookieExtension::parse(ext_data, 0) {
                        let cookie_bytes = cookie.cookie(ext_data);
                        cookie_data = Some(Buf::from_slice(cookie_bytes));
                    }
                }
                _ => {}
            }
        }

        // Verify supported_versions includes DTLS 1.3
        if !supported_versions_ok {
            return Err(Error::SecurityError(
                "Client does not support DTLS 1.3".to_string(),
            ));
        }

        // Select TLS 1.3 cipher suite early (needed for both HRR and ServerHello)
        let mut selected_suite: Option<CipherSuite> = None;
        for suite in ch.cipher_suites.iter() {
            if suite.is_tls13() && server.engine.is_cipher_suite_allowed(*suite) {
                selected_suite = Some(*suite);
                break;
            }
        }

        let Some(cs) = selected_suite else {
            return Err(Error::SecurityError(
                "No mutually acceptable TLS 1.3 cipher suite".to_string(),
            ));
        };

        server.engine.set_cipher_suite(cs);
        server.selected_cipher_suite = Some(cs);
        debug!("Selected cipher suite: {:?}", cs);

        // Verify cookie if we sent HelloRetryRequest
        // For now, we use stateless cookie: HMAC(secret, client_random)
        let hmac_provider = server.engine.config().crypto_provider().hmac_provider;

        // Check if client provided a key share for a group we support
        // If not, we need HRR to request one
        let need_hrr_for_key_share = client_key_share.is_none();

        // TODO: Re-enable cookie requirement after OpenSSL interop is working
        // let need_cookie = cookie_data.is_none();
        let need_cookie = false; // Disabled for testing

        if need_cookie || need_hrr_for_key_share {
            if need_hrr_for_key_share {
                debug!("ClientHello missing compatible key share; will send HelloRetryRequest");
            } else {
                debug!("ClientHello missing cookie; will send HelloRetryRequest");
            }
            // Store extension data for HRR
            server.client_supported_groups = client_supported_groups;
            return Ok(State::SendHelloRetryRequest);
        }

        // Verify cookie
        if let Some(ref cookie) = cookie_data {
            if !verify_cookie_13(hmac_provider, &server.cookie_secret, client_random, cookie) {
                return Err(Error::SecurityError("Invalid cookie".to_string()));
            }
        }

        // Need a key share from the client
        let Some((group, client_public_key)) = client_key_share else {
            return Err(Error::SecurityError(
                "Client did not provide a key share".to_string(),
            ));
        };

        server.selected_group = Some(group);
        server.client_supported_groups = client_supported_groups;
        server.client_signature_algorithms = client_signature_algorithms;

        // Initialize server's key exchange
        let mut kx_buf = server.engine.pop_buffer();
        let server_public_key = server
            .engine
            .crypto_context_mut()
            .init_ecdh_server(group, &mut kx_buf)
            .map_err(|e| Error::CryptoError(format!("Key exchange init failed: {}", e)))?;

        server.server_key_share = Some(Buf::from_slice(server_public_key));

        // Compute shared secret
        let mut shared_secret_buf = server.engine.pop_buffer();
        server
            .engine
            .crypto_context_mut()
            .compute_shared_secret(&client_public_key, &mut shared_secret_buf)
            .map_err(|e| Error::CryptoError(format!("Shared secret computation failed: {}", e)))?;

        server.shared_secret = Some(shared_secret_buf);
        server.engine.push_buffer(kx_buf);

        // Select SRTP profile
        if let Some(profiles) = client_srtp_profiles {
            for preferred in [
                SrtpProfile::AeadAes256Gcm,
                SrtpProfile::AeadAes128Gcm,
                SrtpProfile::Aes128CmSha1_80,
            ] {
                if profiles.iter().any(|pid| preferred == (*pid).into()) {
                    server.negotiated_srtp_profile = Some(preferred);
                    debug!("Negotiated SRTP profile: {:?}", preferred);
                    break;
                }
            }
        }

        Ok(State::SendServerHello)
    }

    fn send_hello_retry_request(self, server: &mut Server13) -> Result<Self, Error> {
        debug!("Sending HelloRetryRequest");

        // Start flight timer
        server.engine.flight_begin(2);

        // Compute cookie
        let client_random = server
            .client_random
            .ok_or_else(|| Error::UnexpectedMessage("No client random".to_string()))?;
        let hmac_provider = server.engine.config().crypto_provider().hmac_provider;
        let cookie = compute_cookie_13(hmac_provider, &server.cookie_secret, client_random)?;

        // Get the selected cipher suite (must have been selected before HRR)
        let cipher_suite = server.selected_cipher_suite.ok_or_else(|| {
            Error::UnexpectedMessage("No cipher suite selected for HRR".to_string())
        })?;

        // Select a group to request (prefer P-256)
        let selected_group = select_hrr_group(server.client_supported_groups.as_ref());

        // Replace transcript with TLS 1.3 message_hash construct BEFORE creating HRR
        // Per RFC 8446, the transcript after HRR is:
        //   message_hash || HelloRetryRequest || ClientHello2
        // So we must replace transcript first, then HRR gets added to it
        server
            .engine
            .transcript_replace_for_hrr(crate::message::HashAlgorithm::SHA256);

        let session_id = server.session_id;
        server
            .engine
            .create_handshake(MessageType::ServerHello, move |body, _engine| {
                // HRR uses special random value
                let hrr_random = Random::from_bytes(&HELLO_RETRY_REQUEST_RANDOM);

                // Build extensions
                let mut ext_data = Buf::new();
                let mut extensions: ArrayVec<Extension, 32> = ArrayVec::new();

                // supported_versions extension (required)
                let sv = SupportedVersionsServerHello {
                    selected_version: ProtocolVersion::DTLS1_3,
                };
                let sv_start = ext_data.len();
                sv.serialize(&mut ext_data);
                extensions.push(Extension {
                    extension_type: ExtensionType::SupportedVersions,
                    extension_data_range: sv_start..ext_data.len(),
                });

                // key_share extension (selected_group only for HRR)
                let ks_start = ext_data.len();
                ext_data.extend_from_slice(&selected_group.as_u16().to_be_bytes());
                extensions.push(Extension {
                    extension_type: ExtensionType::KeyShare,
                    extension_data_range: ks_start..ext_data.len(),
                });

                // cookie extension
                let cookie_start = ext_data.len();
                CookieExtension::serialize_from_bytes(cookie.as_ref(), &mut ext_data);
                extensions.push(Extension {
                    extension_type: ExtensionType::Cookie,
                    extension_data_range: cookie_start..ext_data.len(),
                });

                // Serialize ServerHello (which is actually HRR)
                // HRR must also echo the client's legacy_session_id
                let sh = ServerHello {
                    server_version: ProtocolVersion::DTLS1_2, // Legacy
                    random: hrr_random,
                    session_id,
                    cipher_suite, // Must match what will be sent in ServerHello
                    compression_method: CompressionMethod::Null,
                    extensions: Some(extensions),
                };

                sh.serialize(&ext_data, body);
                Ok(())
            })?;

        // Go back to await ClientHello (with cookie)
        Ok(State::AwaitClientHello)
    }

    fn send_server_hello(self, server: &mut Server13) -> Result<Self, Error> {
        debug!("Sending ServerHello");

        // Start flight timer
        server.engine.flight_begin(4);

        let random = server.random.unwrap();
        let session_id = server.session_id;
        let cipher_suite = server
            .selected_cipher_suite
            .ok_or_else(|| Error::UnexpectedMessage("No cipher suite selected".to_string()))?;
        let selected_group = server
            .selected_group
            .ok_or_else(|| Error::UnexpectedMessage("No group selected".to_string()))?;
        let server_key_share = server
            .server_key_share
            .as_ref()
            .ok_or_else(|| Error::UnexpectedMessage("No server key share".to_string()))?;

        server
            .engine
            .create_handshake(MessageType::ServerHello, move |body, _engine| {
                let mut ext_data = Buf::new();
                let mut extensions: ArrayVec<Extension, 32> = ArrayVec::new();

                // supported_versions extension
                let sv = SupportedVersionsServerHello {
                    selected_version: ProtocolVersion::DTLS1_3,
                };
                let sv_start = ext_data.len();
                sv.serialize(&mut ext_data);
                extensions.push(Extension {
                    extension_type: ExtensionType::SupportedVersions,
                    extension_data_range: sv_start..ext_data.len(),
                });

                // key_share extension
                let ks_start = ext_data.len();
                // Serialize KeyShareServerHello: group (2) + key_exchange_len (2) + key_exchange
                ext_data.extend_from_slice(&selected_group.as_u16().to_be_bytes());
                ext_data.extend_from_slice(&(server_key_share.len() as u16).to_be_bytes());
                ext_data.extend_from_slice(server_key_share);
                extensions.push(Extension {
                    extension_type: ExtensionType::KeyShare,
                    extension_data_range: ks_start..ext_data.len(),
                });

                let sh = ServerHello {
                    server_version: ProtocolVersion::DTLS1_2, // Legacy
                    random,
                    session_id,
                    cipher_suite,
                    compression_method: CompressionMethod::Null,
                    extensions: Some(extensions),
                };

                sh.serialize(&ext_data, body);
                Ok(())
            })?;

        // Derive handshake traffic keys after ServerHello
        // Transcript hash covers ClientHello...ServerHello
        let hash_alg = cipher_suite.hash_algorithm();
        let mut transcript_hash = Buf::new();
        server
            .engine
            .transcript_hash(hash_alg, &mut transcript_hash);

        debug!(
            "Server transcript_hash at key derivation: {:02x?}",
            &*transcript_hash
        );
        debug!(
            "Server raw transcript len={}, first 32 bytes: {:02x?}",
            server.engine.transcript().len(),
            &server.engine.transcript()[..32.min(server.engine.transcript().len())]
        );

        // Derive keys with provider first, then install separately
        let (send_cipher, recv_cipher, client_hs_secret, server_hs_secret) = {
            let provider = server.engine.config().crypto_provider();
            let shared_secret = server.shared_secret.as_ref();

            let mut send_result: Dtls13CipherResult = None;
            let mut recv_result: Dtls13CipherResult = None;
            let mut client_secret: Option<Buf> = None;
            let mut server_secret: Option<Buf> = None;

            if let Some(shared_secret) = shared_secret {
                if let Ok(mut ks) = crate::crypto::tls13_key_schedule::KeySchedule::new(
                    provider.hkdf_provider,
                    hash_alg,
                ) {
                    if let Ok((client_hs, server_hs)) =
                        ks.derive_handshake_secrets(shared_secret, &transcript_hash)
                    {
                        // Store the secrets for Finished verification
                        client_secret = Some(Buf::from_slice(&client_hs));
                        server_secret = Some(Buf::from_slice(&server_hs));

                        let (key_len, iv_len) = match cipher_suite {
                            CipherSuite::TLS_AES_128_GCM_SHA256 => (16, 12),
                            CipherSuite::TLS_AES_256_GCM_SHA384 => (32, 12),
                            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => (32, 12),
                            _ => (16, 12),
                        };

                        // Server->client keys (for encrypting) - use DTLS 1.3 derivation with sn_key
                        if let Ok((server_key, server_iv, server_sn_key)) =
                            ks.derive_traffic_keys_dtls13(&server_hs, key_len, iv_len)
                        {
                            debug!("Server derived server_key: {:02x?}", &server_key[..]);
                            debug!("Server derived server_iv: {:02x?}", &server_iv[..]);
                            debug!("Server derived server_sn_key: {:02x?}", &server_sn_key[..]);
                            if let Some(suite_impl) = provider.cipher_suites.iter().find(|s| {
                                s.suite() == cipher_suite
                                    || (cipher_suite.is_tls13() && s.hash_algorithm() == hash_alg)
                            }) {
                                if let Ok(cipher) = suite_impl.create_cipher(&server_key) {
                                    let mut iv = [0u8; 12];
                                    iv.copy_from_slice(&server_iv[..12]);
                                    let mut sn_key = [0u8; 16];
                                    sn_key.copy_from_slice(&server_sn_key[..16]);
                                    send_result = Some((cipher, iv, sn_key));
                                }
                            }
                        }

                        // Client->server keys (for decrypting) - use DTLS 1.3 derivation with sn_key
                        if let Ok((client_key, client_iv, client_sn_key)) =
                            ks.derive_traffic_keys_dtls13(&client_hs, key_len, iv_len)
                        {
                            if let Some(suite_impl) = provider.cipher_suites.iter().find(|s| {
                                s.suite() == cipher_suite
                                    || (cipher_suite.is_tls13() && s.hash_algorithm() == hash_alg)
                            }) {
                                if let Ok(cipher) = suite_impl.create_cipher(&client_key) {
                                    let mut iv = [0u8; 12];
                                    iv.copy_from_slice(&client_iv[..12]);
                                    let mut sn_key = [0u8; 16];
                                    sn_key.copy_from_slice(&client_sn_key[..16]);
                                    recv_result = Some((cipher, iv, sn_key));
                                }
                            }
                        }
                    }
                }
            }

            (send_result, recv_result, client_secret, server_secret)
        };

        // Store handshake secrets for Finished verification
        server.client_hs_traffic_secret = client_hs_secret;
        server.server_hs_traffic_secret = server_hs_secret;

        // Now install keys (provider borrow is released)
        if let Some((cipher, iv, sn_key)) = send_cipher {
            server
                .engine
                .install_dtls13_hs_send_keys_with_sn(cipher, &iv, &sn_key);
            debug!("Installed handshake send keys (epoch 2)");
        }
        if let Some((cipher, iv, sn_key)) = recv_cipher {
            server
                .engine
                .install_dtls13_hs_recv_keys_with_sn(cipher, &iv, &sn_key);
            debug!("Installed handshake receive keys (epoch 2)");
        }

        // Note: We intentionally do NOT flush the datagram here. Keeping ServerHello
        // and encrypted records in the same datagram ensures they arrive together,
        // which is important for out-of-order packet handling. If they were in separate
        // datagrams, the encrypted records could arrive before ServerHello, and the peer
        // couldn't decrypt them without the keys from ServerHello.
        //
        // RFC 9147 allows mixing DTLS 1.2 format (ServerHello) and DTLS 1.3 unified
        // header records in the same datagram.

        Ok(State::SendEncryptedExtensions)
    }

    fn send_encrypted_extensions(self, server: &mut Server13) -> Result<Self, Error> {
        debug!("Sending EncryptedExtensions");

        let negotiated_srtp = server.negotiated_srtp_profile;

        server.engine.create_handshake_dtls13(
            MessageType::EncryptedExtensions,
            move |body, _engine| {
                let mut ext_data = Buf::new();
                let mut extensions: ArrayVec<Extension, 32> = ArrayVec::new();

                // Add use_srtp extension if negotiated
                if let Some(profile) = negotiated_srtp {
                    let srtp_id: crate::message::SrtpProfileId = match profile {
                        SrtpProfile::AeadAes256Gcm => {
                            crate::message::SrtpProfileId::SrtpAeadAes256Gcm
                        }
                        SrtpProfile::AeadAes128Gcm => {
                            crate::message::SrtpProfileId::SrtpAeadAes128Gcm
                        }
                        SrtpProfile::Aes128CmSha1_80 => {
                            crate::message::SrtpProfileId::SrtpAes128CmSha1_80
                        }
                    };
                    let mut profiles = ArrayVec::new();
                    profiles.push(srtp_id);
                    let use_srtp = UseSrtpExtension::new(profiles, Vec::new());
                    let start = ext_data.len();
                    use_srtp.serialize(&mut ext_data);
                    extensions.push(Extension {
                        extension_type: ExtensionType::UseSrtp,
                        extension_data_range: start..ext_data.len(),
                    });
                }

                // Serialize EncryptedExtensions
                // Format: extensions_length (2) + extensions
                let mut ee_body = Buf::new();

                // Calculate total extensions length
                let mut total_len: u16 = 0;
                for ext in &extensions {
                    // Each extension: type (2) + length (2) + data
                    total_len +=
                        4 + (ext.extension_data_range.end - ext.extension_data_range.start) as u16;
                }

                ee_body.extend_from_slice(&total_len.to_be_bytes());
                for ext in &extensions {
                    ee_body.extend_from_slice(&ext.extension_type.as_u16().to_be_bytes());
                    let data = &ext_data[ext.extension_data_range.clone()];
                    ee_body.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    ee_body.extend_from_slice(data);
                }

                body.extend_from_slice(&ee_body);
                Ok(())
            },
        )?;

        if server.engine.config().require_client_certificate() {
            server.certificate_requested = true;
            Ok(State::SendCertificateRequest)
        } else {
            Ok(State::SendCertificate)
        }
    }

    fn send_certificate_request(self, server: &mut Server13) -> Result<Self, Error> {
        debug!("Sending CertificateRequest");

        server.engine.create_handshake_dtls13(
            MessageType::CertificateRequest,
            |body, _engine| {
                // TLS 1.3 CertificateRequest format:
                // certificate_request_context (opaque <0..2^8-1>)
                // extensions (Extension extensions<2..2^16-1>)

                // Empty context
                body.push(0);

                // Extensions - at minimum, signature_algorithms
                let sig_algs = SignatureAlgorithmsExtension::default();
                let mut ext_data = Buf::new();
                sig_algs.serialize(&mut ext_data);

                // Extension: type (2) + length (2) + data
                let ext_total_len = 4 + ext_data.len();
                body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
                body.extend_from_slice(&ExtensionType::SignatureAlgorithms.as_u16().to_be_bytes());
                body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
                body.extend_from_slice(&ext_data);

                Ok(())
            },
        )?;

        Ok(State::SendCertificate)
    }

    fn send_certificate(self, server: &mut Server13) -> Result<Self, Error> {
        debug!("Sending Certificate");

        server
            .engine
            .create_handshake_dtls13(MessageType::Certificate, |body, engine| {
                // TLS 1.3 Certificate format:
                // certificate_request_context (opaque <0..2^8-1>)
                // certificate_list (CertificateEntry certificate_list<0..2^24-1>)

                // Empty context (we're server)
                body.push(0);

                // Serialize certificate chain in TLS 1.3 format
                engine.crypto_context().serialize_certificate_tls13(body);

                Ok(())
            })?;

        Ok(State::SendCertificateVerify)
    }

    fn send_certificate_verify(self, server: &mut Server13) -> Result<Self, Error> {
        debug!("Sending CertificateVerify");

        // Get transcript hash for signature
        let suite = server
            .selected_cipher_suite
            .ok_or_else(|| Error::UnexpectedMessage("No cipher suite".to_string()))?;
        let suite_hash = suite.hash_algorithm();

        // Select signature algorithm
        let sig_alg = select_signature_algorithm(
            server.client_signature_algorithms.as_ref(),
            server.engine.crypto_context().signature_algorithm(),
        );

        server
            .engine
            .create_handshake_dtls13(MessageType::CertificateVerify, |body, engine| {
                // TLS 1.3 CertificateVerify format:
                // SignatureScheme algorithm (2)
                // opaque signature<0..2^16-1>

                // Compute transcript hash (up to but not including CertificateVerify)
                let mut transcript_hash = engine.pop_buffer();
                engine.transcript_hash(suite_hash, &mut transcript_hash);

                // Build data to sign:
                // 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
                let mut sign_data = Buf::new();
                sign_data.extend_from_slice(&[0x20u8; 64]); // 64 spaces
                sign_data.extend_from_slice(b"TLS 1.3, server CertificateVerify");
                sign_data.push(0x00);
                sign_data.extend_from_slice(&transcript_hash);

                engine.push_buffer(transcript_hash);

                // Sign
                let mut signature = engine.pop_buffer();
                engine
                    .crypto_context
                    .sign_data(&sign_data, sig_alg.hash, &mut signature)
                    .map_err(|e| Error::CryptoError(format!("Failed to sign: {}", e)))?;

                // Write algorithm + signature
                body.extend_from_slice(&sig_alg.as_u16().to_be_bytes());
                body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
                body.extend_from_slice(&signature);

                engine.push_buffer(signature);
                Ok(())
            })?;

        Ok(State::SendFinished)
    }

    fn send_finished(self, server: &mut Server13) -> Result<Self, Error> {
        debug!("Sending Finished");

        // Compute verify_data using TLS 1.3 key schedule
        let verify_data = {
            let cipher_suite = server
                .selected_cipher_suite
                .ok_or_else(|| Error::CryptoError("No cipher suite selected".to_string()))?;
            let hash_alg = cipher_suite.hash_algorithm();
            let server_hs_secret = server
                .server_hs_traffic_secret
                .as_ref()
                .ok_or_else(|| Error::CryptoError("No server handshake secret".to_string()))?;

            // Get transcript hash up to this point (before Finished)
            let mut transcript_hash = server.engine.pop_buffer();
            server
                .engine
                .transcript_hash(hash_alg, &mut transcript_hash);

            let provider = server.engine.config().crypto_provider();

            // Create key schedule for derive_finished
            let ks = crate::crypto::tls13_key_schedule::KeySchedule::new(
                provider.hkdf_provider,
                hash_alg,
            )
            .map_err(Error::CryptoError)?;

            let verify = ks
                .derive_finished(server_hs_secret, &transcript_hash, provider.hmac_provider)
                .map_err(Error::CryptoError)?;

            server.engine.push_buffer(transcript_hash);
            verify
        };

        server
            .engine
            .create_handshake_dtls13(MessageType::Finished, |body, _engine| {
                body.extend_from_slice(&verify_data);
                Ok(())
            })?;

        // Derive application keys and exporter master secret
        if let (Some(shared_secret), Some(cipher_suite)) =
            (&server.shared_secret, server.selected_cipher_suite)
        {
            let hash_alg = cipher_suite.hash_algorithm();

            // Get transcript hash first (before we need provider)
            let mut transcript_hash = server.engine.pop_buffer();
            server
                .engine
                .transcript_hash(hash_alg, &mut transcript_hash);

            let provider = server.engine.config().crypto_provider();

            // Create key schedule and derive secrets
            if let Ok(mut ks) = crate::crypto::tls13_key_schedule::KeySchedule::new(
                provider.hkdf_provider,
                hash_alg,
            ) {
                // Derive handshake secrets first (needed to advance key schedule)
                if ks
                    .derive_handshake_secrets(shared_secret, &transcript_hash)
                    .is_ok()
                {
                    // Derive application secrets
                    if let Ok((client_app_secret, server_app_secret)) =
                        ks.derive_application_secrets(&transcript_hash)
                    {
                        // Derive traffic keys
                        let (key_len, iv_len) = match cipher_suite {
                            CipherSuite::TLS_AES_128_GCM_SHA256 => (16, 12),
                            CipherSuite::TLS_AES_256_GCM_SHA384 => (32, 12),
                            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => (32, 12),
                            _ => (16, 12),
                        };

                        // Derive send keys (server -> client) with sn_key for DTLS 1.3
                        let send_cipher = if let Ok((server_key, server_iv, server_sn_key)) =
                            ks.derive_traffic_keys_dtls13(&server_app_secret, key_len, iv_len)
                        {
                            provider
                                .cipher_suites
                                .iter()
                                .find(|s| {
                                    s.suite() == cipher_suite
                                        || (cipher_suite.is_tls13()
                                            && s.hash_algorithm() == hash_alg)
                                })
                                .and_then(|suite_impl| {
                                    suite_impl.create_cipher(&server_key).ok().map(|c| {
                                        let mut sn_key = [0u8; 16];
                                        sn_key.copy_from_slice(&server_sn_key[..16]);
                                        (c, server_iv, sn_key)
                                    })
                                })
                        } else {
                            None
                        };

                        // Derive receive keys (client -> server) with sn_key for DTLS 1.3
                        let recv_cipher = if let Ok((client_key, client_iv, client_sn_key)) =
                            ks.derive_traffic_keys_dtls13(&client_app_secret, key_len, iv_len)
                        {
                            provider
                                .cipher_suites
                                .iter()
                                .find(|s| {
                                    s.suite() == cipher_suite
                                        || (cipher_suite.is_tls13()
                                            && s.hash_algorithm() == hash_alg)
                                })
                                .and_then(|suite_impl| {
                                    suite_impl.create_cipher(&client_key).ok().map(|c| {
                                        let mut sn_key = [0u8; 16];
                                        sn_key.copy_from_slice(&client_sn_key[..16]);
                                        (c, client_iv, sn_key)
                                    })
                                })
                        } else {
                            None
                        };

                        // Derive exporter master secret
                        let exporter_secret = ks.derive_exporter_secret(&transcript_hash).ok();

                        // Now install keys (mutable borrow of engine)
                        if let Some((cipher, iv, sn_key)) = send_cipher {
                            server
                                .engine
                                .install_dtls13_send_keys_with_sn(cipher, &iv, &sn_key);
                            // Store the traffic secret for KeyUpdate derivation
                            server.engine.set_send_traffic_secret(&server_app_secret);
                            debug!("Installed DTLS 1.3 send keys (epoch 3)");
                        }
                        if let Some((cipher, iv, sn_key)) = recv_cipher {
                            server
                                .engine
                                .install_dtls13_recv_keys_with_sn(cipher, &iv, &sn_key);
                            // Store the traffic secret for KeyUpdate derivation
                            server.engine.set_recv_traffic_secret(&client_app_secret);
                            debug!("Installed DTLS 1.3 receive keys (epoch 3)");
                        }
                        if let Some(secret) = exporter_secret {
                            server
                                .engine
                                .crypto_context_mut()
                                .set_exporter_master_secret(secret);
                            debug!("Derived TLS 1.3 exporter master secret");
                        }
                    }
                }
            }
            server.engine.push_buffer(transcript_hash);
        }

        // Piggyback any queued application data with the Finished flight
        // Since we just installed application keys, we can send app data now
        if !server.queued_data.is_empty() && server.engine.has_dtls13_send_keys() {
            debug!(
                "Piggybacking {} queued application data with server Finished",
                server.queued_data.len()
            );
            let max_fragment = server.engine.max_dtls13_app_data_fragment_size();
            for data in server.queued_data.drain(..) {
                for chunk in data.chunks(max_fragment) {
                    server
                        .engine
                        .create_record_dtls13(ContentType::ApplicationData, |body| {
                            body.extend_from_slice(chunk);
                        })?;
                }
            }
        }

        // Note: Do NOT stop resend timers here. The server must keep retransmitting
        // its flight until it receives acknowledgment (client's response).
        // Timers are stopped in await_finished after receiving client's Finished,
        // or in await_certificate after receiving client's Certificate.

        if server.certificate_requested {
            Ok(State::AwaitCertificate)
        } else {
            Ok(State::AwaitFinished)
        }
    }

    fn await_certificate(self, server: &mut Server13) -> Result<Self, Error> {
        let maybe = server
            .engine
            .next_handshake(MessageType::Certificate, &mut server.defragment_buffer)?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        // We received client's Certificate - stop resend timers
        server.engine.flight_stop_resend_timers();

        // Handle TLS 1.3 Certificate format
        let cert_ranges: ArrayVec<_, 32> = match &handshake.body {
            Body::Certificate13(certificate) => certificate
                .certificate_list
                .iter()
                .map(|c| c.cert_data.clone())
                .collect(),
            Body::Certificate(certificate) => {
                // Fallback for DTLS 1.2 format (shouldn't happen in DTLS 1.3)
                certificate
                    .certificate_list
                    .iter()
                    .map(|cert| cert.0.clone())
                    .collect()
            }
            _ => unreachable!("Expected Certificate or Certificate13 body"),
        };

        let is_empty = cert_ranges.is_empty();

        drop(handshake);

        if !is_empty {
            debug!(
                "Received client certificate chain with {} certificate(s)",
                cert_ranges.len()
            );
            for range in cert_ranges {
                let cert_data = &server.defragment_buffer[range];
                server.client_certificates.push(cert_data.to_buf());
            }
            server.local_events.push_back(LocalEvent::PeerCert);
        }

        if !server.client_certificates.is_empty() {
            Ok(State::AwaitCertificateVerify)
        } else {
            Ok(State::AwaitFinished)
        }
    }

    fn await_certificate_verify(self, server: &mut Server13) -> Result<Self, Error> {
        // Compute transcript hash BEFORE processing CertificateVerify
        let suite_hash = server.selected_cipher_suite.unwrap().hash_algorithm();
        let mut transcript_before_cv = server.engine.pop_buffer();
        server
            .engine
            .transcript_hash(suite_hash, &mut transcript_before_cv);

        let maybe = server.engine.next_handshake(
            MessageType::CertificateVerify,
            &mut server.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            server.engine.push_buffer(transcript_before_cv);
            return Ok(self);
        };

        let Body::CertificateVerify(cv) = &handshake.body else {
            unreachable!()
        };

        let signature_range = cv.signed.signature_range.clone();
        let signature_algorithm = cv.signed.algorithm;

        drop(handshake);

        let signature_bytes = &server.defragment_buffer[signature_range];

        if server.client_certificates.is_empty() {
            return Err(Error::CertificateError(
                "CertificateVerify received but no client certificate".to_string(),
            ));
        }

        // Build verification data for TLS 1.3
        let mut verify_data = Buf::new();
        verify_data.extend_from_slice(&[0x20u8; 64]); // 64 spaces
        verify_data.extend_from_slice(b"TLS 1.3, client CertificateVerify");
        verify_data.push(0x00);
        verify_data.extend_from_slice(&transcript_before_cv);

        let temp_signed = crate::message::DigitallySigned {
            algorithm: signature_algorithm,
            signature_range: 0..signature_bytes.len(),
        };

        server
            .engine
            .crypto_context()
            .verify_signature(
                &verify_data,
                &temp_signed,
                signature_bytes,
                &server.client_certificates[0],
            )
            .map_err(|e| {
                Error::CryptoError(format!("Failed to verify client CertificateVerify: {}", e))
            })?;

        server.engine.push_buffer(transcript_before_cv);
        debug!("Client CertificateVerify verified successfully");

        Ok(State::AwaitFinished)
    }

    fn await_finished(self, server: &mut Server13) -> Result<Self, Error> {
        // Compute expected verify_data using TLS 1.3 key schedule
        let expected = {
            let cipher_suite = server
                .selected_cipher_suite
                .ok_or_else(|| Error::CryptoError("No cipher suite selected".to_string()))?;
            let hash_alg = cipher_suite.hash_algorithm();
            let client_hs_secret = server
                .client_hs_traffic_secret
                .as_ref()
                .ok_or_else(|| Error::CryptoError("No client handshake secret".to_string()))?;

            // Get transcript hash up to this point (before Finished)
            let mut transcript_hash = server.engine.pop_buffer();
            server
                .engine
                .transcript_hash(hash_alg, &mut transcript_hash);

            let provider = server.engine.config().crypto_provider();

            // Create key schedule for derive_finished
            let ks = crate::crypto::tls13_key_schedule::KeySchedule::new(
                provider.hkdf_provider,
                hash_alg,
            )
            .map_err(Error::CryptoError)?;

            let verify = ks
                .derive_finished(client_hs_secret, &transcript_hash, provider.hmac_provider)
                .map_err(Error::CryptoError)?;

            server.engine.push_buffer(transcript_hash);
            verify
        };

        let maybe = server
            .engine
            .next_handshake(MessageType::Finished, &mut server.defragment_buffer)?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        // We received client's Finished - stop resend timers (if not already stopped)
        server.engine.flight_stop_resend_timers();

        let Body::Finished(finished) = &handshake.body else {
            unreachable!()
        };

        let verify_data_range = finished.verify_data_range.clone();

        drop(handshake);

        let verify_data = &server.defragment_buffer[verify_data_range];

        // Constant-time comparison
        let is_eq: bool = verify_data.ct_eq(&expected[..]).into();
        if !is_eq {
            return Err(Error::SecurityError(
                "Client Finished verification failed".to_string(),
            ));
        }

        debug!("Client Finished verified successfully");

        // Handshake complete
        server.local_events.push_back(LocalEvent::Connected);

        // Piggyback queued application data immediately after handshake completes
        // This saves a round-trip by including app data with the first post-handshake packet
        if !server.queued_data.is_empty() && server.engine.has_dtls13_send_keys() {
            debug!(
                "Piggybacking {} queued application data after Finished verification",
                server.queued_data.len()
            );
            let max_fragment = server.engine.max_dtls13_app_data_fragment_size();
            for data in server.queued_data.drain(..) {
                for chunk in data.chunks(max_fragment) {
                    server
                        .engine
                        .create_record_dtls13(ContentType::ApplicationData, |body| {
                            body.extend_from_slice(chunk);
                        })?;
                }
            }
        }

        // Emit SRTP keying material if negotiated (using TLS 1.3 exporter)
        if let Some(profile) = server.negotiated_srtp_profile {
            let suite_hash = server.selected_cipher_suite.unwrap().hash_algorithm();
            match server
                .engine
                .crypto_context()
                .extract_srtp_keying_material_tls13(profile, suite_hash)
            {
                Ok(keying_material) => {
                    debug!(
                        "SRTP keying material extracted ({} bytes) for profile: {:?}",
                        keying_material.len(),
                        profile
                    );
                    server
                        .local_events
                        .push_back(LocalEvent::KeyingMaterial(keying_material, profile));
                }
                Err(e) => {
                    warn!("Failed to extract SRTP keying material: {}", e);
                }
            }
        }

        server.engine.release_application_data();

        Ok(State::Connected)
    }

    fn connected(self, server: &mut Server13) -> Result<Self, Error> {
        // Process any incoming post-handshake messages (ACK, KeyUpdate)
        server.engine.process_incoming_post_handshake()?;

        // Send any queued application data using DTLS 1.3 record encryption
        if !server.queued_data.is_empty() {
            debug!(
                "Sending queued application data: {}",
                server.queued_data.len()
            );
            for data in server.queued_data.drain(..) {
                if server.engine.has_dtls13_send_keys() {
                    // Use DTLS 1.3 record encryption (epoch 3)
                    server
                        .engine
                        .create_record_dtls13(ContentType::ApplicationData, |body| {
                            body.extend_from_slice(&data);
                        })?;
                } else {
                    // Fallback to DTLS 1.2 style (shouldn't happen in 1.3 mode)
                    server.engine.create_record(
                        ContentType::ApplicationData,
                        1,
                        false,
                        |body| {
                            body.extend_from_slice(&data);
                        },
                    )?;
                }
            }
        }

        Ok(self)
    }
}

/// HelloRetryRequest has a special random value (RFC 8446 Section 4.1.3)
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

fn is_supported_group(group: NamedGroup) -> bool {
    // P-256, P-384, and X25519 are supported by aws-lc-rs
    matches!(
        group,
        NamedGroup::Secp256r1 | NamedGroup::Secp384r1 | NamedGroup::X25519
    )
}

fn select_hrr_group(client_groups: Option<&ArrayVec<NamedGroup, 16>>) -> NamedGroup {
    // Prefer X25519, then P-256, then P-384
    let preferred = [
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        NamedGroup::Secp384r1,
    ];

    if let Some(groups) = client_groups {
        for p in preferred {
            if groups.contains(&p) {
                return p;
            }
        }
    }

    // Default to P-256
    NamedGroup::Secp256r1
}

fn compute_cookie_13(
    hmac_provider: &dyn crate::crypto::HmacProvider,
    secret: &[u8],
    client_random: Random,
) -> Result<Buf, Error> {
    let mut buf = Buf::new();
    client_random.serialize(&mut buf);
    let tag = hmac_provider
        .hmac_sha256(secret, &buf)
        .map_err(|e| Error::CryptoError(format!("Failed to compute HMAC: {}", e)))?;
    Ok(Buf::from_slice(&tag))
}

fn verify_cookie_13(
    hmac_provider: &dyn crate::crypto::HmacProvider,
    secret: &[u8],
    client_random: Random,
    cookie: &[u8],
) -> bool {
    if cookie.len() != 32 {
        return false;
    }
    match compute_cookie_13(hmac_provider, secret, client_random) {
        Ok(expected) => expected.as_ref().ct_eq(cookie).into(),
        Err(_) => false,
    }
}

fn select_signature_algorithm(
    client_algorithms: Option<&ArrayVec<SignatureAndHashAlgorithm, 32>>,
    server_sig_alg: crate::message::SignatureAlgorithm,
) -> SignatureAndHashAlgorithm {
    use crate::message::HashAlgorithm;

    // Preferred hash algorithms for TLS 1.3
    let preferred_hashes = [HashAlgorithm::SHA256, HashAlgorithm::SHA384];

    if let Some(algorithms) = client_algorithms {
        for hash in preferred_hashes {
            let candidate = SignatureAndHashAlgorithm {
                hash,
                signature: server_sig_alg,
            };
            if algorithms.contains(&candidate) {
                return candidate;
            }
        }
    }

    // Default to SHA-256 with server's signature algorithm
    SignatureAndHashAlgorithm {
        hash: crate::message::HashAlgorithm::SHA256,
        signature: server_sig_alg,
    }
}

impl std::fmt::Debug for Server13 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server13")
            .field("state", &self.state)
            .finish()
    }
}
