// DTLS 1.3 Client Handshake Flow (RFC 9147):
//
// 1. Client sends ClientHello (with supported_versions, key_share extensions)
// 2. Server may respond with HelloRetryRequest containing a cookie
//    - If so, Client sends another ClientHello with the cookie
// 3. Server sends ServerHello, then encrypted:
//    EncryptedExtensions, (CertificateRequest), Certificate, CertificateVerify, Finished
// 4. Client sends encrypted: (Certificate, CertificateVerify), Finished
// 5. Handshake complete, application data can flow
//
// Key differences from DTLS 1.2:
// - No ChangeCipherSpec
// - No ServerKeyExchange / ClientKeyExchange (key_share extension instead)
// - No ServerHelloDone
// - Most of server flight is encrypted
// - HelloRetryRequest replaces HelloVerifyRequest for cookies
//
// This implementation is a Sans-IO DTLS 1.3 client.

use std::collections::VecDeque;
use std::time::Instant;

use arrayvec::ArrayVec;

use crate::buffer::{Buf, ToBuf};
use crate::crypto::CipherSuite;
use crate::event::LocalEvent;
use crate::message::Body;
use crate::message::ClientHello;
use crate::message::CompressionMethod;
use crate::message::ContentType;
use crate::message::CookieExtension;
use crate::message::ECPointFormatsExtension;
use crate::message::Extension;
use crate::message::ExtensionType;
use crate::message::KeyShareEntry;
use crate::message::KeyShareHelloRetryRequest;
use crate::message::KeyShareServerHello;
use crate::message::MessageType;
use crate::message::NamedGroup;
use crate::message::ProtocolVersion;
use crate::message::Random;
use crate::message::SessionId;
use crate::message::SignatureAlgorithmsExtension;
use crate::message::SignatureAndHashAlgorithm;
use crate::message::SupportedGroupsExtension;
use crate::message::SupportedVersionsClientHello;
use crate::message::SupportedVersionsServerHello;
use crate::message::UseSrtpExtension;
use crate::{Error, Output, SrtpProfile};

use super::engine::Engine;

/// Type alias for DTLS 1.3 cipher keys result (cipher, IV, SN key).
type Dtls13CipherResult = Option<(Box<dyn crate::crypto::Cipher>, [u8; 12], [u8; 16])>;

/// DTLS 1.3 client state machine.
pub struct Client13 {
    /// Current client state.
    state: State,

    /// Engine in common between server and client.
    engine: Engine,

    /// The last now we seen
    last_now: Option<Instant>,

    /// Local events
    local_events: VecDeque<LocalEvent>,

    /// Data that is sent before we are connected.
    queued_data: Vec<Buf>,

    /// Client random value.
    random: Option<Random>,

    /// Session ID (legacy, but needed for compatibility).
    session_id: SessionId,

    /// Extension data buffer for serialization (needed for HRR retry).
    extension_data: Buf,

    /// Key share entries we offered in ClientHello.
    offered_key_shares: ArrayVec<NamedGroup, 4>,

    /// Cookie from HelloRetryRequest (if any).
    cookie: Option<Buf>,

    /// Selected group for key exchange (after ServerHello).
    selected_group: Option<NamedGroup>,

    /// Server certificates received.
    server_certificates: Vec<Buf>,

    /// Buffer for defragmenting handshakes.
    defragment_buffer: Buf,

    /// Whether server requested client certificate.
    certificate_requested: bool,

    /// The negotiated SRTP profile (if any).
    negotiated_srtp_profile: Option<SrtpProfile>,

    /// Server random from ServerHello.
    server_random: Option<Random>,

    /// ECDHE shared secret (stored for key derivation).
    shared_secret: Option<Buf>,

    /// Client handshake traffic secret (for Finished computation).
    client_hs_traffic_secret: Option<Buf>,

    /// Server handshake traffic secret (for verifying server Finished).
    server_hs_traffic_secret: Option<Buf>,
}

impl Client13 {
    pub(crate) fn new_with_engine(mut engine: Engine) -> Client13 {
        engine.set_client(true);
        engine.set_dtls13(true); // DTLS 1.3 transcript format

        Client13 {
            state: State::SendClientHello,
            engine,
            last_now: None,
            local_events: VecDeque::new(),
            queued_data: Vec::new(),
            random: None,
            session_id: SessionId::empty(),
            extension_data: Buf::new(),
            offered_key_shares: ArrayVec::new(),
            cookie: None,
            selected_group: None,
            server_certificates: Vec::with_capacity(3),
            defragment_buffer: Buf::new(),
            certificate_requested: false,
            negotiated_srtp_profile: None,
            server_random: None,
            shared_secret: None,
            client_hs_traffic_secret: None,
            server_hs_traffic_secret: None,
        }
    }

    /// Convert this client into a DTLS 1.3 server (role switch).
    pub fn into_server(self) -> super::server::Server13 {
        super::server::Server13::new_with_engine(self.engine)
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
            return event.into_output(buf, &self.server_certificates);
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

    /// Send application data when the client is connected.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            self.queued_data.push(Buf::from_slice(data));
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
            // Fallback - queue for later
            self.queued_data.push(Buf::from_slice(data));
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
    /// Send initial ClientHello
    SendClientHello,
    /// Await ServerHello (or HelloRetryRequest)
    AwaitServerHello,
    /// Await encrypted server flight (EncryptedExtensions, Certificate, etc.)
    AwaitEncryptedExtensions,
    /// Await server Certificate (if not using PSK)
    AwaitCertificate,
    /// Await server CertificateVerify
    AwaitCertificateVerify,
    /// Await server Finished
    AwaitFinished,
    /// Send client Certificate (if requested)
    SendCertificate,
    /// Send client CertificateVerify (if Certificate sent)
    SendCertificateVerify,
    /// Send client Finished
    SendFinished,
    /// Handshake complete, ready for application data
    Connected,
}

impl State {
    fn make_progress(self, client: &mut Client13) -> Result<Self, Error> {
        match self {
            State::SendClientHello => self.send_client_hello(client),
            State::AwaitServerHello => self.await_server_hello(client),
            State::AwaitEncryptedExtensions => self.await_encrypted_extensions(client),
            State::AwaitCertificate => self.await_certificate(client),
            State::AwaitCertificateVerify => self.await_certificate_verify(client),
            State::AwaitFinished => self.await_finished(client),
            State::SendCertificate => self.send_certificate(client),
            State::SendCertificateVerify => self.send_certificate_verify(client),
            State::SendFinished => self.send_finished(client),
            State::Connected => self.connected(client),
        }
    }

    fn send_client_hello(self, client: &mut Client13) -> Result<Self, Error> {
        // Determine flight number: 1 for initial, 3 for retry with cookie
        let flight_no = if client.cookie.is_none() { 1 } else { 3 };
        client.engine.flight_begin(flight_no);

        // unwrap: is ok because we set random in handle_timeout
        let random = client.random.unwrap();

        // Build ClientHello for DTLS 1.3
        client
            .engine
            .create_handshake(MessageType::ClientHello, |body, engine| {
                handshake_create_client_hello_13(
                    body,
                    engine,
                    random,
                    client.session_id,
                    &mut client.extension_data,
                    &mut client.offered_key_shares,
                    client.cookie.as_deref(),
                )
            })?;

        Ok(State::AwaitServerHello)
    }

    fn await_server_hello(self, client: &mut Client13) -> Result<Self, Error> {
        // Capture transcript length before next_handshake to track HRR bytes
        let transcript_len_before = client.engine.transcript().len();

        let maybe = client
            .engine
            .next_handshake(MessageType::ServerHello, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        let Body::ServerHello(server_hello) = &handshake.body else {
            unreachable!()
        };

        // Check for HelloRetryRequest (special random value)
        let is_hrr = is_hello_retry_request(&server_hello.random);

        // Extract data we need before potentially dropping handshake
        let server_version = server_hello.server_version;
        let cipher_suite = server_hello.cipher_suite;
        let server_random = server_hello.random;
        let extensions = server_hello.extensions.clone();

        // For HRR handling, we need to extract extension data while we still have the buffer
        let hrr_data = if is_hrr {
            Some(extract_hrr_data(&extensions, &client.defragment_buffer)?)
        } else {
            None
        };

        // Drop the borrow before handling HRR
        drop(handshake);

        if let Some((selected_group, cookie_data)) = hrr_data {
            // Get the HRR bytes that were added to transcript
            let hrr_transcript_bytes = client.engine.transcript()[transcript_len_before..].to_vec();
            return handle_hello_retry_request(
                client,
                selected_group,
                cookie_data,
                &hrr_transcript_bytes,
            );
        }

        debug!(
            "Received ServerHello: version={:?}, cipher_suite={:?}",
            server_version, cipher_suite
        );

        // In DTLS 1.3, the legacy version field is 0xFEFD (DTLS 1.2)
        // Real version is in supported_versions extension
        if server_version != ProtocolVersion::DTLS1_2 {
            return Err(Error::SecurityError(format!(
                "Invalid legacy_version in DTLS 1.3 ServerHello: {:?}",
                server_version
            )));
        }

        // Check cipher suite is TLS 1.3
        if !cipher_suite.is_tls13() {
            return Err(Error::SecurityError(format!(
                "Server selected non-TLS 1.3 cipher suite: {:?}",
                cipher_suite
            )));
        }

        // Store server random
        client.server_random = Some(server_random);

        // Parse extensions
        let Some(ref ext_list) = extensions else {
            return Err(Error::IncompleteServerHello);
        };

        // Find supported_versions extension
        let mut found_dtls13 = false;
        let mut key_share_entry: Option<KeyShareEntry> = None;

        for ext in ext_list {
            match ext.extension_type {
                ExtensionType::SupportedVersions => {
                    let ext_data = ext.extension_data(&client.defragment_buffer);
                    let (_, sv) = SupportedVersionsServerHello::parse(ext_data).map_err(|_| {
                        Error::SecurityError("Failed to parse supported_versions".to_string())
                    })?;
                    if sv.selected_version == ProtocolVersion::DTLS1_3 {
                        found_dtls13 = true;
                    }
                }
                ExtensionType::KeyShare => {
                    let ext_data = ext.extension_data(&client.defragment_buffer);
                    let offset = ext.extension_data_range.start;
                    let (_, ks) = KeyShareServerHello::parse(ext_data, offset).map_err(|_| {
                        Error::SecurityError("Failed to parse key_share".to_string())
                    })?;
                    key_share_entry = Some(ks.entry);
                }
                ExtensionType::UseSrtp => {
                    let ext_data = ext.extension_data(&client.defragment_buffer);
                    if let Ok((_, use_srtp)) = UseSrtpExtension::parse(ext_data) {
                        if !use_srtp.profiles.is_empty() {
                            client.negotiated_srtp_profile = Some(use_srtp.profiles[0].into());
                            trace!("ServerHello UseSRTP: {:?}", client.negotiated_srtp_profile);
                        }
                    }
                }
                _ => {}
            }
        }

        if !found_dtls13 {
            return Err(Error::SecurityError(
                "Server did not select DTLS 1.3".to_string(),
            ));
        }

        // Set DTLS 1.3 mode in engine (affects transcript format)
        client.engine.set_dtls13(true);

        let key_share = key_share_entry.ok_or_else(|| {
            Error::SecurityError("ServerHello missing key_share extension".to_string())
        })?;

        // Verify server selected a group we offered
        if !client.offered_key_shares.contains(&key_share.group) {
            return Err(Error::SecurityError(format!(
                "Server selected group {:?} we didn't offer",
                key_share.group
            )));
        }
        client.selected_group = Some(key_share.group);

        // Store cipher suite
        client.engine.set_cipher_suite(cipher_suite);

        // Compute ECDHE shared secret
        let server_public_key = key_share.key_exchange(&client.defragment_buffer);
        let mut kx_buf = client.engine.pop_buffer();
        client
            .engine
            .crypto_context_mut()
            .compute_shared_secret(server_public_key, &mut kx_buf)
            .map_err(|e| Error::CryptoError(format!("ECDHE failed: {}", e)))?;

        // Store shared secret for later key derivation
        client.shared_secret = Some(std::mem::take(&mut kx_buf));
        client.engine.push_buffer(kx_buf);

        // Compute transcript hash up to ServerHello (ClientHello...ServerHello)
        let hash_alg = cipher_suite.hash_algorithm();
        let mut transcript_hash = Buf::new();
        client
            .engine
            .transcript_hash(hash_alg, &mut transcript_hash);

        // Derive handshake traffic secrets and keys
        // We derive everything with provider first, then install keys separately
        let (recv_cipher, send_cipher, client_secret, server_secret) = {
            let provider = client.engine.config().crypto_provider();
            let shared_secret = client.shared_secret.as_ref().unwrap();

            let mut recv_result: Dtls13CipherResult = None;
            let mut send_result: Dtls13CipherResult = None;
            let mut client_hs: Option<Buf> = None;
            let mut server_hs: Option<Buf> = None;

            if let Ok(mut ks) = crate::crypto::tls13_key_schedule::KeySchedule::new(
                provider.hkdf_provider,
                hash_alg,
            ) {
                if let Ok((client_hs_secret, server_hs_secret)) =
                    ks.derive_handshake_secrets(shared_secret, &transcript_hash)
                {
                    // Store the secrets for Finished verification
                    client_hs = Some(Buf::from_slice(&client_hs_secret));
                    server_hs = Some(Buf::from_slice(&server_hs_secret));

                    // Log only non-sensitive metadata about derived secrets
                    debug!(
                        "Derived handshake secrets (shared_secret_len={}, transcript_len={})",
                        shared_secret.len(),
                        client.engine.transcript().len()
                    );

                    let (key_len, iv_len) = match cipher_suite {
                        CipherSuite::TLS_AES_128_GCM_SHA256 => (16, 12),
                        CipherSuite::TLS_AES_256_GCM_SHA384 => (32, 12),
                        CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => (32, 12),
                        _ => (16, 12),
                    };

                    // Server->client keys (for decrypting)
                    if let Ok((server_key, server_iv, server_sn_key)) =
                        ks.derive_traffic_keys_dtls13(&server_hs_secret, key_len, iv_len)
                    {
                        debug!("Derived server_key: {:02x?}", &server_key[..]);
                        debug!("Derived server_iv: {:02x?}", &server_iv[..]);
                        debug!("Derived server_sn_key: {:02x?}", &server_sn_key[..]);
                        if let Some(suite_impl) = provider.cipher_suites.iter().find(|s| {
                            s.suite() == cipher_suite
                                || (cipher_suite.is_tls13() && s.hash_algorithm() == hash_alg)
                        }) {
                            if let Ok(cipher) = suite_impl.create_cipher(&server_key) {
                                let mut iv = [0u8; 12];
                                iv.copy_from_slice(&server_iv[..12]);
                                let mut sn_key = [0u8; 16];
                                let sn_len = server_sn_key.len().min(16);
                                sn_key[..sn_len].copy_from_slice(&server_sn_key[..sn_len]);
                                recv_result = Some((cipher, iv, sn_key));
                            }
                        }
                    }

                    // Client->server keys (for encrypting)
                    if let Ok((client_key, client_iv, client_sn_key)) =
                        ks.derive_traffic_keys_dtls13(&client_hs_secret, key_len, iv_len)
                    {
                        debug!("Derived client_key: {:02x?}", &client_key[..]);
                        debug!("Derived client_iv: {:02x?}", &client_iv[..]);
                        debug!("Derived client_sn_key: {:02x?}", &client_sn_key[..]);
                        if let Some(suite_impl) = provider.cipher_suites.iter().find(|s| {
                            s.suite() == cipher_suite
                                || (cipher_suite.is_tls13() && s.hash_algorithm() == hash_alg)
                        }) {
                            if let Ok(cipher) = suite_impl.create_cipher(&client_key) {
                                let mut iv = [0u8; 12];
                                iv.copy_from_slice(&client_iv[..12]);
                                let mut sn_key = [0u8; 16];
                                let sn_len = client_sn_key.len().min(16);
                                sn_key[..sn_len].copy_from_slice(&client_sn_key[..sn_len]);
                                send_result = Some((cipher, iv, sn_key));
                            }
                        }
                    }
                }
            }

            (recv_result, send_result, client_hs, server_hs)
        };

        // Store handshake secrets for Finished verification
        client.client_hs_traffic_secret = client_secret;
        client.server_hs_traffic_secret = server_secret;

        // Now install keys (provider borrow is released)
        if let Some((cipher, iv, sn_key)) = recv_cipher {
            debug!(
                "Installing handshake recv keys with sn_key: {:02x?}",
                sn_key
            );
            client
                .engine
                .install_dtls13_hs_recv_keys_with_sn(cipher, &iv, &sn_key);
            debug!("Installed handshake receive keys with sn_key (epoch 2)");
        }
        if let Some((cipher, iv, sn_key)) = send_cipher {
            debug!(
                "Installing handshake send keys with sn_key: {:02x?}",
                sn_key
            );
            client
                .engine
                .install_dtls13_hs_send_keys_with_sn(cipher, &iv, &sn_key);
            debug!("Installed handshake send keys with sn_key (epoch 2)");
        }

        // Process any deferred packet data now that keys are installed
        if client.engine.has_deferred_packet() {
            client.engine.process_deferred_packet()?;
        }

        debug!(
            "Computed ECDHE shared secret ({} bytes), handshake keys installed",
            client.shared_secret.as_ref().map(|s| s.len()).unwrap_or(0)
        );

        Ok(State::AwaitEncryptedExtensions)
    }

    fn await_encrypted_extensions(self, client: &mut Client13) -> Result<Self, Error> {
        let maybe = client.engine.next_handshake(
            MessageType::EncryptedExtensions,
            &mut client.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        let Body::EncryptedExtensions(ee) = &handshake.body else {
            unreachable!()
        };

        debug!(
            "Received EncryptedExtensions with {} extensions",
            ee.extensions.len()
        );

        // Process extensions (e.g., use_srtp if not in ServerHello)
        for ext in &ee.extensions {
            if ext.extension_type == ExtensionType::UseSrtp {
                let ext_data = ext.extension_data(&client.defragment_buffer);
                if let Ok((_, use_srtp)) = UseSrtpExtension::parse(ext_data) {
                    if !use_srtp.profiles.is_empty() && client.negotiated_srtp_profile.is_none() {
                        client.negotiated_srtp_profile = Some(use_srtp.profiles[0].into());
                        trace!(
                            "EncryptedExtensions UseSRTP: {:?}",
                            client.negotiated_srtp_profile
                        );
                    }
                }
            }
        }

        Ok(State::AwaitCertificate)
    }

    fn await_certificate(self, client: &mut Client13) -> Result<Self, Error> {
        // Check if we might have a CertificateRequest first
        if client
            .engine
            .has_complete_handshake(MessageType::CertificateRequest)
        {
            let maybe = client.engine.next_handshake(
                MessageType::CertificateRequest,
                &mut client.defragment_buffer,
            )?;
            if maybe.is_some() {
                debug!("Server requested client certificate");
                client.certificate_requested = true;
            }
        }

        let maybe = client
            .engine
            .next_handshake(MessageType::Certificate, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        // Handle TLS 1.3 Certificate format
        let cert_ranges: ArrayVec<_, 32> = match &handshake.body {
            Body::Certificate13(certificate) => {
                if certificate.certificate_list.is_empty() {
                    return Err(Error::CertificateError(
                        "Server sent empty certificate".to_string(),
                    ));
                }
                debug!("Received TLS 1.3 Certificate");
                certificate
                    .certificate_list
                    .iter()
                    .map(|c| c.cert_data.clone())
                    .collect()
            }
            Body::Certificate(certificate) => {
                // Fallback for DTLS 1.2 format (shouldn't happen in DTLS 1.3)
                if certificate.certificate_list.is_empty() {
                    return Err(Error::CertificateError(
                        "Server sent empty certificate".to_string(),
                    ));
                }
                debug!("Received Certificate");
                certificate
                    .certificate_list
                    .iter()
                    .map(|c| c.0.clone())
                    .collect()
            }
            _ => unreachable!("Expected Certificate or Certificate13 body"),
        };

        drop(handshake);

        for range in cert_ranges {
            let cert_data = &client.defragment_buffer[range];
            client.server_certificates.push(cert_data.to_buf());
        }

        // Emit peer cert event
        client.local_events.push_back(LocalEvent::PeerCert);

        Ok(State::AwaitCertificateVerify)
    }

    fn await_certificate_verify(self, client: &mut Client13) -> Result<Self, Error> {
        // First, compute the transcript hash BEFORE CertificateVerify is processed
        // This is needed for signature verification
        let cipher_suite = client
            .engine
            .cipher_suite()
            .ok_or_else(|| Error::CryptoError("No cipher suite".to_string()))?;
        let hash_alg = cipher_suite.hash_algorithm();

        let mut transcript_before_cv = Buf::new();
        client
            .engine
            .transcript_hash(hash_alg, &mut transcript_before_cv);

        // Now get the CertificateVerify message (this adds it to transcript)
        let maybe = client.engine.next_handshake(
            MessageType::CertificateVerify,
            &mut client.defragment_buffer,
        )?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        let Body::CertificateVerify(cv) = &handshake.body else {
            unreachable!()
        };

        debug!(
            "Received CertificateVerify: algorithm={:?}",
            cv.signed.algorithm
        );

        // Get signature bytes
        let signature = &client.defragment_buffer[cv.signed.signature_range.clone()];

        // Build the data that was signed: context string + 0x00 + transcript hash
        // TLS 1.3 context: 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript

        let mut signed_data = Buf::new();
        // 64 spaces
        signed_data.extend_from_slice(&[0x20u8; 64]);
        // Context string for server
        signed_data.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        // Separator
        signed_data.push(0x00);
        // Transcript hash (computed BEFORE CertificateVerify)
        signed_data.extend_from_slice(&transcript_before_cv);

        // Verify signature against server certificate
        let server_cert = client
            .server_certificates
            .first()
            .ok_or_else(|| Error::CertificateError("No server certificate".to_string()))?;

        let temp_signed = crate::message::DigitallySigned {
            algorithm: cv.signed.algorithm,
            signature_range: 0..signature.len(),
        };

        client
            .engine
            .crypto_context_mut()
            .verify_signature(&signed_data, &temp_signed, signature, server_cert)
            .map_err(|e| Error::CryptoError(format!("CertificateVerify failed: {}", e)))?;

        debug!("Server CertificateVerify verified successfully");

        Ok(State::AwaitFinished)
    }

    fn await_finished(self, client: &mut Client13) -> Result<Self, Error> {
        // Compute expected verify_data using TLS 1.3 key schedule
        let cipher_suite = client
            .engine
            .cipher_suite()
            .ok_or_else(|| Error::CryptoError("No cipher suite".to_string()))?;
        let hash_alg = cipher_suite.hash_algorithm();

        let mut transcript_hash = Buf::new();
        client
            .engine
            .transcript_hash(hash_alg, &mut transcript_hash);

        let expected_verify_data = {
            let server_hs_secret = client
                .server_hs_traffic_secret
                .as_ref()
                .ok_or_else(|| Error::CryptoError("No server handshake secret".to_string()))?;

            let provider = client.engine.config().crypto_provider();

            let ks = crate::crypto::tls13_key_schedule::KeySchedule::new(
                provider.hkdf_provider,
                hash_alg,
            )
            .map_err(Error::CryptoError)?;

            ks.derive_finished(server_hs_secret, &transcript_hash, provider.hmac_provider)
                .map_err(Error::CryptoError)?
        };

        let maybe = client
            .engine
            .next_handshake(MessageType::Finished, &mut client.defragment_buffer)?;

        let Some(handshake) = maybe else {
            return Ok(self);
        };

        let Body::Finished(finished) = &handshake.body else {
            unreachable!()
        };

        let received_verify_data = &client.defragment_buffer[finished.verify_data_range.clone()];

        // Verify server Finished using HMAC comparison
        use subtle::ConstantTimeEq;
        let is_eq: bool = received_verify_data.ct_eq(&expected_verify_data[..]).into();
        if !is_eq {
            return Err(Error::SecurityError(
                "Server Finished verification failed".to_string(),
            ));
        }

        debug!(
            "Server Finished verified successfully ({} bytes)",
            received_verify_data.len()
        );

        // Derive application keys and exporter master secret NOW
        // (transcript is at server Finished - the correct point for app secrets)
        if let Some(shared_secret) = &client.shared_secret {
            let cipher_suite = client
                .engine
                .cipher_suite()
                .ok_or_else(|| Error::CryptoError("No cipher suite".to_string()))?;
            let hash_alg = cipher_suite.hash_algorithm();

            // Get transcript hash (at server Finished)
            let mut transcript_hash = client.engine.pop_buffer();
            client
                .engine
                .transcript_hash(hash_alg, &mut transcript_hash);

            let provider = client.engine.config().crypto_provider();

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

                        // Derive send keys (client -> server)
                        let send_cipher = if let Ok((client_key, client_iv, client_sn_key)) =
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
                                    suite_impl
                                        .create_cipher(&client_key)
                                        .ok()
                                        .map(|c| (c, client_iv, client_sn_key))
                                })
                        } else {
                            None
                        };

                        // Derive receive keys (server -> client)
                        let recv_cipher = if let Ok((server_key, server_iv, server_sn_key)) =
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
                                    suite_impl
                                        .create_cipher(&server_key)
                                        .ok()
                                        .map(|c| (c, server_iv, server_sn_key))
                                })
                        } else {
                            None
                        };

                        // Derive exporter master secret
                        let exporter_secret = ks.derive_exporter_secret(&transcript_hash).ok();

                        // Now install keys (mutable borrow of engine)
                        if let Some((cipher, iv, sn_key)) = send_cipher {
                            client
                                .engine
                                .install_dtls13_send_keys_with_sn(cipher, &iv, &sn_key);
                            // Store the traffic secret for KeyUpdate derivation
                            client.engine.set_send_traffic_secret(&client_app_secret);
                            debug!("Installed DTLS 1.3 send keys with sn_key (epoch 3)");
                        }
                        if let Some((cipher, iv, sn_key)) = recv_cipher {
                            client
                                .engine
                                .install_dtls13_recv_keys_with_sn(cipher, &iv, &sn_key);
                            // Store the traffic secret for KeyUpdate derivation
                            client.engine.set_recv_traffic_secret(&server_app_secret);
                            debug!("Installed DTLS 1.3 receive keys with sn_key (epoch 3)");

                            // Process any deferred packet data now that epoch 3 keys are installed
                            // This handles piggybacked app data from server's Finished flight
                            if client.engine.has_deferred_packet() {
                                client.engine.process_deferred_packet()?;
                            }
                        }
                        if let Some(secret) = exporter_secret {
                            client
                                .engine
                                .crypto_context_mut()
                                .set_exporter_master_secret(secret);
                            debug!("Derived TLS 1.3 exporter master secret");
                        }
                    }
                }
            }
            client.engine.push_buffer(transcript_hash);
        }

        // Send client flight
        if client.certificate_requested {
            Ok(State::SendCertificate)
        } else {
            Ok(State::SendFinished)
        }
    }

    fn send_certificate(self, client: &mut Client13) -> Result<Self, Error> {
        debug!("Sending client Certificate");

        client.engine.flight_begin(5);

        client
            .engine
            .create_handshake_dtls13(MessageType::Certificate, |body, engine| {
                // TLS 1.3 Certificate format
                // Empty context
                body.push(0);
                // Certificate chain in TLS 1.3 format
                engine.crypto_context().serialize_certificate_tls13(body);
                Ok(())
            })?;

        Ok(State::SendCertificateVerify)
    }

    fn send_certificate_verify(self, client: &mut Client13) -> Result<Self, Error> {
        debug!("Sending client CertificateVerify");

        let hash_alg = client
            .engine
            .crypto_context()
            .private_key_default_hash_algorithm();
        let sig_alg = client.engine.crypto_context().signature_algorithm();
        let algorithm = SignatureAndHashAlgorithm::new(hash_alg, sig_alg);

        // Build signed data: 64 spaces + context + 0x00 + transcript hash
        let cipher_suite = client
            .engine
            .cipher_suite()
            .ok_or_else(|| Error::CryptoError("No cipher suite".to_string()))?;
        let suite_hash = cipher_suite.hash_algorithm();

        let mut transcript_hash = Buf::new();
        client
            .engine
            .transcript_hash(suite_hash, &mut transcript_hash);

        let mut signed_data = Buf::new();
        signed_data.extend_from_slice(&[0x20u8; 64]);
        signed_data.extend_from_slice(b"TLS 1.3, client CertificateVerify");
        signed_data.push(0x00);
        signed_data.extend_from_slice(&transcript_hash);

        let mut signature = client.engine.pop_buffer();
        client
            .engine
            .crypto_context
            .sign_data(&signed_data, hash_alg, &mut signature)
            .map_err(|e| Error::CryptoError(format!("Failed to sign: {}", e)))?;

        client.engine.create_handshake_dtls13(
            MessageType::CertificateVerify,
            |body, _engine| {
                body.extend_from_slice(&algorithm.as_u16().to_be_bytes());
                body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
                body.extend_from_slice(&signature);
                Ok(())
            },
        )?;

        client.engine.push_buffer(signature);

        Ok(State::SendFinished)
    }

    fn send_finished(self, client: &mut Client13) -> Result<Self, Error> {
        debug!("Sending client Finished");

        if !client.certificate_requested {
            client.engine.flight_begin(5);
        }

        // Compute verify_data using TLS 1.3 key schedule
        let verify_data = {
            let cipher_suite = client
                .engine
                .cipher_suite()
                .ok_or_else(|| Error::CryptoError("No cipher suite".to_string()))?;
            let hash_alg = cipher_suite.hash_algorithm();
            let client_hs_secret = client
                .client_hs_traffic_secret
                .as_ref()
                .ok_or_else(|| Error::CryptoError("No client handshake secret".to_string()))?;

            // Get transcript hash up to this point (before Finished)
            let mut transcript_hash = client.engine.pop_buffer();
            client
                .engine
                .transcript_hash(hash_alg, &mut transcript_hash);

            let provider = client.engine.config().crypto_provider();

            // Create key schedule for derive_finished
            let ks = crate::crypto::tls13_key_schedule::KeySchedule::new(
                provider.hkdf_provider,
                hash_alg,
            )
            .map_err(Error::CryptoError)?;

            let verify = ks
                .derive_finished(client_hs_secret, &transcript_hash, provider.hmac_provider)
                .map_err(Error::CryptoError)?;

            client.engine.push_buffer(transcript_hash);
            verify
        };

        client
            .engine
            .create_handshake_dtls13(MessageType::Finished, |body, _engine| {
                body.extend_from_slice(&verify_data);
                Ok(())
            })?;

        // Piggyback queued application data with the Finished message
        // This saves a round-trip by including app data in the same flight
        if !client.queued_data.is_empty() && client.engine.has_dtls13_send_keys() {
            debug!(
                "Piggybacking {} queued application data with Finished",
                client.queued_data.len()
            );
            let max_fragment = client.engine.max_dtls13_app_data_fragment_size();
            for data in client.queued_data.drain(..) {
                for chunk in data.chunks(max_fragment) {
                    client
                        .engine
                        .create_record_dtls13(ContentType::ApplicationData, |body| {
                            body.extend_from_slice(chunk);
                        })?;
                }
            }
        }

        // NOTE: We don't stop retransmission timers here because the server needs to
        // receive our Finished. The timers will be stopped when we receive something
        // from the server (like application data or ACK) using the new epoch 3 keys.
        // For now, we rely on the flight timeout to eventually resend if needed.

        // Application keys were already derived in await_finished (at correct transcript point)

        // Emit connected event
        client.local_events.push_back(LocalEvent::Connected);

        // Extract SRTP keying material if negotiated (using TLS 1.3 exporter)
        if let Some(profile) = client.negotiated_srtp_profile {
            let cipher_suite = client
                .engine
                .cipher_suite()
                .ok_or_else(|| Error::CryptoError("No cipher suite".to_string()))?;
            let suite_hash = cipher_suite.hash_algorithm();
            match client
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
                    client
                        .local_events
                        .push_back(LocalEvent::KeyingMaterial(keying_material, profile));
                }
                Err(e) => {
                    warn!("Failed to extract SRTP keying material: {}", e);
                }
            }
        }

        client.engine.release_application_data();

        Ok(State::Connected)
    }

    fn connected(self, client: &mut Client13) -> Result<Self, Error> {
        // Process any incoming post-handshake messages (ACK, KeyUpdate)
        client.engine.process_incoming_post_handshake()?;

        // Send any queued application data using DTLS 1.3 record encryption
        if !client.queued_data.is_empty() {
            debug!(
                "Sending {} queued application data",
                client.queued_data.len()
            );
            for data in client.queued_data.drain(..) {
                if client.engine.has_dtls13_send_keys() {
                    // Use DTLS 1.3 record encryption (epoch 3)
                    client
                        .engine
                        .create_record_dtls13(ContentType::ApplicationData, |body| {
                            body.extend_from_slice(&data);
                        })?;
                } else {
                    // Fallback to DTLS 1.2 style (shouldn't happen in 1.3 mode)
                    client.engine.create_record(
                        ContentType::ApplicationData,
                        3,
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

fn is_hello_retry_request(random: &Random) -> bool {
    // Serialize random to bytes for comparison
    let mut buf = Buf::new();
    random.serialize(&mut buf);
    buf.as_ref() == HELLO_RETRY_REQUEST_RANDOM
}

/// Extract HelloRetryRequest data from extensions while we still have the buffer
fn extract_hrr_data(
    extensions: &Option<ArrayVec<Extension, 32>>,
    buf: &Buf,
) -> Result<(Option<NamedGroup>, Option<Buf>), Error> {
    let Some(ext_list) = extensions else {
        return Err(Error::SecurityError("HRR missing extensions".to_string()));
    };

    let mut selected_group: Option<NamedGroup> = None;
    let mut cookie_data: Option<Buf> = None;

    for ext in ext_list {
        match ext.extension_type {
            ExtensionType::KeyShare => {
                // In HRR, key_share contains just the selected group
                let ext_data = ext.extension_data(buf);
                let (_, ks) = KeyShareHelloRetryRequest::parse(ext_data).map_err(|_| {
                    Error::SecurityError("Failed to parse HRR key_share".to_string())
                })?;
                selected_group = Some(ks.selected_group);
            }
            ExtensionType::Cookie => {
                let ext_data = ext.extension_data(buf);
                let (_, cookie) = CookieExtension::parse(ext_data, 0)
                    .map_err(|_| Error::SecurityError("Failed to parse HRR cookie".to_string()))?;
                let cookie_bytes = cookie.cookie(ext_data);
                cookie_data = Some(Buf::from_slice(cookie_bytes));
            }
            _ => {}
        }
    }

    Ok((selected_group, cookie_data))
}

fn handle_hello_retry_request(
    client: &mut Client13,
    selected_group: Option<NamedGroup>,
    cookie_data: Option<Buf>,
    hrr_transcript_bytes: &[u8],
) -> Result<State, Error> {
    debug!("Received HelloRetryRequest");

    // Store cookie for retry
    if let Some(cookie) = cookie_data {
        client.cookie = Some(cookie);
    }

    // If server requested a different group, we need to regenerate key share
    if let Some(group) = selected_group {
        if !client.offered_key_shares.contains(&group) {
            // Server asked for a group we support but didn't offer
            // Reinitialize key exchange with the requested group
            client
                .engine
                .crypto_context_mut()
                .init_ecdh_server(group, &mut Buf::new())
                .map_err(|e| Error::CryptoError(format!("HRR key exchange init failed: {}", e)))?;
            client.offered_key_shares.clear();
            client.offered_key_shares.push(group);
        }
    }

    // The transcript currently contains: ClientHello1 || HelloRetryRequest
    // We need to transform it to: message_hash(ClientHello1) || HelloRetryRequest
    //
    // Per RFC 8446, the transcript after HRR is computed as:
    //   Transcript-Hash(ClientHello1, HelloRetryRequest, ClientHello2) =
    //     Hash(message_hash || HelloRetryRequest || ClientHello2)
    //
    // Where message_hash = Hash(ClientHello1) formatted as a fake handshake message.
    //
    // First, remove the HRR from transcript to get just ClientHello1
    let hrr_len = hrr_transcript_bytes.len();
    let transcript_len = client.engine.transcript().len();
    client.engine.transcript_truncate(transcript_len - hrr_len);

    // Now transcript = ClientHello1, replace with message_hash
    client
        .engine
        .transcript_replace_for_hrr(crate::message::HashAlgorithm::SHA256);

    // Now re-add the HRR to transcript
    client.engine.transcript_extend(hrr_transcript_bytes);

    // Resend ClientHello with cookie
    Ok(State::SendClientHello)
}

fn handshake_create_client_hello_13(
    body: &mut Buf,
    engine: &mut Engine,
    random: Random,
    session_id: SessionId,
    extension_data: &mut Buf,
    offered_key_shares: &mut ArrayVec<NamedGroup, 4>,
    cookie: Option<&[u8]>,
) -> Result<(), Error> {
    // Legacy version is DTLS 1.2 (0xFEFD) per RFC 9147
    let legacy_version = ProtocolVersion::DTLS1_2;

    // Get TLS 1.3 cipher suites from provider
    let provider = engine.crypto_context().provider();
    let cipher_suites: ArrayVec<CipherSuite, 32> = provider
        .supported_cipher_suites()
        .map(|cs| cs.suite())
        .filter(|suite| suite.is_tls13())
        .take(32)
        .collect();

    debug!(
        "Sending DTLS 1.3 ClientHello: offering {} TLS 1.3 cipher suites",
        cipher_suites.len()
    );

    // Compression: only null
    let mut compression_methods = ArrayVec::new();
    compression_methods.push(CompressionMethod::Null);

    // Build extensions in extension_data buffer
    extension_data.clear();

    // 1. supported_versions extension (required for TLS 1.3)
    let sv = SupportedVersionsClientHello::new_dtls13(true); // Include DTLS 1.2 for fallback
    let sv_start = extension_data.len();
    sv.serialize(extension_data);
    let sv_end = extension_data.len();

    // 2. supported_groups extension - use from_provider to get properly typed groups
    let sg = SupportedGroupsExtension::from_provider(provider);
    let supported_groups = sg.groups.clone();
    let sg_start = extension_data.len();
    sg.serialize(extension_data);
    let sg_end = extension_data.len();

    // 3. key_share extension - generate key shares for preferred groups
    offered_key_shares.clear();

    // Store public keys temporarily for serializing key_share extension
    let mut key_share_data: ArrayVec<(NamedGroup, Buf), 4> = ArrayVec::new();

    // Generate key share for first supported group
    if let Some(first_group) = supported_groups.first() {
        // Initialize key exchange
        let mut kx_buf = engine.pop_buffer();
        engine
            .crypto_context_mut()
            .init_ecdh_server(*first_group, &mut kx_buf)
            .map_err(|e| Error::CryptoError(format!("Key exchange init failed: {}", e)))?;

        // Get public key
        let public_key = engine
            .crypto_context_mut()
            .maybe_init_key_exchange()
            .map_err(|e| Error::CryptoError(format!("Key exchange failed: {}", e)))?;

        key_share_data.push((*first_group, Buf::from_slice(public_key)));
        offered_key_shares.push(*first_group);

        engine.push_buffer(kx_buf);
    }

    // Serialize key_share extension directly
    let ks_start = extension_data.len();
    // Calculate total length: sum of (2 + 2 + key_len) for each entry
    let mut ks_total_len: u16 = 0;
    for (_, key_buf) in &key_share_data {
        ks_total_len += 4 + key_buf.len() as u16; // 2 for group, 2 for length, + key bytes
    }
    extension_data.extend_from_slice(&ks_total_len.to_be_bytes());
    for (group, key_buf) in &key_share_data {
        extension_data.extend_from_slice(&group.as_u16().to_be_bytes());
        extension_data.extend_from_slice(&(key_buf.len() as u16).to_be_bytes());
        extension_data.extend_from_slice(key_buf);
    }
    let ks_end = extension_data.len();

    // 4. signature_algorithms extension
    let sig_algs = SignatureAlgorithmsExtension::default();
    let sa_start = extension_data.len();
    sig_algs.serialize(extension_data);
    let sa_end = extension_data.len();

    // 5. EC point formats extension (required by some implementations)
    let ec_point_formats = ECPointFormatsExtension::default();
    let epf_start = extension_data.len();
    ec_point_formats.serialize(extension_data);
    let epf_end = extension_data.len();

    // 6. use_srtp extension (for WebRTC)
    let use_srtp = UseSrtpExtension::default();
    let srtp_start = extension_data.len();
    use_srtp.serialize(extension_data);
    let srtp_end = extension_data.len();

    // 7. cookie extension (if retrying after HRR)
    let cookie_range = if let Some(cookie_bytes) = cookie {
        let start = extension_data.len();
        CookieExtension::serialize_from_bytes(cookie_bytes, extension_data);
        Some(start..extension_data.len())
    } else {
        None
    };

    // Build extensions list (max 16 per ClientHello)
    let mut extensions: ArrayVec<Extension, 16> = ArrayVec::new();

    extensions.push(Extension {
        extension_type: ExtensionType::SupportedVersions,
        extension_data_range: sv_start..sv_end,
    });
    extensions.push(Extension {
        extension_type: ExtensionType::SupportedGroups,
        extension_data_range: sg_start..sg_end,
    });
    extensions.push(Extension {
        extension_type: ExtensionType::KeyShare,
        extension_data_range: ks_start..ks_end,
    });
    extensions.push(Extension {
        extension_type: ExtensionType::SignatureAlgorithms,
        extension_data_range: sa_start..sa_end,
    });
    extensions.push(Extension {
        extension_type: ExtensionType::EcPointFormats,
        extension_data_range: epf_start..epf_end,
    });
    extensions.push(Extension {
        extension_type: ExtensionType::UseSrtp,
        extension_data_range: srtp_start..srtp_end,
    });

    if let Some(range) = cookie_range {
        extensions.push(Extension {
            extension_type: ExtensionType::Cookie,
            extension_data_range: range,
        });
    }

    // Build ClientHello
    let client_hello = ClientHello {
        client_version: legacy_version,
        random,
        session_id,
        cookie: crate::message::Cookie::empty(),
        cipher_suites,
        compression_methods,
        extensions,
    };

    client_hello.serialize(extension_data, body);
    Ok(())
}

impl std::fmt::Debug for Client13 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client13")
            .field("state", &self.state)
            .finish()
    }
}
