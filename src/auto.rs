/// Version detection and hybrid ClientHello for auto-sensing DTLS endpoints.
///
/// `server_hello_version` does lightweight parsing of the first record in a
/// datagram. It looks for a `HelloVerifyRequest` or a `ServerHello` with the
/// `supported_versions` extension to decide between DTLS 1.2 and 1.3 for the
/// client auto-sense path.
///
/// [`HybridClientHello`] constructs a ClientHello compatible with both
/// DTLS 1.2 and 1.3 servers: it offers both versions cipher suites and
/// includes `supported_versions` with both versions. Once the server
/// responds, the caller inspects the reply with `server_hello_version`
/// and forks into the appropriate handshake path.
///
/// Server-side auto-sense does not use lightweight detection. Instead,
/// it starts a DTLS 1.3 server which handles fragment reassembly natively
/// and falls back to DTLS 1.2 via [`Error::Dtls12Fallback`] if the
/// reassembled ClientHello does not offer DTLS 1.3.
use std::sync::Arc;
use std::time::Instant;

use crate::buffer::Buf;
use crate::client_hello_builder::{ClientHelloBuilder, Offer};
use crate::crypto::ActiveKeyExchange;
use crate::dtls13::message::Random;
use crate::timer::HandshakeTimers;
use crate::{Config, CryptoError, DtlsCertificate, Error, Output, SeededRng, TimeoutError};
/// A self-contained hybrid ClientHello compatible with both DTLS 1.2 and 1.3.
///
/// Holds the serialized bytes and crypto state needed to fork into either
/// version's handshake once the server responds:
///
/// - **DTLS 1.3 fork**: transcript bytes and ECDHE private key are injected
///   into a `Client13` via `new_from_hybrid`.
/// - **DTLS 1.2 fork**: the random and transcript are injected into a `Client12`.
///   Both forks retain the hybrid offer for cookie retries.
///
/// These buffers are temporary probe state created before an engine exists.
/// The selected engine copies the needed bytes into its own buffers; probe
/// buffers are dropped and never returned to the engine's pool.
pub(crate) struct HybridClientHello {
    /// Client random used in the ClientHello.
    pub random: Random,

    /// ECDHE private key from the key_share extension.
    pub active_key_exchange: Box<dyn ActiveKeyExchange>,

    /// TLS-style transcript bytes: msg_type(1) + length(3) + CH body.
    /// Does not include DTLS message_seq/fragment_offset/fragment_length.
    pub transcript_bytes: Buf,

    /// DTLS handshake fragment: msg_type(1) + length(3) + message_seq(2)
    ///     + fragment_offset(3) + fragment_length(3) + CH body.
    ///     Used by [`wire_packet`](Self::wire_packet) to build the on-wire record
    ///     and by `Client12::new_from_hybrid` for transcript injection.
    pub handshake_fragment: Buf,
}

impl HybridClientHello {
    /// Build a hybrid ClientHello from the given configuration.
    ///
    /// Serializes the ClientHello body with both DTLS 1.2 and 1.3 cipher
    /// suites, `supported_versions` offering both versions, and 1.2-compat
    /// extensions (`ec_point_formats`, `extended_master_secret`,
    /// `renegotiation_info`).
    pub fn new(config: &Arc<Config>) -> Result<Self, Error> {
        let mut rng = SeededRng::new(config.rng_seed());
        let random = Random::new(&mut rng);

        // Start ECDHE key exchange with the first supported group (filtered)
        let group = config.kx_groups().next().ok_or(Error::CryptoError(
            CryptoError::NoSupportedKeyExchangeGroups,
        ))?;
        let kx_buf = Buf::new();
        let key_exchange = group.start_exchange(kx_buf).map_err(Error::CryptoError)?;

        let mut ch_body = Buf::new();
        ClientHelloBuilder::new(config, random, Offer::Hybrid)
            .key_share(group.name(), key_exchange.pub_key())
            .serialize(&mut ch_body);

        // ---- Build transcript bytes: msg_type(1) + length(3) + body ----
        let mut transcript_bytes = Buf::new();
        transcript_bytes.push(0x01); // ClientHello msg_type
        let body_len = ch_body.len() as u32;
        transcript_bytes.extend_from_slice(&body_len.to_be_bytes()[1..]);
        transcript_bytes.extend_from_slice(&ch_body);

        // ---- Build DTLS handshake fragment ----
        // msg_type(1) + length(3) + message_seq(2) + frag_offset(3) + frag_len(3) + body
        let mut handshake_fragment = Buf::new();
        handshake_fragment.push(0x01); // msg_type = ClientHello
        handshake_fragment.extend_from_slice(&body_len.to_be_bytes()[1..]); // length (3 bytes)
        handshake_fragment.extend_from_slice(&0u16.to_be_bytes()); // message_seq = 0
        handshake_fragment.extend_from_slice(&0u32.to_be_bytes()[1..]); // fragment_offset (3 bytes)
        handshake_fragment.extend_from_slice(&body_len.to_be_bytes()[1..]); // fragment_length (3 bytes)
        handshake_fragment.extend_from_slice(&ch_body);

        Ok(HybridClientHello {
            random,
            active_key_exchange: key_exchange,
            transcript_bytes,
            handshake_fragment,
        })
    }

    /// Build the full wire-format DTLSPlaintext record for the hybrid CH.
    pub fn wire_packet(&self) -> Buf {
        let mut pkt = Buf::new();
        // DTLSPlaintext header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2)
        pkt.push(0x16); // Handshake
        pkt.extend_from_slice(&0xFEFDu16.to_be_bytes()); // DTLS 1.2
        pkt.extend_from_slice(&0u16.to_be_bytes()); // epoch 0
        pkt.extend_from_slice(&[0u8; 6]); // sequence 0
        pkt.extend_from_slice(&(self.handshake_fragment.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&self.handshake_fragment);
        pkt
    }
}

/// Auto-sense client that sends a hybrid ClientHello and waits for the server's response
/// to determine the DTLS version.
pub(crate) struct ClientPending {
    hybrid: HybridClientHello,
    config: Arc<Config>,
    certificate: DtlsCertificate,
    /// Pre-built wire packet (record header + handshake fragment).
    wire_packet: Buf,
    /// Whether the wire_packet hasn't been polled yet.
    needs_send: bool,
    /// Last time handle_timeout was called.
    last_now: Instant,
    timers: HandshakeTimers,
    rng: SeededRng,
    closed: bool,
}

impl ClientPending {
    pub fn new(
        config: Arc<Config>,
        certificate: DtlsCertificate,
        now: Instant,
    ) -> Result<Self, Error> {
        let hybrid = HybridClientHello::new(&config)?;
        let wire_packet = hybrid.wire_packet();
        let mut rng = SeededRng::new(config.rng_seed());
        let mut timers = HandshakeTimers::new(&config, &mut rng);
        timers.begin_flight(&mut rng);
        Ok(ClientPending {
            hybrid,
            config,
            certificate,
            wire_packet,
            needs_send: true,
            last_now: now,
            timers,
            rng,
            closed: false,
        })
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.last_now = now;
        if self.closed {
            return Ok(());
        }
        let resend = self
            .timers
            .handle_timeout(now, &mut self.rng)
            .map_err(|error| {
                Error::Timeout(match error {
                    TimeoutError::Handshake => TimeoutError::HybridClientHello,
                    other => other,
                })
            })?;
        if resend {
            self.needs_send = true;
        }
        Ok(())
    }

    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Output<'a> {
        if self.needs_send {
            let len = self.wire_packet.len();
            if buf.len() < len {
                // Keep needs_send armed so the packet is emitted on retry.
                return Output::BufferTooSmall { needed: len };
            }
            self.needs_send = false;
            buf[..len].copy_from_slice(&self.wire_packet);
            self.timers.start_handshake(self.last_now);
            self.timers.flight_sent(self.last_now);
            return Output::Packet(&buf[..len]);
        }
        let next = self.timers.poll_timeout(self.last_now);
        Output::Timeout(next)
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn close(&mut self) -> Result<(), Error> {
        self.closed = true;
        self.needs_send = false;
        self.timers.stop();
        Ok(())
    }

    pub fn into_parts(
        self,
    ) -> (
        HybridClientHello,
        Arc<Config>,
        DtlsCertificate,
        Instant,
        HandshakeTimers,
    ) {
        // Bind the fields first: CodeQL treats a tuple holding `self.certificate`
        // directly as sensitive data and taints every element, including `config`.
        let Self {
            hybrid,
            config,
            certificate,
            last_now,
            timers,
            ..
        } = self;
        (hybrid, config, certificate, last_now, timers)
    }
}

// =========================================================================
// Version detection helpers
// =========================================================================

/// Detected DTLS version from packet inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectedVersion {
    Dtls12,
    Dtls13,
    Unknown,
}

/// Detect DTLS version from a server response (ServerHello or HelloVerifyRequest).
///
/// - HelloVerifyRequest (msg_type 3) → `Dtls12`
/// - ServerHello with `supported_versions` containing DTLS 1.3 → `Dtls13`
/// - ServerHello without `supported_versions` → `Dtls12`
/// - Anything else → `Unknown`
pub(crate) fn server_hello_version(packet: &[u8]) -> DetectedVersion {
    server_hello_version_inner(packet).unwrap_or(DetectedVersion::Unknown)
}

fn server_hello_version_inner(packet: &[u8]) -> Option<DetectedVersion> {
    // Record header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13
    if packet.len() < 13 {
        return None;
    }

    // content_type must be 0x16 (Handshake)
    if packet[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
    let record_body = packet.get(13..13 + record_len)?;

    // Handshake header: msg_type(1) + length(3) + message_seq(2) +
    //   fragment_offset(3) + fragment_length(3) = 12
    if record_body.len() < 12 {
        return None;
    }

    let msg_type = record_body[0];

    // HelloVerifyRequest → DTLS 1.2
    if msg_type == 3 {
        return Some(DetectedVersion::Dtls12);
    }

    // ServerHello → inspect supported_versions
    if msg_type != 2 {
        return None;
    }

    let fragment_len = ((record_body[9] as usize) << 16)
        | ((record_body[10] as usize) << 8)
        | (record_body[11] as usize);
    let body = record_body.get(12..12 + fragment_len)?;

    // ServerHello body:
    //   server_version(2) + random(32) + session_id_len(1) + session_id + ...
    if body.len() < 35 {
        return Some(DetectedVersion::Dtls12);
    }
    let mut pos = 34; // past version(2) + random(32)

    // session_id: 1-byte length + data
    let sid_len = *body.get(pos)? as usize;
    pos += 1 + sid_len;

    // cipher_suite: 2 bytes
    pos += 2;

    // compression_method: 1 byte
    pos += 1;

    // extensions: 2-byte total length (optional)
    if pos + 2 > body.len() {
        // No extensions → DTLS 1.2
        return Some(DetectedVersion::Dtls12);
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > body.len() {
        return Some(DetectedVersion::Dtls12);
    }

    // Walk extensions looking for supported_versions (0x002B)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x002B {
            // ServerHello supported_versions: just 2 bytes (selected_version)
            if ext_len >= 2 {
                let version = u16::from_be_bytes([body[pos], body[pos + 1]]);
                if version == 0xFEFC {
                    return Some(DetectedVersion::Dtls13);
                }
            }
            return Some(DetectedVersion::Dtls12);
        }

        pos += ext_len;
    }

    // No supported_versions → DTLS 1.2
    Some(DetectedVersion::Dtls12)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PskResolver;
    use crate::dtls12::message::Dtls12CipherSuite;

    fn offered_cipher_suites(hybrid: &HybridClientHello) -> Vec<u16> {
        let body = &hybrid.handshake_fragment[12..];
        let mut offset = 2 + 32; // legacy_version + random

        let session_id_len = body[offset] as usize;
        offset += 1 + session_id_len;

        let cookie_len = body[offset] as usize;
        offset += 1 + cookie_len;

        let suites_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;

        body[offset..offset + suites_len]
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect()
    }

    struct DummyResolver;

    impl PskResolver for DummyResolver {
        fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
            Some(b"0123456789abcdef".to_vec())
        }
    }

    #[test]
    fn hello_verify_request_is_dtls12() {
        // Minimal HelloVerifyRequest packet
        let mut pkt = Vec::new();
        // Record header: content_type=22, version=DTLS1.2, epoch=0, seq=0, length=TBD
        pkt.push(0x16); // handshake
        pkt.extend_from_slice(&[0xFE, 0xFD]); // DTLS 1.2
        pkt.extend_from_slice(&[0x00, 0x00]); // epoch 0
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // seq 0
        // length placeholder (will fill)
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=3 (HVR), length=5, msg_seq=0, frag_off=0, frag_len=5
        pkt.push(3); // HelloVerifyRequest
        pkt.extend_from_slice(&[0x00, 0x00, 0x05]); // length
        pkt.extend_from_slice(&[0x00, 0x00]); // message_seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
        pkt.extend_from_slice(&[0x00, 0x00, 0x05]); // fragment_length

        // HVR body: server_version(2) + cookie_len(1) + cookie(2)
        pkt.extend_from_slice(&[0xFE, 0xFD]); // server_version
        pkt.push(0x02); // cookie length
        pkt.extend_from_slice(&[0xAA, 0xBB]); // cookie

        // Fill record length
        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls12);
    }

    #[test]
    fn server_hello_with_supported_versions_is_dtls13() {
        let mut pkt = Vec::new();
        // Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=2 (ServerHello)
        pkt.push(2);
        let hs_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder
        pkt.extend_from_slice(&[0x00, 0x00]); // message_seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_offset
        let frag_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // fragment_length placeholder

        let body_start = pkt.len();

        // ServerHello body: version(2) + random(32) + session_id
        pkt.extend_from_slice(&[0xFE, 0xFD]); // legacy version DTLS 1.2
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(0x00); // session_id length = 0
        pkt.extend_from_slice(&[0x13, 0x01]); // cipher_suite AES_128_GCM_SHA256
        pkt.push(0x00); // compression_method = null

        // Extensions
        let ext_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]); // extensions length placeholder

        let ext_start = pkt.len();

        // supported_versions extension: type=0x002B, data=0xFEFC (DTLS 1.3)
        pkt.extend_from_slice(&[0x00, 0x2B]); // type
        pkt.extend_from_slice(&[0x00, 0x02]); // length
        pkt.extend_from_slice(&[0xFE, 0xFC]); // DTLS 1.3

        let ext_total = pkt.len() - ext_start;
        pkt[ext_len_pos] = (ext_total >> 8) as u8;
        pkt[ext_len_pos + 1] = ext_total as u8;

        let body_len = pkt.len() - body_start;
        // Fill handshake length and fragment length
        pkt[hs_len_pos] = 0;
        pkt[hs_len_pos + 1] = (body_len >> 8) as u8;
        pkt[hs_len_pos + 2] = body_len as u8;
        pkt[frag_len_pos] = 0;
        pkt[frag_len_pos + 1] = (body_len >> 8) as u8;
        pkt[frag_len_pos + 2] = body_len as u8;

        // Fill record length
        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls13);
    }

    #[test]
    fn server_hello_without_supported_versions_is_dtls12() {
        let mut pkt = Vec::new();
        // Record header
        pkt.push(0x16);
        pkt.extend_from_slice(&[0xFE, 0xFD]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00]);

        // Handshake header: msg_type=2 (ServerHello)
        pkt.push(2);
        let hs_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        let frag_len_pos = pkt.len();
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);

        let body_start = pkt.len();

        // ServerHello body without extensions
        pkt.extend_from_slice(&[0xFE, 0xFD]); // version
        pkt.extend_from_slice(&[0u8; 32]); // random
        pkt.push(0x00); // session_id length
        pkt.extend_from_slice(&[0xC0, 0x2B]); // cipher_suite (1.2 ECDHE)
        pkt.push(0x00); // compression

        let body_len = pkt.len() - body_start;
        pkt[hs_len_pos] = 0;
        pkt[hs_len_pos + 1] = (body_len >> 8) as u8;
        pkt[hs_len_pos + 2] = body_len as u8;
        pkt[frag_len_pos] = 0;
        pkt[frag_len_pos + 1] = (body_len >> 8) as u8;
        pkt[frag_len_pos + 2] = body_len as u8;

        let record_len = (pkt.len() - 13) as u16;
        pkt[len_pos] = (record_len >> 8) as u8;
        pkt[len_pos + 1] = record_len as u8;

        assert_eq!(server_hello_version(&pkt), DetectedVersion::Dtls12);
    }

    #[test]
    fn garbage_packet_is_unknown() {
        assert_eq!(
            server_hello_version(&[0xFF, 0x00]),
            DetectedVersion::Unknown
        );
        assert_eq!(server_hello_version(&[]), DetectedVersion::Unknown);
    }

    #[test]
    fn too_short_is_unknown() {
        // Non-handshake content type
        let pkt = [
            0x17, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
        ];
        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }

    #[test]
    fn hybrid_client_hello_excludes_psk_dtls12_suites() {
        let config = Arc::new(
            Config::builder()
                .with_psk_client(b"identity".to_vec(), Arc::new(DummyResolver))
                .build()
                .expect("config with PSK should build"),
        );

        assert!(
            config.dtls12_cipher_suites().any(|cs| cs.suite().is_psk()),
            "precondition: PSK-enabled config should expose a PSK DTLS 1.2 suite"
        );

        let hybrid = HybridClientHello::new(&config).expect("hybrid ClientHello should build");
        let offered = offered_cipher_suites(&hybrid);

        assert!(
            !offered.contains(&Dtls12CipherSuite::PSK_AES128_CCM_8.as_u16()),
            "auto client must not advertise PSK DTLS 1.2 suites it cannot use after fallback"
        );
    }
}
