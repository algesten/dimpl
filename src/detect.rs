/// Version detection and hybrid ClientHello for auto-sensing DTLS endpoints.
///
/// Both `client_hello_version` and `server_hello_version` do lightweight
/// parsing of the first record in a datagram, looking for the
/// `supported_versions` extension to decide between DTLS 1.2 and 1.3.
///
/// [`HybridClientHello`] constructs a ClientHello compatible with both
/// DTLS 1.2 and 1.3 servers: it offers both version's cipher suites and
/// includes `supported_versions` with both versions. Once the server
/// responds, the caller inspects the reply with `server_hello_version`
/// and forks into the appropriate handshake path.

use std::sync::Arc;

use arrayvec::ArrayVec;

use crate::buffer::Buf;
use crate::crypto::ActiveKeyExchange;
use crate::dtls13::message::{
    KeyShareClientHello, KeyShareEntry, Random, SignatureAlgorithmsExtension,
    SupportedGroupsExtension, UseSrtpExtension,
};
use crate::types::NamedGroup;
use crate::{Config, Error, SeededRng};

/// Detected DTLS version from packet inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectedVersion {
    Dtls12,
    Dtls13,
    Unknown,
}

/// Detect DTLS version from a ClientHello packet.
///
/// Returns `Dtls13` if the `supported_versions` extension contains
/// DTLS 1.3 (0xFEFC), otherwise `Dtls12`.
pub(crate) fn client_hello_version(packet: &[u8]) -> DetectedVersion {
    match client_hello_version_inner(packet) {
        Some(true) => DetectedVersion::Dtls13,
        _ => DetectedVersion::Dtls12,
    }
}

fn client_hello_version_inner(packet: &[u8]) -> Option<bool> {
    // Record header: content_type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13
    if packet.len() < 13 {
        return Some(false);
    }

    // content_type must be 0x16 (Handshake)
    if packet[0] != 0x16 {
        return Some(false);
    }

    let record_len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
    let record_body = packet.get(13..13 + record_len)?;

    // Handshake header: msg_type(1) + length(3) + message_seq(2) +
    //   fragment_offset(3) + fragment_length(3) = 12
    if record_body.len() < 12 {
        return Some(false);
    }

    // msg_type must be 1 (ClientHello)
    if record_body[0] != 1 {
        return Some(false);
    }

    let fragment_len = ((record_body[9] as usize) << 16)
        | ((record_body[10] as usize) << 8)
        | (record_body[11] as usize);
    let body = record_body.get(12..12 + fragment_len)?;

    // ClientHello body:
    //   client_version(2) + random(32) = 34 minimum before session_id
    if body.len() < 34 {
        return Some(false);
    }
    let mut pos = 34;

    // session_id: 1-byte length + data
    let sid_len = *body.get(pos)? as usize;
    pos += 1 + sid_len;

    // cookie: 1-byte length + data
    let cookie_len = *body.get(pos)? as usize;
    pos += 1 + cookie_len;

    // cipher_suites: 2-byte length + data
    if pos + 2 > body.len() {
        return Some(false);
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // compression_methods: 1-byte length + data
    let cm_len = *body.get(pos)? as usize;
    pos += 1 + cm_len;

    // extensions: 2-byte total length
    if pos + 2 > body.len() {
        return Some(false);
    }
    let ext_total_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > body.len() {
        return Some(false);
    }

    // Walk extensions looking for supported_versions (0x002B)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x002B {
            // supported_versions client format: 1-byte list length, then 2-byte versions
            if ext_len < 1 {
                return Some(false);
            }
            let list_len = body[pos] as usize;
            let list_start = pos + 1;
            if list_start + list_len > pos + ext_len {
                return Some(false);
            }
            let mut i = list_start;
            while i + 2 <= list_start + list_len {
                let version = u16::from_be_bytes([body[i], body[i + 1]]);
                if version == 0xFEFC {
                    return Some(true);
                }
                i += 2;
            }
            return Some(false);
        }

        pos += ext_len;
    }

    Some(false)
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

// =========================================================================
// Hybrid ClientHello
// =========================================================================

// DTLS 1.2 cipher suite values (IANA)
const ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;
const ECDHE_ECDSA_AES256_GCM_SHA384: u16 = 0xC02C;

// DTLS 1.3 cipher suite values (IANA)
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;

// Extension type constants
const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const EXT_EC_POINT_FORMATS: u16 = 0x000B;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
const EXT_USE_SRTP: u16 = 0x000E;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;

/// A self-contained hybrid ClientHello compatible with both DTLS 1.2 and 1.3.
///
/// Holds the serialized bytes and crypto state needed to fork into either
/// version's handshake once the server responds:
///
/// - **DTLS 1.3 fork**: transcript bytes and ECDHE private key are injected
///   into a `Client13` via `new_from_hybrid`.
/// - **DTLS 1.2 fork**: all state is discarded (HelloVerifyRequest clears
///   the transcript), and a fresh `Client12` is created.
pub(crate) struct HybridClientHello {
    /// Client random used in the ClientHello.
    pub random: Random,

    /// ECDHE private key from the key_share extension.
    pub active_key_exchange: Box<dyn ActiveKeyExchange>,

    /// TLS-style transcript bytes: msg_type(1) + length(3) + CH body.
    /// Does not include DTLS message_seq/fragment_offset/fragment_length.
    pub transcript_bytes: Buf,

    /// DTLS handshake fragment: msg_type(1) + length(3) + message_seq(2)
    /// + fragment_offset(3) + fragment_length(3) + CH body.
    /// Used by [`wire_packet`](Self::wire_packet) to build the on-wire record
    /// and by `Client12::new_from_hybrid` for transcript injection.
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
        let provider = config.crypto_provider();

        // Start ECDHE key exchange with the first supported group
        let group = provider
            .kx_groups
            .first()
            .ok_or_else(|| Error::CryptoError("No supported key exchange groups".into()))?;
        let kx_buf = Buf::new();
        let key_exchange = group
            .start_exchange(kx_buf)
            .map_err(|e| Error::CryptoError(format!("Failed to start key exchange: {}", e)))?;

        // ---- Build the ClientHello body ----
        let mut ch_body = Buf::new();

        // legacy_version: DTLS 1.2
        ch_body.extend_from_slice(&0xFEFDu16.to_be_bytes());

        // random
        random.serialize(&mut ch_body);

        // legacy_session_id: empty
        ch_body.push(0);

        // legacy_cookie: empty (DTLS 1.3 requires zero-length)
        ch_body.push(0);

        // cipher_suites: 1.3 suites first, then 1.2 suites
        let suites: &[u16] = &[
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            ECDHE_ECDSA_AES128_GCM_SHA256,
            ECDHE_ECDSA_AES256_GCM_SHA384,
        ];
        ch_body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for &suite in suites {
            ch_body.extend_from_slice(&suite.to_be_bytes());
        }

        // compression_methods: [null]
        ch_body.push(1);
        ch_body.push(0);

        // ---- Extensions ----
        // Build extension data into a separate buffer, then write the
        // extensions_length + extension entries into ch_body.
        let mut ext_buf = Buf::new();
        let mut ext_entries: Vec<(u16, usize, usize)> = Vec::new();

        // 1. supported_versions: [DTLS 1.3, DTLS 1.2]
        let start = ext_buf.len();
        ext_buf.push(4); // list_len = 2 versions * 2 bytes
        ext_buf.extend_from_slice(&0xFEFCu16.to_be_bytes()); // DTLS 1.3
        ext_buf.extend_from_slice(&0xFEFDu16.to_be_bytes()); // DTLS 1.2
        ext_entries.push((EXT_SUPPORTED_VERSIONS, start, ext_buf.len()));

        // 2. supported_groups
        let start = ext_buf.len();
        let groups: ArrayVec<NamedGroup, 4> =
            provider.kx_groups.iter().map(|g| g.name()).collect();
        let sg = SupportedGroupsExtension { groups };
        sg.serialize(&mut ext_buf);
        ext_entries.push((EXT_SUPPORTED_GROUPS, start, ext_buf.len()));

        // 3. key_share (ECDHE public key)
        let pub_key = key_exchange.pub_key();
        let mut key_data = Buf::new();
        let pub_key_start = key_data.len();
        key_data.extend_from_slice(pub_key);
        let pub_key_end = key_data.len();

        let start = ext_buf.len();
        let mut entries = ArrayVec::new();
        entries.push(KeyShareEntry {
            group: group.name(),
            key_exchange_range: pub_key_start..pub_key_end,
        });
        let ks = KeyShareClientHello { entries };
        ks.serialize(&key_data, &mut ext_buf);
        ext_entries.push((EXT_KEY_SHARE, start, ext_buf.len()));

        // 4. signature_algorithms
        let start = ext_buf.len();
        let sa = SignatureAlgorithmsExtension::default();
        sa.serialize(&mut ext_buf);
        ext_entries.push((EXT_SIGNATURE_ALGORITHMS, start, ext_buf.len()));

        // 5. use_srtp
        let start = ext_buf.len();
        let use_srtp = UseSrtpExtension::default();
        use_srtp.serialize(&mut ext_buf);
        ext_entries.push((EXT_USE_SRTP, start, ext_buf.len()));

        // 6. ec_point_formats (DTLS 1.2 compat: uncompressed only)
        let start = ext_buf.len();
        ext_buf.push(1); // list length
        ext_buf.push(0); // ECPointFormat::Uncompressed
        ext_entries.push((EXT_EC_POINT_FORMATS, start, ext_buf.len()));

        // 7. extended_master_secret (empty, DTLS 1.2 compat)
        ext_entries.push((EXT_EXTENDED_MASTER_SECRET, ext_buf.len(), ext_buf.len()));

        // 8. renegotiation_info (empty renegotiated_connection, DTLS 1.2 compat)
        let start = ext_buf.len();
        ext_buf.push(0); // renegotiated_connection length = 0
        ext_entries.push((EXT_RENEGOTIATION_INFO, start, ext_buf.len()));

        // 9. padding: fill to MTU
        let record_header = 13usize;
        let handshake_header = 12usize;
        let body_so_far = ch_body.len()
            + 2 // extensions_length field
            + ext_entries.iter().map(|(_, s, e)| 4 + (e - s)).sum::<usize>();
        let total_so_far = record_header + handshake_header + body_so_far;
        let deficit = config.mtu().saturating_sub(total_so_far);
        if deficit >= 4 {
            let pad_data_len = deficit - 4; // 4 = type(2) + len(2)
            let start = ext_buf.len();
            for _ in 0..pad_data_len {
                ext_buf.push(0);
            }
            ext_entries.push((EXT_PADDING, start, ext_buf.len()));
        }

        // Write extensions into ch_body
        let ext_total_len: usize = ext_entries.iter().map(|(_, s, e)| 4 + (e - s)).sum();
        ch_body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
        for &(ext_type, start, end) in &ext_entries {
            ch_body.extend_from_slice(&ext_type.to_be_bytes());
            ch_body.extend_from_slice(&((end - start) as u16).to_be_bytes());
            if end > start {
                ch_body.extend_from_slice(&ext_buf[start..end]);
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(server_hello_version(&[0xFF, 0x00]), DetectedVersion::Unknown);
        assert_eq!(server_hello_version(&[]), DetectedVersion::Unknown);
    }

    #[test]
    fn too_short_is_unknown() {
        // Non-handshake content type
        let pkt = [0x17, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF];
        assert_eq!(server_hello_version(&pkt), DetectedVersion::Unknown);
    }
}
