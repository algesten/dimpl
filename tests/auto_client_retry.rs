#![cfg(feature = "rcgen")]

//! A dimpl auto-sense client must resend the *same* ClientHello after a
//! HelloVerifyRequest (RFC 6347 §4.2.1) or a HelloRetryRequest (RFC 8446 §4.1.2),
//! apart from the cookie (and key_share/padding for HRR).

use std::sync::Arc;
use std::time::Instant;

use dimpl::{Config, Dtls, Output, certificate};

#[derive(Clone, Copy)]
enum Version {
    Auto,
    Dtls12,
    Dtls13,
}

/// Builds a client and returns it with its first datagram.
fn client(version: Version) -> (Dtls, Vec<u8>) {
    let config = Arc::new(Config::builder().build().expect("config"));
    let cert = certificate::generate_self_signed_certificate().expect("cert");
    let now = Instant::now();
    let mut dtls = match version {
        Version::Auto => Dtls::new_auto(config, cert, now),
        Version::Dtls12 => Dtls::new_12(config, cert, now),
        Version::Dtls13 => Dtls::new_13(config, cert, now),
    };
    dtls.set_active(true);
    dtls.handle_timeout(now).expect("timeout");
    let ch = next_datagram(&mut dtls).expect("first ClientHello");
    (dtls, ch)
}

fn next_datagram(dtls: &mut Dtls) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 2048];
    let mut packet = None;
    loop {
        match dtls.poll_output(&mut buf) {
            Output::Packet(p) => {
                assert!(packet.is_none(), "one ClientHello datagram");
                packet = Some(p.to_vec());
            }
            Output::Timeout(_) => return packet,
            _ => {}
        }
    }
}

/// One handshake message in one DTLS record: 13-byte record header + 12-byte handshake header.
fn handshake_record(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut hs = vec![msg_type];
    hs.extend_from_slice(&len.to_be_bytes()[1..]); // length
    hs.extend_from_slice(&[0, 0]); // message_seq
    hs.extend_from_slice(&[0, 0, 0]); // fragment_offset
    hs.extend_from_slice(&len.to_be_bytes()[1..]); // fragment_length
    hs.extend_from_slice(body);
    let mut rec = vec![0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn hello_verify_request(cookie: &[u8]) -> Vec<u8> {
    let mut body = vec![0xfe, 0xff, cookie.len() as u8]; // server_version DTLS 1.0 (RFC 6347 §4.2.1)
    body.extend_from_slice(cookie);
    handshake_record(3, &body)
}

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// HelloRetryRequest selecting DTLS 1.3 / TLS_AES_128_GCM_SHA256 that only adds a cookie.
fn hello_retry_request(cookie: &[u8], group: Option<u16>) -> Vec<u8> {
    let mut ext = vec![0x00, 0x2b, 0x00, 0x02, 0xfe, 0xfc]; // supported_versions: DTLS 1.3
    ext.extend_from_slice(&[0x00, 0x2c]); // cookie
    ext.extend_from_slice(&((cookie.len() + 2) as u16).to_be_bytes());
    ext.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
    ext.extend_from_slice(cookie);
    if let Some(group) = group {
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x02]);
        ext.extend_from_slice(&group.to_be_bytes());
    }
    let mut body = vec![0xfe, 0xfd]; // legacy_version
    body.extend_from_slice(&HRR_RANDOM);
    body.push(0); // legacy_session_id_echo (client sent an empty one)
    body.extend_from_slice(&[0x13, 0x01, 0x00]); // cipher_suite, legacy_compression_method
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    handshake_record(2, &body)
}

#[derive(Debug, PartialEq, Eq)]
struct ClientHello {
    legacy_version: [u8; 2],
    random: Vec<u8>,
    session_id: Vec<u8>,
    cookie: Vec<u8>,
    cipher_suites: Vec<u16>,
    compression_methods: Vec<u8>,
    /// (type, data) in wire order
    extensions: Vec<(u16, Vec<u8>)>,
}

fn parse_client_hello(datagram: &[u8]) -> ClientHello {
    assert_eq!(datagram[0], 0x16, "handshake record");
    assert_eq!(datagram[13], 1, "ClientHello");
    let b = &datagram[25..];
    let mut i = 0;
    let mut take = |n: usize| {
        let s = &b[i..i + n];
        i += n;
        s.to_vec()
    };
    let legacy_version = take(2).try_into().expect("fixed-width field");
    let random = take(32);
    let n = take(1)[0] as usize;
    let session_id = take(n);
    let n = take(1)[0] as usize;
    let cookie = take(n);
    let n = u16::from_be_bytes(take(2).try_into().expect("fixed-width field")) as usize;
    let cipher_suites = take(n)
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let n = take(1)[0] as usize;
    let compression_methods = take(n);
    let n = u16::from_be_bytes(take(2).try_into().expect("fixed-width field")) as usize;
    let ext = take(n);
    let mut extensions = Vec::new();
    let mut j = 0;
    while j + 4 <= ext.len() {
        let t = u16::from_be_bytes([ext[j], ext[j + 1]]);
        let l = u16::from_be_bytes([ext[j + 2], ext[j + 3]]) as usize;
        extensions.push((t, ext[j + 4..j + 4 + l].to_vec()));
        j += 4 + l;
    }
    ClientHello {
        legacy_version,
        random,
        session_id,
        cookie,
        cipher_suites,
        compression_methods,
        extensions,
    }
}

fn hex(suites: &[u16]) -> Vec<String> {
    suites.iter().map(|s| format!("0x{s:04x}")).collect()
}

const COOKIE: [u8; 20] = [0xC0; 20];
const EXT_PADDING: u16 = 21;
const EXT_COOKIE: u16 = 44;

fn check_hello_verify_request(version: Version) {
    let (mut client, ch1) = client(version);
    client
        .handle_packet(&hello_verify_request(&COOKIE))
        .expect("HVR");
    let ch2 = next_datagram(&mut client).expect("second ClientHello");
    let (ch1, ch2) = (parse_client_hello(&ch1), parse_client_hello(&ch2));

    assert_eq!(ch2.cookie, COOKIE, "cookie echoed");
    // RFC 6347 §4.2.1: "the client MUST use the same parameter values (version, random,
    // session_id, cipher_suites, compression_method) as it did in the original ClientHello."
    assert_eq!(ch1.legacy_version, ch2.legacy_version, "version");
    assert_eq!(ch1.random, ch2.random, "random");
    assert_eq!(ch1.session_id, ch2.session_id, "session_id");
    assert_eq!(
        hex(&ch1.cipher_suites),
        hex(&ch2.cipher_suites),
        "cipher_suites"
    );
    assert_eq!(
        ch1.compression_methods, ch2.compression_methods,
        "compression_method"
    );
}

fn check_hello_retry_request(version: Version, group: Option<u16>) {
    let (mut client, ch1) = client(version);
    client
        .handle_packet(&hello_retry_request(&COOKIE, group))
        .expect("HRR");
    let ch2 = next_datagram(&mut client).expect("second ClientHello");
    let (ch1, ch2) = (parse_client_hello(&ch1), parse_client_hello(&ch2));

    // RFC 8446 §4.1.2: "the client MUST send the same ClientHello without modification,
    // except as follows" (key_share, early_data, cookie, pre_shared_key, padding).
    // This HRR only asks for a cookie, so everything but cookie/padding must match.
    let strip = |ch: &ClientHello| -> Vec<(u16, Vec<u8>)> {
        ch.extensions
            .iter()
            .filter(|(t, _)| {
                *t != EXT_PADDING && *t != EXT_COOKIE && !(group.is_some() && *t == 51)
            })
            .cloned()
            .collect()
    };
    assert!(
        ch2.extensions.iter().any(|(t, _)| *t == EXT_COOKIE),
        "cookie extension"
    );
    assert_eq!(
        hex(&ch1.cipher_suites),
        hex(&ch2.cipher_suites),
        "cipher_suites"
    );
    assert_eq!(
        strip(&ch1),
        strip(&ch2),
        "extensions other than cookie/padding"
    );
    assert_eq!(ch1.random, ch2.random, "random");
    assert_eq!(ch1.legacy_version, ch2.legacy_version);
    assert_eq!(ch1.session_id, ch2.session_id);
    assert_eq!(ch1.compression_methods, ch2.compression_methods);
    assert_eq!(ch1.cookie, ch2.cookie);
    let cookie = &ch2
        .extensions
        .iter()
        .find(|(t, _)| *t == EXT_COOKIE)
        .expect("cookie")
        .1;
    assert_eq!(&cookie[..2], &(COOKIE.len() as u16).to_be_bytes());
    assert_eq!(&cookie[2..], &COOKIE);
    if let Some(group) = group {
        let key = &ch2
            .extensions
            .iter()
            .find(|(t, _)| *t == 51)
            .expect("key_share")
            .1;
        assert_eq!(&key[2..4], &group.to_be_bytes());
        assert_ne!(
            ch1.extensions.iter().find(|(t, _)| *t == 51),
            ch2.extensions.iter().find(|(t, _)| *t == 51)
        );
    }
}

#[test]
fn auto_client_after_hello_verify_request() {
    check_hello_verify_request(Version::Auto);
}

#[test]
fn auto_client_after_hello_retry_request() {
    check_hello_retry_request(Version::Auto, None);
}

// Controls: the version-specific clients already get this right.
#[test]
fn dtls12_client_after_hello_verify_request() {
    check_hello_verify_request(Version::Dtls12);
}

#[test]
fn dtls13_client_after_hello_retry_request() {
    check_hello_retry_request(Version::Dtls13, None);
}

#[test]
fn auto_client_after_hello_retry_request_with_selected_group() {
    // secp256r1 differs from the default X25519 share.
    check_hello_retry_request(Version::Auto, Some(23));
}
