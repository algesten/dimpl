//! DTLS 1.3 interop tests: dimpl <-> OpenSSL 4.1+.
//!
//! OpenSSL added DTLS 1.3 in 4.1. These tests skip when the linked OpenSSL
//! is older, unless `DIMPL_REQUIRE_OPENSSL_DTLS13` is set.
//! `scripts/openssl-4.1-interop.sh` builds OpenSSL 4.1 and runs them.

#![cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]

#[path = "../ossl/mod.rs"]
mod ossl_helper;

mod link;
mod peer;

use std::cell::Cell;
use std::rc::Rc;

use dimpl::{Config, ProtocolVersion};

use link::{Dir, Link, Mode, Setup};
use ossl_helper::DtlsPKeyType;
use peer::Versions;

const CIPHER_SUITES: [&str; 3] = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];

fn dtls13_available() -> bool {
    if peer::has_dtls13() {
        return true;
    }
    assert!(
        std::env::var_os("DIMPL_REQUIRE_OPENSSL_DTLS13").is_none(),
        "DIMPL_REQUIRE_OPENSSL_DTLS13 is set, but {} lacks DTLS 1.3",
        openssl::version::version()
    );
    eprintln!("skipping: {} lacks DTLS 1.3", openssl::version::version());
    false
}

macro_rules! require_dtls13 {
    () => {
        let _ = env_logger::try_init();
        if !$crate::dtls13_available() {
            return;
        }
    };
}

// After the macro so the findings can use it.
mod findings;

fn connect(setup: Setup) -> Link {
    let mut link = setup.link();
    link.handshake().unwrap_or_else(|e| panic!("{e}"));
    if std::env::var_os("DIMPL_INTEROP_TRACE").is_some() {
        eprintln!("{}", link.report("handshake"));
    }
    link
}

fn role(dimpl_client: bool) -> &'static str {
    if dimpl_client {
        "dimpl client, OpenSSL server"
    } else {
        "OpenSSL client, dimpl server"
    }
}

fn config(build: impl FnOnce(dimpl::ConfigBuilder) -> dimpl::ConfigBuilder) -> Config {
    build(Config::builder()).build().expect("dimpl config")
}

#[test]
fn linked_openssl_supports_dtls13() {
    require_dtls13!();
    eprintln!("linked {}", openssl::version::version());
}

#[test]
fn dimpl_client_with_openssl_server() {
    require_dtls13!();
    let mut link = connect(Setup::new(true));
    link.assert_dtls13_session();
    link.assert_data_flows(role(true));
}

#[test]
fn openssl_client_with_dimpl_server() {
    require_dtls13!();
    let mut link = connect(Setup::new(false));
    link.assert_dtls13_session();
    link.assert_data_flows(role(false));
}

#[test]
fn dtls13_only_openssl() {
    require_dtls13!();
    for mode in [Mode::Dtls13, Mode::Auto] {
        for dimpl_client in [true, false] {
            let mut setup = Setup::new(dimpl_client);
            setup.mode = mode;
            setup.ossl.versions = Versions::Dtls13Only;
            let mut link = connect(setup);
            link.assert_dtls13_session();
            link.assert_data_flows(role(dimpl_client));
        }
    }
}

#[test]
fn auto_negotiates_dtls13() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut setup = Setup::new(dimpl_client);
        setup.mode = Mode::Auto;
        let mut link = connect(setup);
        link.assert_dtls13_session();
        link.assert_data_flows(role(dimpl_client));
    }
}

#[test]
fn auto_falls_back_to_dtls12() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut setup = Setup::new(dimpl_client);
        setup.mode = Mode::Auto;
        setup.ossl.versions = Versions::Dtls12Only;
        let mut link = connect(setup);
        assert_eq!(
            link.dimpl.protocol_version(),
            Some(ProtocolVersion::DTLS1_2)
        );
        assert_eq!(link.ossl.version(), Some("DTLSv1.2"));
        link.assert_session();
        link.assert_data_flows(role(dimpl_client));
    }
}

#[test]
fn every_cipher_suite() {
    require_dtls13!();
    for suite in CIPHER_SUITES {
        for dimpl_client in [true, false] {
            let mut setup = Setup::new(dimpl_client);
            setup.ossl.ciphersuites = Some(suite);
            let mut link = connect(setup);
            link.assert_dtls13_session();
            assert_eq!(link.ossl.cipher(), Some(suite), "{}", role(dimpl_client));
            link.assert_data_flows(suite);
        }
    }
}

#[test]
fn every_key_exchange_group() {
    require_dtls13!();
    for (groups, expected) in [
        ("X25519", "X25519"),
        ("P-256", "secp256r1"),
        ("P-384", "secp384r1"),
    ] {
        for dimpl_client in [true, false] {
            let mut setup = Setup::new(dimpl_client);
            setup.ossl.groups = Some(groups);
            let mut link = connect(setup);
            link.assert_dtls13_session();
            let group = link.ossl.group().unwrap_or_default();
            assert!(
                group.eq_ignore_ascii_case(expected),
                "{}: negotiated {group}, expected {expected}",
                role(dimpl_client)
            );
            link.assert_data_flows(groups);
        }
    }
}

#[test]
fn ecdsa_certificate_curves() {
    require_dtls13!();
    use DtlsPKeyType::{EcDsaP256, EcDsaP384};
    for (dimpl_key, ossl_key) in [
        (EcDsaP384, EcDsaP256),
        (EcDsaP256, EcDsaP384),
        (EcDsaP384, EcDsaP384),
    ] {
        for dimpl_client in [true, false] {
            let mut setup = Setup::new(dimpl_client);
            setup.dimpl_key = dimpl_key.clone();
            setup.ossl_key = ossl_key.clone();
            let mut link = connect(setup);
            link.assert_dtls13_session();
            link.assert_data_flows(role(dimpl_client));
        }
    }
}

#[test]
fn small_mtu_fragments_every_flight() {
    require_dtls13!();
    // OpenSSL's floor is 256 bytes, so its flights split into many datagrams.
    for (dimpl_mtu, ossl_mtu) in [(400, 400), (1150, 256)] {
        for dimpl_client in [true, false] {
            let mut setup = Setup::new(dimpl_client);
            setup.dimpl = config(|b| b.mtu(dimpl_mtu));
            setup.ossl.mtu = ossl_mtu;
            let mut link = connect(setup);
            link.assert_dtls13_session();
            link.assert_data_flows(role(dimpl_client));
        }
    }
}

#[test]
fn openssl_client_sends_grease() {
    require_dtls13!();
    for mode in [Mode::Dtls13, Mode::Auto] {
        let mut setup = Setup::new(false);
        setup.mode = mode;
        setup.ossl.grease = true;
        let mut link = setup.link();
        let saw_grease = Rc::new(Cell::new(false));
        let flag = Rc::clone(&saw_grease);
        link.set_drop_rule(move |dir, _, datagram| {
            flag.set(flag.get() || (dir == Dir::ToDimpl && offers_grease_suite(datagram)));
            false
        });
        link.handshake().unwrap_or_else(|e| panic!("{e}"));
        assert!(
            saw_grease.get(),
            "OpenSSL did not send a GREASE cipher suite"
        );
        link.assert_dtls13_session();
        link.assert_data_flows("GREASE");
    }
}

/// True if a datagram starts with a ClientHello whose first fragment offers
/// an RFC 8701 GREASE cipher suite (0x?A?A with equal bytes).
fn offers_grease_suite(datagram: &[u8]) -> bool {
    // Record header (13) + handshake header (12) + version (2) + random (32).
    let mut at = 13 + 12 + 2 + 32;
    if datagram.len() < at || datagram[0] != 22 || datagram[13] != 1 {
        return false;
    }
    for _ in 0..2 {
        // session_id, then legacy cookie
        let Some(&len) = datagram.get(at) else {
            return false;
        };
        at += 1 + len as usize;
    }
    let Some(len) = datagram.get(at..at + 2) else {
        return false;
    };
    let len = u16::from_be_bytes([len[0], len[1]]) as usize;
    datagram
        .get(at + 2..at + 2 + len)
        .unwrap_or_default()
        .chunks_exact(2)
        .any(|suite| suite[0] == suite[1] && suite[0] & 0x0F == 0x0A)
}

#[test]
fn openssl_client_hybrid_only_key_share() {
    require_dtls13!();
    // OpenSSL offers X25519 but only sends an X25519MLKEM768 key share, so
    // dimpl must ask for X25519 in its HelloRetryRequest.
    for use_cookie in [true, false] {
        let mut setup = Setup::new(false);
        setup.dimpl = config(|b| b.use_server_cookie(use_cookie));
        setup.ossl.groups = Some("*X25519MLKEM768:X25519");
        let mut link = connect(setup);
        link.assert_dtls13_session();
        let group = link.ossl.group().unwrap_or_default();
        assert!(group.eq_ignore_ascii_case("X25519"), "negotiated {group}");
        link.assert_data_flows("hybrid key share");
    }
}

#[test]
fn dimpl_server_without_cookie() {
    require_dtls13!();
    let mut setup = Setup::new(false);
    setup.dimpl = config(|b| b.use_server_cookie(false));
    let mut link = connect(setup);
    link.assert_dtls13_session();
    link.assert_data_flows("no cookie");
}

#[test]
fn openssl_server_cookie_exchange() {
    require_dtls13!();
    for mode in [Mode::Dtls13, Mode::Auto] {
        let mut setup = Setup::new(true);
        setup.mode = mode;
        setup.ossl.cookie_exchange = true;
        let mut link = connect(setup);
        link.assert_dtls13_session();
        link.assert_data_flows("OpenSSL cookie");
    }
}

#[test]
fn openssl_server_without_session_tickets() {
    require_dtls13!();
    let mut setup = Setup::new(true);
    setup.ossl.num_tickets = Some(0);
    let mut link = connect(setup);
    link.assert_dtls13_session();
    link.assert_data_flows("no tickets");
}

#[test]
fn final_flights_are_acknowledged() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut link = connect(Setup::new(dimpl_client));
        link.assert_no_pending_retransmit();
        link.assert_data_flows(role(dimpl_client));
        link.assert_no_pending_retransmit();
    }
}

#[test]
fn openssl_initiated_key_update() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        for request_peer_update in [false, true] {
            let mut link = connect(Setup::new(dimpl_client));
            link.assert_data_flows("before KeyUpdate");
            for round in 0..3 {
                link.ossl_key_update(request_peer_update)
                    .unwrap_or_else(|e| panic!("{e}"));
                link.assert_data_flows(&format!("after KeyUpdate {round}"));
            }
            link.assert_no_pending_retransmit();
        }
    }
}

#[test]
fn dimpl_initiated_key_update() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut setup = Setup::new(dimpl_client);
        // Rotate keys every few records.
        setup.dimpl = config(|b| b.aead_encryption_limit(4));
        let mut link = connect(setup);
        for round in 0..12 {
            link.assert_data_flows(&format!("round {round}"));
        }
        link.assert_no_pending_retransmit();
    }
}

#[test]
fn close_notify_from_dimpl() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut link = connect(Setup::new(dimpl_client));
        link.assert_data_flows("before close");
        link.dimpl_close().unwrap_or_else(|e| panic!("{e}"));
        assert!(
            link.ossl_close_notify,
            "{}",
            link.report("OpenSSL missed close_notify")
        );
        link.ossl_shutdown().unwrap_or_else(|e| panic!("{e}"));
        assert!(
            link.dimpl_close_notify,
            "{}",
            link.report("dimpl missed close_notify")
        );
        assert!(
            link.dimpl.is_closed(),
            "{}",
            link.report("dimpl not closed")
        );
    }
}

#[test]
fn close_notify_from_openssl() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut link = connect(Setup::new(dimpl_client));
        link.assert_data_flows("before close");
        link.ossl_shutdown().unwrap_or_else(|e| panic!("{e}"));
        assert!(
            link.dimpl_close_notify,
            "{}",
            link.report("dimpl missed close_notify")
        );
        link.dimpl_close().unwrap_or_else(|e| panic!("{e}"));
        assert!(
            link.ossl_close_notify,
            "{}",
            link.report("OpenSSL missed close_notify")
        );
    }
}

#[test]
fn single_datagram_loss_sweep() {
    require_dtls13!();
    loss_sweep(None);
}

#[test]
fn small_mtu_single_datagram_loss_sweep() {
    require_dtls13!();
    loss_sweep(Some(400));
}

/// Drop each handshake datagram once, in each direction, and require recovery.
fn loss_sweep(mtu: Option<u32>) {
    let mut failures = Vec::new();
    for dimpl_client in [true, false] {
        for dir in [Dir::ToOssl, Dir::ToDimpl] {
            // Stop once the index runs past the last datagram exchanged
            // before both sides go idle.
            for lost in 0..16 {
                let context = format!("{}, MTU {mtu:?}, lost {dir:?} #{lost}", role(dimpl_client));
                let fired = run_case(&context, &mut failures, || {
                    let mut setup = Setup::new(dimpl_client);
                    setup.ossl.fast_timer = true;
                    if let Some(mtu) = mtu {
                        setup.dimpl = config(|b| b.mtu(mtu as usize));
                        setup.ossl.mtu = mtu;
                    }
                    let mut link = setup.link();
                    let fired = drop_once(&mut link, dir, lost);
                    link.handshake_with_retries(12)
                        .unwrap_or_else(|e| panic!("{e}"));
                    link.settle(12).unwrap_or_else(|e| panic!("{e}"));
                    if fired.get() {
                        // Application data is not retransmitted; stop dropping.
                        link.clear_drop_rule();
                        link.assert_dtls13_session();
                        link.assert_data_flows("after loss");
                    }
                    fired.get()
                });
                if !fired {
                    break;
                }
            }
        }
    }
    assert_no_failures(failures);
}

/// Drop datagram `index` in `dir` once; the flag reports whether it fired.
fn drop_once(link: &mut Link, dir: Dir, index: usize) -> Rc<Cell<bool>> {
    let fired = Rc::new(Cell::new(false));
    let flag = Rc::clone(&fired);
    link.set_drop_rule(move |d, n, _| {
        let drop = !flag.get() && d == dir && n == index;
        flag.set(flag.get() || drop);
        drop
    });
    fired
}

/// Run one sweep case, recording a panic as a failure. Returns the case's
/// result, or true after a failure so the sweep keeps going.
fn run_case(context: &str, failures: &mut Vec<String>, case: impl FnOnce() -> bool) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(case)) {
        Ok(result) => result,
        Err(panic) => {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            let first_line = message.lines().next().unwrap_or_default();
            failures.push(format!("{context}: {first_line}"));
            true
        }
    }
}

fn assert_no_failures(failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} failing cases:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

#[test]
fn key_update_loss_sweep() {
    require_dtls13!();
    let mut failures = Vec::new();
    for dimpl_client in [true, false] {
        for request_peer_update in [false, true] {
            for dir in [Dir::ToOssl, Dir::ToDimpl] {
                for offset in 0..4 {
                    let context = format!(
                        "{}, OpenSSL KeyUpdate(request={request_peer_update}), lost {dir:?} +{offset}",
                        role(dimpl_client)
                    );
                    let fired = run_case(&context, &mut failures, || {
                        let mut setup = Setup::new(dimpl_client);
                        setup.ossl.fast_timer = true;
                        let mut link = connect(setup);
                        link.assert_data_flows("before KeyUpdate");
                        let index = link.sent(dir) + offset;
                        let fired = drop_once(&mut link, dir, index);
                        link.ossl_key_update(request_peer_update)
                            .unwrap_or_else(|e| panic!("{e}"));
                        link.settle(12).unwrap_or_else(|e| panic!("{e}"));
                        if fired.get() {
                            link.clear_drop_rule();
                            link.assert_no_pending_retransmit();
                            link.assert_data_flows("after KeyUpdate");
                        }
                        fired.get()
                    });
                    if !fired {
                        break;
                    }
                }
            }
        }
    }
    assert_no_failures(failures);
}

#[test]
fn duplicated_datagrams() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut link = Setup::new(dimpl_client).link();
        link.duplicate = true;
        link.handshake().unwrap_or_else(|e| panic!("{e}"));
        link.assert_dtls13_session();
        link.assert_data_flows("duplicated");
        link.ossl_key_update(true).unwrap_or_else(|e| panic!("{e}"));
        link.assert_data_flows("duplicated after KeyUpdate");
        link.assert_no_pending_retransmit();
    }
}

#[test]
fn reordered_flights() {
    require_dtls13!();
    let mut failures = Vec::new();
    for dimpl_client in [true, false] {
        run_case(role(dimpl_client), &mut failures, || {
            let mut setup = Setup::new(dimpl_client);
            setup.dimpl = config(|b| b.mtu(400));
            setup.ossl.mtu = 400;
            setup.ossl.fast_timer = true;
            let mut link = setup.link();
            link.reorder = true;
            link.handshake_with_retries(12)
                .unwrap_or_else(|e| panic!("{e}"));
            link.settle(12).unwrap_or_else(|e| panic!("{e}"));
            link.assert_dtls13_session();
            link.reorder = false;
            link.assert_data_flows("reordered");
            true
        });
    }
    assert_no_failures(failures);
}

#[test]
fn server_queues_application_data_until_connected() {
    require_dtls13!();
    let mut link = Setup::new(false).link();
    let early = b"queued before the handshake".to_vec();
    assert_eq!(link.dimpl.send_application_data(&early), Ok(early.len()));
    link.handshake().unwrap_or_else(|e| panic!("{e}"));
    link.assert_dtls13_session();
    assert_eq!(
        std::mem::take(&mut link.ossl_data),
        vec![early],
        "{}",
        link.report("OpenSSL lost queued data")
    );
    link.assert_data_flows("after queued data");
}

#[test]
fn application_data_sizes_and_bursts() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut link = connect(Setup::new(dimpl_client));
        for size in [1, 100, 1000, 1100] {
            let payload: Vec<u8> = (0..size).map(|i| i as u8).collect();
            link.dimpl_send(&payload).unwrap_or_else(|e| panic!("{e}"));
            link.ossl_send(&payload).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                std::mem::take(&mut link.ossl_data),
                vec![payload.clone()],
                "{size}B to OpenSSL"
            );
            assert_eq!(
                std::mem::take(&mut link.dimpl_data),
                vec![payload],
                "{size}B to dimpl"
            );
        }

        let burst: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i; 60]).collect();
        for message in &burst {
            assert_eq!(link.dimpl.send_application_data(message), Ok(message.len()));
            link.ossl.send(message).unwrap_or_else(|e| panic!("{e}"));
        }
        link.dimpl_handle_timeout()
            .unwrap_or_else(|e| panic!("{e}"));
        link.pump().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            std::mem::take(&mut link.ossl_data),
            burst,
            "burst to OpenSSL"
        );
        assert_eq!(
            std::mem::take(&mut link.dimpl_data),
            burst,
            "burst to dimpl"
        );
    }
}

#[test]
fn key_updates_wrap_epoch_bits() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        // Eight OpenSSL updates move both directions well past epoch 7.
        let mut link = connect(Setup::new(dimpl_client));
        for round in 0..8 {
            link.ossl_key_update(true).unwrap_or_else(|e| panic!("{e}"));
            link.assert_data_flows(&format!("OpenSSL KeyUpdate {round}"));
        }
        link.assert_no_pending_retransmit();

        let mut setup = Setup::new(dimpl_client);
        setup.dimpl = config(|b| b.aead_encryption_limit(2));
        let mut link = connect(setup);
        for round in 0..24 {
            link.assert_data_flows(&format!("dimpl KeyUpdate round {round}"));
        }
        link.assert_no_pending_retransmit();
    }
}
