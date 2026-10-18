//! Focused reproductions of interop issues found against OpenSSL 4.1.
//!
//! Each test asserts the RFC 9147 behaviour, so it fails while the issue is
//! open. The doc comment names the side at fault.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use crate::link::{Dir, Mode, RTO_STEP, Setup, has_client_hello};
use crate::{config, connect, role};

/// dimpl. RFC 8446 §4.6.1 lets a server send NewSessionTicket any time after
/// the client Finished; a client that does not resume ignores it, and DTLS
/// 1.3 ACKs it (RFC 9147 §5.8.4). dimpl rejects every post-handshake message
/// except KeyUpdate as `RenegotiationAttempt`, a fatal error. Filed as #178.
#[test]
fn dimpl_client_rejects_post_handshake_ticket() {
    require_dtls13!();
    for mode in [Mode::Dtls13, Mode::Auto] {
        let mut setup = Setup::new(true);
        setup.mode = mode;
        let mut link = connect(setup);
        link.ossl_new_session_ticket()
            .unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        link.assert_data_flows("after ticket");
        link.assert_no_pending_retransmit();
    }
}

/// dimpl. RFC 9147 §7: post-handshake ACKs cover "records containing messages
/// which are discarded because a previous copy has been received". When
/// dimpl's ACK for a KeyUpdate is lost, OpenSSL retransmits the KeyUpdate but
/// dimpl drops the duplicate silently. OpenSSL never completes the update and
/// holds all further application data (RFC 9147 §8), so its sending
/// direction stalls for good. Filed as #177.
#[test]
fn dimpl_does_not_reack_retransmitted_key_update() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut setup = Setup::new(dimpl_client);
        setup.ossl.fast_timer = true;
        let mut link = connect(setup);
        let lost_ack = link.sent(Dir::ToOssl);
        link.set_drop_rule(move |dir, n, _| dir == Dir::ToOssl && n == lost_ack);
        link.ossl_key_update(false)
            .unwrap_or_else(|e| panic!("{e}"));
        link.settle(8)
            .unwrap_or_else(|e| panic!("{}: {e}", role(dimpl_client)));
        link.clear_drop_rule();
        link.assert_data_flows("after KeyUpdate");
    }
}

/// dimpl. RFC 9147 §7.2: "the receipt of any record responding to a given
/// flight MUST be taken as an implicit acknowledgement for the entire flight",
/// after which retransmissions MUST stop. When the middle of OpenSSL's first
/// flight is lost, dimpl still resends its ClientHello on the flight timer
/// although it already processed the ServerHello.
#[test]
fn dimpl_client_resends_client_hello_after_server_hello() {
    require_dtls13!();
    let mut setup = Setup::new(true);
    // OpenSSL's first flight spans three datagrams.
    setup.ossl.mtu = 400;
    let mut link = setup.link();
    let resent = Rc::new(Cell::new(false));
    let flag = Rc::clone(&resent);
    link.set_drop_rule(move |dir, n, datagram| match dir {
        Dir::ToDimpl => n == 1,
        // Keep dimpl's reaction from OpenSSL (see the partial-flight ACK test).
        Dir::ToOssl => {
            flag.set(flag.get() || (n > 0 && has_client_hello(datagram)));
            n > 0
        }
    });
    assert!(
        link.handshake().is_err(),
        "the lost datagram stalls the handshake"
    );
    link.advance_dimpl(RTO_STEP)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !resent.get(),
        "{}",
        link.report("dimpl resent its ClientHello after receiving ServerHello")
    );
}

/// dimpl. After the peer's close_notify has been reported and `close()` sends
/// ours, nothing is left to do, yet `is_closing()` stays true and `is_closed()`
/// false until some later `handle_packet`/`handle_timeout`. The next timeout
/// is ~10 years out, so an embedder waiting for `is_closed()` never gets it.
/// Filed as #179.
#[test]
fn dimpl_is_not_closed_after_answering_close_notify() {
    require_dtls13!();
    for dimpl_client in [true, false] {
        let mut link = connect(Setup::new(dimpl_client));
        link.ossl_shutdown().unwrap_or_else(|e| panic!("{e}"));
        assert!(link.dimpl_close_notify);
        link.dimpl_close().unwrap_or_else(|e| panic!("{e}"));
        assert!(link.ossl_close_notify);
        let next_timeout = link
            .dimpl_timeout
            .map(|timeout| timeout.saturating_duration_since(link.now));
        assert!(
            link.dimpl.is_closed() && !link.dimpl.is_closing(),
            "{}: is_closing={}, is_closed={}, next timeout in {next_timeout:?}",
            role(dimpl_client),
            link.dimpl.is_closing(),
            link.dimpl.is_closed()
        );
    }
}

/// dimpl + OpenSSL. Data queued before the handshake is sent by the dimpl
/// client as an epoch-3 record in the same datagram as its epoch-2 Finished.
/// OpenSSL 4.1 drops it (RFC 9147 §4.2.1 allows discarding new-epoch records
/// before the handshake completes) and dimpl never resends application data,
/// so the data is lost every time.
#[test]
fn queued_data_coalesced_with_client_finished_is_lost() {
    require_dtls13!();
    let mut link = Setup::new(true).link();
    let early = b"queued before the handshake".to_vec();
    assert_eq!(link.dimpl.send_application_data(&early), Ok(early.len()));
    link.handshake().unwrap_or_else(|e| panic!("{e}"));
    link.assert_data_flows("after the handshake");
    link.ossl_send(b"flush").unwrap_or_else(|e| panic!("{e}"));
    assert!(
        link.ossl_data.contains(&early),
        "{}",
        link.report("OpenSSL never delivered the queued data")
    );
}

/// Control for the test above: the same data in its own datagram arrives.
#[test]
fn queued_data_in_its_own_datagram_is_delivered() {
    require_dtls13!();
    let mut link = Setup::new(true).link();
    link.split_dimpl_records = true;
    let early = b"queued before the handshake".to_vec();
    assert_eq!(link.dimpl.send_application_data(&early), Ok(early.len()));
    link.handshake().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        std::mem::take(&mut link.ossl_data),
        vec![early],
        "{}",
        link.report("OpenSSL lost the queued data")
    );
}

/// OpenSSL. After a HelloRetryRequest the OpenSSL client's record layer is in
/// DTLS 1.3 mode. A datagram holding only epoch-2 records (because the one
/// with the ServerHello was lost or reordered) is buffered and
/// `dtls_get_more_records` returns RETRY without reading the BIO, so
/// `SSL_get_error` reports `SSL_ERROR_SYSCALL` with an empty error queue
/// instead of `SSL_ERROR_WANT_READ`. Applications treat that as fatal.
/// Filed as openssl/openssl#33241.
#[test]
fn openssl_client_syscall_on_lost_server_hello_after_hrr() {
    require_dtls13!();
    let mut link = lost_server_hello(true, false);
    link.handshake_with_retries(8)
        .unwrap_or_else(|e| panic!("{e}"));
    link.assert_dtls13_session();
}

/// Control: OpenSSL recovers when told to ignore the silent SYSCALL, so it was
/// a mis-reported retry rather than a broken connection.
#[test]
fn openssl_client_recovers_if_silent_syscall_is_ignored() {
    require_dtls13!();
    let mut link = lost_server_hello(true, true);
    link.handshake_with_retries(8)
        .unwrap_or_else(|e| panic!("{e}"));
    link.assert_dtls13_session();
    assert!(
        link.ossl.silent_syscalls > 0,
        "OpenSSL never hit the silent SYSCALL"
    );
}

/// Control: without a HelloRetryRequest the same loss is handled.
#[test]
fn openssl_client_handles_lost_server_hello_without_hrr() {
    require_dtls13!();
    let mut link = lost_server_hello(false, false);
    link.handshake_with_retries(8)
        .unwrap_or_else(|e| panic!("{e}"));
    link.assert_dtls13_session();
}

/// dimpl server with a multi-datagram first flight whose ServerHello datagram
/// is lost once.
fn lost_server_hello(hello_retry: bool, tolerate_silent_syscall: bool) -> crate::link::Link {
    let mut setup = Setup::new(false);
    setup.dimpl = config(|b| b.mtu(400).use_server_cookie(hello_retry));
    setup.ossl.mtu = 400;
    setup.ossl.fast_timer = true;
    setup.ossl.tolerate_silent_syscall = tolerate_silent_syscall;
    let mut link = setup.link();
    // With a cookie, ToOssl #0 is the HelloRetryRequest.
    let server_hello = usize::from(hello_retry);
    link.set_drop_rule(move |dir, n, _| dir == Dir::ToOssl && n == server_hello);
    link
}

/// OpenSSL. RFC 9147 §7.1 notes that KeyUpdates "might have crossed in
/// flight". While its own KeyUpdate awaits an ACK, the OpenSSL 4.1 server
/// (`TLS_ST_SW_KEY_UPDATE`) only accepts an ACK, so a crossing client
/// KeyUpdate aborts the connection with `unexpected_message`. The OpenSSL
/// client state machine accepts it.
#[test]
fn openssl_server_aborts_on_crossing_key_update() {
    require_dtls13!();
    crossing_key_updates(true);
}

/// Control: the OpenSSL client handles the same crossing.
#[test]
fn openssl_client_handles_crossing_key_update() {
    require_dtls13!();
    crossing_key_updates(false);
}

fn crossing_key_updates(dimpl_client: bool) {
    let mut setup = Setup::new(dimpl_client);
    // dimpl starts a KeyUpdate as soon as it encrypts an application record.
    setup.dimpl = config(|b| b.aead_encryption_limit(1));
    let mut link = connect(setup);
    // OpenSSL's KeyUpdate stays queued until both updates are in flight.
    link.ossl
        .key_update(false)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(link.dimpl.send_application_data(b"crossing"), Ok(8));
    link.dimpl_handle_timeout()
        .unwrap_or_else(|e| panic!("{e}"));
    link.pump()
        .unwrap_or_else(|e| panic!("{}: {e}", role(dimpl_client)));
    assert_eq!(
        std::mem::take(&mut link.ossl_data),
        vec![b"crossing".to_vec()]
    );
    link.assert_data_flows("after crossing KeyUpdates");
    link.assert_no_pending_retransmit();
}

/// OpenSSL. RFC 9147 §7.1: on a gap in the incoming flight a receiver SHOULD
/// ACK what it has, and §7.2 says the sender SHOULD then retransmit the rest.
/// The OpenSSL 4.1 server only accepts ACKs after KeyUpdate/NewSessionTicket;
/// in `TLS_ST_SW_FINISHED` it aborts with `unexpected_message`. Filed as
/// openssl/openssl#33242.
#[test]
fn openssl_server_aborts_on_ack_for_partial_flight() {
    require_dtls13!();
    let mut setup = Setup::new(true);
    setup.ossl.mtu = 400;
    setup.ossl.fast_timer = true;
    let mut link = setup.link();
    // Lose the middle of OpenSSL's three-datagram first flight once.
    link.set_drop_rule(|dir, n, _| dir == Dir::ToDimpl && n == 1);
    assert!(
        link.handshake().is_err(),
        "the lost datagram stalls the handshake"
    );
    // dimpl ACKs what it has after RTO/4 (at most ~312 ms with jitter), well
    // before its ClientHello timer (at least 750 ms), so OpenSSL only gets the
    // ACK.
    let sent = link.sent(Dir::ToOssl);
    link.advance_dimpl(Duration::from_millis(400))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(link.sent(Dir::ToOssl), sent + 1, "dimpl sends only its ACK");
    link.handshake_with_retries(8)
        .unwrap_or_else(|e| panic!("{e}"));
    link.assert_dtls13_session();
}
