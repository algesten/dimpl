//! OpenSSL 4.1 talking to itself, to check that OpenSSL findings don't depend
//! on dimpl. Uses the same in-memory datagram link as the dimpl tests.

use std::time::Duration;

use crate::link::describe;
use crate::ossl_helper::{DtlsCertOptions, OsslDtlsCert};
use crate::peer::{OsslConfig, OsslEvent, OsslPeer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum To {
    Server,
    Client,
}

struct Pair {
    client: OsslPeer,
    server: OsslPeer,
    /// Datagram index to drop once, per direction.
    drop_once: Option<(To, usize)>,
    sent: [usize; 2],
    client_data: Vec<Vec<u8>>,
    server_data: Vec<Vec<u8>>,
    trace: Vec<String>,
}

impl Pair {
    fn new(client: OsslConfig, server: OsslConfig) -> Self {
        let client_cert = OsslDtlsCert::new(DtlsCertOptions::default());
        let server_cert = OsslDtlsCert::new(DtlsCertOptions::default());
        Pair {
            client: OsslPeer::new(&client_cert, &client, true),
            server: OsslPeer::new(&server_cert, &server, false),
            drop_once: None,
            sent: [0; 2],
            client_data: Vec::new(),
            server_data: Vec::new(),
            trace: Vec::new(),
        }
    }

    /// Run the handshake, firing OpenSSL's timers up to `rounds` times.
    fn handshake(&mut self, rounds: usize) -> Result<(), String> {
        if let Err(e) = self.client.start() {
            return Err(self.report(e));
        }
        self.pump()?;
        for _ in 0..rounds {
            if self.client.is_connected() && self.server.is_connected() {
                return Ok(());
            }
            self.tick()?;
        }
        if self.client.is_connected() && self.server.is_connected() {
            return Ok(());
        }
        Err(self.report("handshake did not complete"))
    }

    fn pump(&mut self) -> Result<(), String> {
        for _ in 0..64 {
            self.collect_events();
            let to_server = self.client.take_datagrams();
            let to_client = self.server.take_datagrams();
            if to_server.is_empty() && to_client.is_empty() {
                return Ok(());
            }
            for datagram in to_server {
                if self.deliver(To::Server, &datagram) {
                    if let Err(e) = self.server.handle_datagram(&datagram) {
                        return Err(self.report(format!("server: {e}")));
                    }
                }
            }
            for datagram in to_client {
                if self.deliver(To::Client, &datagram) {
                    if let Err(e) = self.client.handle_datagram(&datagram) {
                        return Err(self.report(format!("client: {e}")));
                    }
                }
            }
        }
        Err(self.report("exchange did not settle"))
    }

    /// Sleep until the earliest OpenSSL timer expires, fire both, exchange.
    fn tick(&mut self) -> Result<(), String> {
        let wait = [self.client.timer(), self.server.timer()]
            .into_iter()
            .flatten()
            .min();
        if let Some(wait) = wait {
            std::thread::sleep(wait + Duration::from_millis(2));
        }
        if let Err(e) = self.client.handle_timeout() {
            return Err(self.report(format!("client: {e}")));
        }
        if let Err(e) = self.server.handle_timeout() {
            return Err(self.report(format!("server: {e}")));
        }
        self.pump()
    }

    fn assert_data_flows(&mut self) {
        self.client
            .send(b"client data")
            .unwrap_or_else(|e| panic!("{e}"));
        self.server
            .send(b"server data")
            .unwrap_or_else(|e| panic!("{e}"));
        self.pump().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(self.server_data, vec![b"client data".to_vec()]);
        assert_eq!(self.client_data, vec![b"server data".to_vec()]);
    }

    fn collect_events(&mut self) {
        for event in self.client.take_events() {
            if let OsslEvent::Data(data) = event {
                self.client_data.push(data);
            }
        }
        for event in self.server.take_events() {
            if let OsslEvent::Data(data) = event {
                self.server_data.push(data);
            }
        }
    }

    fn deliver(&mut self, to: To, datagram: &[u8]) -> bool {
        let n = self.sent[to as usize];
        self.sent[to as usize] += 1;
        let dropped = self.drop_once == Some((to, n));
        if dropped {
            self.drop_once = None;
        }
        let arrow = match to {
            To::Server => "client -> server",
            To::Client => "server -> client",
        };
        let note = if dropped { "DROPPED" } else { "" };
        self.trace.push(format!(
            "{arrow} #{n:<2} {:>5}B {} {note}",
            datagram.len(),
            describe(datagram)
        ));
        !dropped
    }

    fn report(&self, message: impl std::fmt::Display) -> String {
        let mut report = format!("{message}\n  packet trace:");
        for line in &self.trace {
            report.push_str("\n  ");
            report.push_str(line);
        }
        report
    }
}

/// OpenSSL server bug: both peers start a KeyUpdate at the same time. The
/// server, waiting for the ACK of its own KeyUpdate, aborts with
/// `unexpected_message` when the client's KeyUpdate arrives.
#[test]
fn openssl_pair_crossing_key_updates() {
    require_dtls13!();
    let mut pair = Pair::new(OsslConfig::default(), OsslConfig::default());
    pair.handshake(0).unwrap_or_else(|e| panic!("{e}"));
    pair.assert_data_flows();
    // Both KeyUpdates are queued before either side sees the other's.
    pair.server
        .key_update(false)
        .unwrap_or_else(|e| panic!("{e}"));
    pair.client
        .key_update(false)
        .unwrap_or_else(|e| panic!("{e}"));
    pair.pump().unwrap_or_else(|e| panic!("{e}"));
    pair.client_data.clear();
    pair.server_data.clear();
    pair.assert_data_flows();
}

/// Control: one side updating at a time works.
#[test]
fn openssl_pair_sequential_key_updates() {
    require_dtls13!();
    let mut pair = Pair::new(OsslConfig::default(), OsslConfig::default());
    pair.handshake(0).unwrap_or_else(|e| panic!("{e}"));
    pair.server
        .key_update(false)
        .unwrap_or_else(|e| panic!("{e}"));
    pair.pump().unwrap_or_else(|e| panic!("{e}"));
    pair.client
        .key_update(false)
        .unwrap_or_else(|e| panic!("{e}"));
    pair.pump().unwrap_or_else(|e| panic!("{e}"));
    pair.assert_data_flows();
}

/// OpenSSL client bug: the server answers the client's default key shares
/// (X25519MLKEM768, X25519) with a HelloRetryRequest for P-256, and its next
/// flight spans several datagrams. If the one with the ServerHello is lost,
/// the client buffers the encrypted remainder and `SSL_connect` fails with
/// `SSL_ERROR_SYSCALL` and an empty error queue. Filed as
/// openssl/openssl#33241.
#[test]
fn openssl_pair_lost_server_hello_after_hrr() {
    require_dtls13!();
    let mut pair = lost_server_hello_pair(true, false);
    pair.handshake(8).unwrap_or_else(|e| panic!("{e}"));
    pair.assert_data_flows();
}

/// Control: ignoring the silent SYSCALL lets the same handshake complete.
#[test]
fn openssl_pair_lost_server_hello_after_hrr_tolerating_syscall() {
    require_dtls13!();
    let mut pair = lost_server_hello_pair(true, true);
    pair.handshake(8).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        pair.client.silent_syscalls > 0,
        "the silent SYSCALL never happened"
    );
    pair.assert_data_flows();
}

/// Control: without the HelloRetryRequest the same loss is handled.
#[test]
fn openssl_pair_lost_server_hello_without_hrr() {
    require_dtls13!();
    let mut pair = lost_server_hello_pair(false, false);
    pair.handshake(8).unwrap_or_else(|e| panic!("{e}"));
    pair.assert_data_flows();
}

fn lost_server_hello_pair(hello_retry: bool, tolerate_silent_syscall: bool) -> Pair {
    let client = OsslConfig {
        fast_timer: true,
        tolerate_silent_syscall,
        ..OsslConfig::default()
    };
    let server = OsslConfig {
        // The client's default key shares miss P-256, forcing an HRR.
        groups: hello_retry.then_some("P-256"),
        // Spread the server's ServerHello flight over several datagrams.
        mtu: 400,
        fast_timer: true,
        ..OsslConfig::default()
    };
    let mut pair = Pair::new(client, server);
    // Server datagram #0 is the HRR when there is one.
    pair.drop_once = Some((To::Client, usize::from(hello_retry)));
    pair
}
