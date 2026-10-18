//! Drives a dimpl endpoint against an [`OsslPeer`] over an in-memory link.

use std::fmt;
use std::mem;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, DtlsCertificate, Output, ProtocolVersion, SrtpProfile};

use crate::ossl_helper::{DtlsCertOptions, DtlsPKeyType, OsslDtlsCert};
use crate::peer::{OsslConfig, OsslEvent, OsslPeer};

/// Which dimpl constructor to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Dtls13,
    Auto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    ToOssl,
    ToDimpl,
}

/// Decides whether to drop the `n`th datagram (counted per direction).
pub type DropRule = Box<dyn FnMut(Dir, usize, &[u8]) -> bool>;

/// Past dimpl's first retransmission: 1 s start RTO with ±25% jitter.
pub const RTO_STEP: Duration = Duration::from_millis(1300);

pub struct Setup {
    pub mode: Mode,
    pub dimpl_client: bool,
    pub dimpl: Config,
    pub ossl: OsslConfig,
    pub dimpl_key: DtlsPKeyType,
    pub ossl_key: DtlsPKeyType,
}

impl Setup {
    pub fn new(dimpl_client: bool) -> Self {
        Setup {
            mode: Mode::Dtls13,
            dimpl_client,
            dimpl: Config::default(),
            ossl: OsslConfig::default(),
            dimpl_key: DtlsPKeyType::EcDsaP256,
            ossl_key: DtlsPKeyType::EcDsaP256,
        }
    }

    pub fn link(self) -> Link {
        Link::new(self)
    }
}

pub struct Link {
    pub now: Instant,
    pub dimpl: Dtls,
    pub ossl: OsslPeer,
    dimpl_cert: Vec<u8>,
    ossl_cert: Vec<u8>,
    to_ossl: Vec<Vec<u8>>,
    pub dimpl_connected: bool,
    pub dimpl_peer_cert: Option<Vec<u8>>,
    pub dimpl_keying: Option<(Vec<u8>, SrtpProfile)>,
    pub dimpl_data: Vec<Vec<u8>>,
    pub dimpl_close_notify: bool,
    pub dimpl_timeout: Option<Instant>,
    pub ossl_connected: bool,
    pub ossl_data: Vec<Vec<u8>>,
    pub ossl_close_notify: bool,
    drop_rule: Option<DropRule>,
    /// Deliver every datagram twice.
    pub duplicate: bool,
    /// Deliver each batch of datagrams in reverse order.
    pub reorder: bool,
    /// Send every record from dimpl in its own datagram.
    pub split_dimpl_records: bool,
    sent: [usize; 2],
    trace: Vec<String>,
}

impl Link {
    fn new(setup: Setup) -> Self {
        let dimpl_cert = OsslDtlsCert::new(DtlsCertOptions {
            pkey_type: setup.dimpl_key,
            ..DtlsCertOptions::default()
        });
        let ossl_cert = OsslDtlsCert::new(DtlsCertOptions {
            pkey_type: setup.ossl_key,
            ..DtlsCertOptions::default()
        });
        let certificate = DtlsCertificate {
            certificate: dimpl_cert.x509.to_der().expect("dimpl certificate DER"),
            private_key: dimpl_cert
                .pkey
                .private_key_to_pkcs8()
                .expect("dimpl private key DER"),
        };

        let now = Instant::now();
        let config = Arc::new(setup.dimpl);
        let mut dimpl = match setup.mode {
            Mode::Dtls13 => Dtls::new_13(config, certificate.clone(), now),
            Mode::Auto => Dtls::new_auto(config, certificate.clone(), now),
        };
        dimpl.set_active(setup.dimpl_client);
        let ossl = OsslPeer::new(&ossl_cert, &setup.ossl, !setup.dimpl_client);

        Link {
            now,
            dimpl,
            ossl,
            dimpl_cert: certificate.certificate,
            ossl_cert: ossl_cert.x509.to_der().expect("OpenSSL certificate DER"),
            to_ossl: Vec::new(),
            dimpl_connected: false,
            dimpl_peer_cert: None,
            dimpl_keying: None,
            dimpl_data: Vec::new(),
            dimpl_close_notify: false,
            dimpl_timeout: None,
            ossl_connected: false,
            ossl_data: Vec::new(),
            ossl_close_notify: false,
            drop_rule: None,
            duplicate: false,
            reorder: false,
            split_dimpl_records: false,
            sent: [0; 2],
            trace: Vec::new(),
        }
    }

    pub fn set_drop_rule(&mut self, rule: impl FnMut(Dir, usize, &[u8]) -> bool + 'static) {
        self.drop_rule = Some(Box::new(rule));
    }

    pub fn clear_drop_rule(&mut self) {
        self.drop_rule = None;
    }

    /// Datagrams offered in `dir` so far, i.e. the index of the next one.
    pub fn sent(&self, dir: Dir) -> usize {
        self.sent[dir as usize]
    }

    /// Run the handshake until both sides report Connected.
    pub fn handshake(&mut self) -> Result<(), String> {
        self.dimpl_handle_timeout()?;
        if let Err(e) = self.ossl.start() {
            return Err(self.report(e));
        }
        self.pump()?;
        if self.dimpl_connected && self.ossl_connected {
            return Ok(());
        }
        Err(self.report(format!(
            "handshake stalled: dimpl connected={}, OpenSSL connected={}",
            self.dimpl_connected, self.ossl_connected
        )))
    }

    /// Run the handshake, retransmitting on both sides until it completes.
    pub fn handshake_with_retries(&mut self, rounds: usize) -> Result<(), String> {
        self.dimpl_handle_timeout()?;
        if let Err(e) = self.ossl.start() {
            return Err(self.report(e));
        }
        self.pump()?;
        for _ in 0..rounds {
            if self.dimpl_connected && self.ossl_connected {
                return Ok(());
            }
            self.tick(RTO_STEP)?;
        }
        if self.dimpl_connected && self.ossl_connected {
            return Ok(());
        }
        Err(self.report(format!(
            "handshake did not recover: dimpl connected={}, OpenSSL connected={}",
            self.dimpl_connected, self.ossl_connected
        )))
    }

    /// Exchange datagrams until neither side has anything left to send.
    pub fn pump(&mut self) -> Result<(), String> {
        for _ in 0..64 {
            self.collect_ossl_events();
            let mut from_dimpl = mem::take(&mut self.to_ossl);
            if self.split_dimpl_records {
                from_dimpl = from_dimpl
                    .iter()
                    .flat_map(|datagram| records(datagram).into_iter().map(<[u8]>::to_vec))
                    .collect();
            }
            let from_dimpl = self.shape(from_dimpl);
            let from_ossl = self.ossl.take_datagrams();
            let from_ossl = self.shape(from_ossl);
            if from_dimpl.is_empty() && from_ossl.is_empty() {
                return Ok(());
            }

            for datagram in from_dimpl {
                if !self.deliver(Dir::ToOssl, &datagram) {
                    continue;
                }
                if let Err(e) = self.ossl.handle_datagram(&datagram) {
                    self.collect_ossl_events();
                    for alert in self.ossl.take_datagrams() {
                        self.record(Dir::ToDimpl, None, &alert, "after OpenSSL failure");
                        let result = self.dimpl.handle_packet(&alert);
                        self.trace.push(format!("      dimpl: {result:?}"));
                    }
                    return Err(self.report(e));
                }
            }

            for datagram in from_ossl {
                if !self.deliver(Dir::ToDimpl, &datagram) {
                    continue;
                }
                if let Err(e) = self.dimpl.handle_packet(&datagram) {
                    return Err(self.report(format!("dimpl rejected datagram: {e:?}")));
                }
                self.drain_dimpl();
            }
        }
        Err(self.report("exchange did not settle"))
    }

    /// Advance dimpl's clock, fire expired OpenSSL timers, then exchange.
    pub fn tick(&mut self, by: Duration) -> Result<(), String> {
        // OpenSSL timers run on wall-clock time.
        if let Some(remaining) = self.ossl.timer() {
            std::thread::sleep(remaining + Duration::from_millis(2));
        }
        self.now += by;
        self.dimpl_handle_timeout()?;
        if let Err(e) = self.ossl.handle_timeout() {
            return Err(self.report(e));
        }
        self.pump()
    }

    /// Advance only dimpl's clock; OpenSSL's timers keep wall-clock time.
    pub fn advance_dimpl(&mut self, by: Duration) -> Result<(), String> {
        self.now += by;
        self.dimpl_handle_timeout()?;
        self.pump()
    }

    /// Keep ticking until neither side has a retransmission timer armed.
    pub fn settle(&mut self, rounds: usize) -> Result<(), String> {
        for _ in 0..rounds {
            let dimpl_idle = self
                .dimpl_timeout
                .is_some_and(|timeout| timeout > self.now + Duration::from_secs(3600));
            if dimpl_idle && self.ossl.timer().is_none() {
                return Ok(());
            }
            self.tick(RTO_STEP)?;
        }
        Err(self.report("retransmission timers did not settle"))
    }

    pub fn dimpl_handle_timeout(&mut self) -> Result<(), String> {
        if let Err(e) = self.dimpl.handle_timeout(self.now) {
            return Err(self.report(format!("dimpl handle_timeout failed: {e:?}")));
        }
        self.drain_dimpl();
        Ok(())
    }

    pub fn dimpl_send(&mut self, data: &[u8]) -> Result<(), String> {
        match self.dimpl.send_application_data(data) {
            Ok(accepted) if accepted == data.len() => {}
            other => return Err(self.report(format!("dimpl send returned {other:?}"))),
        }
        self.drain_dimpl();
        self.pump()
    }

    pub fn ossl_send(&mut self, data: &[u8]) -> Result<(), String> {
        if let Err(e) = self.ossl.send(data) {
            return Err(self.report(e));
        }
        self.pump()
    }

    pub fn dimpl_close(&mut self) -> Result<(), String> {
        if let Err(e) = self.dimpl.close() {
            return Err(self.report(format!("dimpl close failed: {e:?}")));
        }
        self.drain_dimpl();
        self.pump()
    }

    pub fn ossl_shutdown(&mut self) -> Result<(), String> {
        if let Err(e) = self.ossl.shutdown() {
            return Err(self.report(e));
        }
        self.pump()
    }

    pub fn ossl_key_update(&mut self, request_peer_update: bool) -> Result<(), String> {
        if let Err(e) = self.ossl.key_update(request_peer_update) {
            return Err(self.report(e));
        }
        self.pump()
    }

    pub fn ossl_new_session_ticket(&mut self) -> Result<(), String> {
        if let Err(e) = self.ossl.new_session_ticket() {
            return Err(self.report(e));
        }
        self.pump()
    }

    /// Both sides negotiated DTLS 1.3 and agree on certificates and SRTP keys.
    pub fn assert_dtls13_session(&self) {
        assert_eq!(
            self.dimpl.protocol_version(),
            Some(ProtocolVersion::DTLS1_3),
            "{}",
            self.report("dimpl did not negotiate DTLS 1.3")
        );
        assert_eq!(
            self.ossl.version(),
            Some("DTLSv1.3"),
            "{}",
            self.report("OpenSSL did not negotiate DTLS 1.3")
        );
        self.assert_session();
    }

    pub fn assert_session(&self) {
        assert_eq!(
            self.dimpl_peer_cert.as_deref(),
            Some(self.ossl_cert.as_slice()),
            "dimpl saw the wrong OpenSSL certificate"
        );
        assert_eq!(
            self.ossl.peer_certificate().as_deref(),
            Some(self.dimpl_cert.as_slice()),
            "OpenSSL saw the wrong dimpl certificate"
        );
        let (dimpl_material, dimpl_profile) = self
            .dimpl_keying
            .clone()
            .expect("dimpl SRTP keying material");
        let (ossl_profile, ossl_material) = self.ossl.srtp().expect("OpenSSL SRTP profile");
        assert_eq!(dimpl_profile, ossl_profile, "SRTP profile mismatch");
        assert_eq!(
            dimpl_material, ossl_material,
            "SRTP keying material mismatch"
        );
    }

    /// Send one message each way and check both arrive exactly once.
    pub fn assert_data_flows(&mut self, tag: &str) {
        let to_ossl = format!("{tag}: dimpl -> OpenSSL").into_bytes();
        let to_dimpl = format!("{tag}: OpenSSL -> dimpl").into_bytes();
        self.dimpl_send(&to_ossl).unwrap_or_else(|e| panic!("{e}"));
        self.ossl_send(&to_dimpl).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            self.ossl.pending_writes(),
            0,
            "{}",
            self.report("OpenSSL is still holding application data")
        );
        assert_eq!(
            mem::take(&mut self.ossl_data),
            vec![to_ossl],
            "{}",
            self.report("OpenSSL did not receive dimpl's data once")
        );
        assert_eq!(
            mem::take(&mut self.dimpl_data),
            vec![to_dimpl],
            "{}",
            self.report("dimpl did not receive OpenSSL's data once")
        );
    }

    /// Neither side is waiting to retransmit, i.e. every flight was ACKed.
    pub fn assert_no_pending_retransmit(&self) {
        let ossl_timer = self.ossl.timer();
        assert_eq!(
            ossl_timer,
            None,
            "{}",
            self.report("OpenSSL still has a retransmission timer armed")
        );
        let dimpl_timeout = self.dimpl_timeout.expect("dimpl polled to timeout");
        assert!(
            dimpl_timeout > self.now + Duration::from_secs(3600),
            "{}",
            self.report(format!(
                "dimpl still has a timer armed in {:?}",
                dimpl_timeout.saturating_duration_since(self.now)
            ))
        );
    }

    pub fn report(&self, message: impl fmt::Display) -> String {
        let mut report = format!("{message}\n  packet trace:");
        for line in &self.trace {
            report.push_str("\n  ");
            report.push_str(line);
        }
        report
    }

    fn drain_dimpl(&mut self) {
        let mut buffer = vec![0u8; 2048];
        loop {
            match self.dimpl.poll_output(&mut buffer) {
                Output::Packet(packet) => self.to_ossl.push(packet.to_vec()),
                Output::Connected => self.dimpl_connected = true,
                Output::PeerCert(certificate) => self.dimpl_peer_cert = Some(certificate.to_vec()),
                Output::KeyingMaterial(material, profile) => {
                    self.dimpl_keying = Some((material.to_vec(), profile));
                }
                Output::ApplicationData(data) => self.dimpl_data.push(data.to_vec()),
                Output::CloseNotify => self.dimpl_close_notify = true,
                Output::BufferTooSmall { needed } => buffer.resize(needed, 0),
                Output::Timeout(timeout) => {
                    self.dimpl_timeout = Some(timeout);
                    return;
                }
                _ => {}
            }
        }
    }

    fn collect_ossl_events(&mut self) {
        for event in self.ossl.take_events() {
            match event {
                OsslEvent::Connected => self.ossl_connected = true,
                OsslEvent::Data(data) => self.ossl_data.push(data),
                OsslEvent::CloseNotify => self.ossl_close_notify = true,
            }
        }
    }

    /// Apply the reorder and duplicate impairments to one batch.
    fn shape(&self, mut batch: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        if self.reorder {
            batch.reverse();
        }
        if self.duplicate {
            batch = batch.into_iter().flat_map(|d| [d.clone(), d]).collect();
        }
        batch
    }

    /// Count and trace a datagram; returns false when the drop rule eats it.
    fn deliver(&mut self, dir: Dir, datagram: &[u8]) -> bool {
        let n = self.sent[dir as usize];
        self.sent[dir as usize] += 1;
        let dropped = self
            .drop_rule
            .as_mut()
            .is_some_and(|rule| rule(dir, n, datagram));
        self.record(dir, Some(n), datagram, if dropped { "DROPPED" } else { "" });
        !dropped
    }

    fn record(&mut self, dir: Dir, n: Option<usize>, datagram: &[u8], note: &str) {
        let arrow = match dir {
            Dir::ToOssl => "dimpl -> OpenSSL",
            Dir::ToDimpl => "OpenSSL -> dimpl",
        };
        let n = n.map_or_else(|| "-".to_string(), |n| n.to_string());
        self.trace.push(format!(
            "{arrow} #{n:<2} {:>5}B {} {note}",
            datagram.len(),
            describe(datagram)
        ));
    }
}

/// Split a datagram into its DTLS records (plaintext or unified header).
pub fn records(datagram: &[u8]) -> Vec<&[u8]> {
    let mut records = Vec::new();
    let mut rest = datagram;
    while let Some(&first) = rest.first() {
        let len = if first & 0xE0 == 0x20 {
            let seq_len = if first & 0x08 != 0 { 2 } else { 1 };
            if first & 0x04 == 0 || rest.len() < 3 + seq_len {
                rest.len()
            } else {
                3 + seq_len + u16::from_be_bytes([rest[1 + seq_len], rest[2 + seq_len]]) as usize
            }
        } else if rest.len() >= 13 {
            13 + u16::from_be_bytes([rest[11], rest[12]]) as usize
        } else {
            rest.len()
        };
        let (record, tail) = rest.split_at(len.min(rest.len()));
        records.push(record);
        rest = tail;
    }
    records
}

/// True if the datagram carries a plaintext ClientHello fragment.
pub fn has_client_hello(datagram: &[u8]) -> bool {
    records(datagram)
        .iter()
        .any(|record| record.len() > 13 && record[0] == 22 && record[13] == 1)
}

/// Summarize the records in a datagram for traces.
pub fn describe(datagram: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut rest = datagram;
    while let Some(&first) = rest.first() {
        if first & 0xE0 == 0x20 {
            // DTLS 1.3 unified header: 001CSLEE.
            let seq_len = if first & 0x08 != 0 { 2 } else { 1 };
            let has_len = first & 0x04 != 0;
            let header = 1 + seq_len + if has_len { 2 } else { 0 };
            if first & 0x10 != 0 || rest.len() < header {
                parts.push(format!("cipher?({first:#04x})"));
                break;
            }
            let len = if has_len {
                u16::from_be_bytes([rest[1 + seq_len], rest[2 + seq_len]]) as usize
            } else {
                rest.len() - header
            };
            parts.push(format!("cipher(e{}, {len}B)", first & 0x03));
            rest = &rest[(header + len).min(rest.len())..];
        } else if rest.len() >= 13 {
            let len = u16::from_be_bytes([rest[11], rest[12]]) as usize;
            let epoch = u16::from_be_bytes([rest[3], rest[4]]);
            let body = &rest[13..(13 + len).min(rest.len())];
            parts.push(match (first, epoch) {
                (22, 0) if body.len() >= 12 => describe_handshake(body),
                (21, _) if body.len() >= 2 => format!("alert({}, {})", body[0], body[1]),
                (content_type, epoch) => format!("plain(ct={content_type}, e{epoch}, {len}B)"),
            });
            rest = &rest[(13 + len).min(rest.len())..];
        } else {
            parts.push(format!("junk({}B)", rest.len()));
            break;
        }
    }
    parts.join(" ")
}

fn describe_handshake(body: &[u8]) -> String {
    const HRR_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ];
    let total = u32::from_be_bytes([0, body[1], body[2], body[3]]);
    let seq = u16::from_be_bytes([body[4], body[5]]);
    let offset = u32::from_be_bytes([0, body[6], body[7], body[8]]);
    let fragment = u32::from_be_bytes([0, body[9], body[10], body[11]]);
    let name = match body[0] {
        1 => "ClientHello",
        2 if body.get(14..46) == Some(&HRR_RANDOM[..]) => "HelloRetryRequest",
        2 => "ServerHello",
        3 => "HelloVerifyRequest",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Handshake",
    };
    if offset == 0 && fragment == total {
        format!("{name}(seq {seq}, {total}B)")
    } else {
        format!("{name}(seq {seq}, {offset}+{fragment}/{total})")
    }
}
