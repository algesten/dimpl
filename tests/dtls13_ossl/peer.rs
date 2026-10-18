//! In-memory OpenSSL DTLS endpoint driven like a UDP socket.
//!
//! Datagram boundaries are preserved in both directions. OpenSSL runs its
//! retransmission timers on wall-clock time; [`OsslConfig::fast_timer`]
//! shortens them so loss tests only need to sleep briefly.

use std::collections::VecDeque;
use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use std::io;
use std::mem;
use std::ptr;
use std::time::Duration;

use dimpl::SrtpProfile;
use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::srtp::SrtpProfileId;
use openssl::ssl::{
    ErrorCode, HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslContextBuilder,
    SslMethod, SslOptions, SslRef, SslStream, SslVerifyMode,
};

use crate::ossl_helper::OsslDtlsCert;

// Values from OpenSSL 4.1 ssl.h and prov_ssl.h.
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
const DTLS_CTRL_GET_TIMEOUT: c_int = 73;
const DTLS_CTRL_HANDLE_TIMEOUT: c_int = 74;
const DTLS1_2_VERSION: c_long = 0xFEFD;
const DTLS1_3_VERSION: c_long = 0xFEFC;
const SSL_OP_GREASE: u64 = 1 << 41;

const SRTP_PROFILES: &str = "SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80";
const SRTP_LABEL: &str = "EXTRACTOR-dtls_srtp";
const COOKIE: &[u8] = b"dimpl-interop-cookie";

type TimerCallback = unsafe extern "C" fn(ssl: *mut c_void, timer_us: c_uint) -> c_uint;

unsafe extern "C" {
    fn SSL_ctrl(ssl: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_key_update(ssl: *mut c_void, update_type: c_int) -> c_int;
    fn SSL_new_session_ticket(ssl: *mut c_void) -> c_int;
    fn SSL_get0_group_name(ssl: *mut c_void) -> *const c_char;
    fn DTLS_set_timer_cb(ssl: *mut c_void, cb: Option<TimerCallback>);
}

/// True when the linked OpenSSL implements DTLS 1.3 (4.1.0 or later).
pub fn has_dtls13() -> bool {
    openssl::version::number() >= 0x4010_0000
}

/// Protocol versions the OpenSSL endpoint may negotiate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Versions {
    /// OpenSSL defaults: DTLS 1.2 and 1.3.
    Any,
    Dtls12Only,
    Dtls13Only,
}

/// OpenSSL endpoint settings. Defaults mirror a stock `DTLS_method` peer.
#[derive(Clone, Debug)]
pub struct OsslConfig {
    pub versions: Versions,
    /// TLS 1.3 cipher suites (`SSL_CTX_set_ciphersuites`).
    pub ciphersuites: Option<&'static str>,
    /// Supported groups and key shares (`SSL_CTX_set1_groups_list`).
    pub groups: Option<&'static str>,
    pub mtu: u32,
    /// NewSessionTickets sent by a server (OpenSSL default is 2).
    pub num_tickets: Option<usize>,
    /// Send RFC 8701 GREASE values in the ClientHello.
    pub grease: bool,
    /// Require a cookie round trip before a server continues the handshake.
    pub cookie_exchange: bool,
    /// Start retransmission timers at 20 ms instead of 1 s.
    pub fast_timer: bool,
    /// Keep going after `SSL_ERROR_SYSCALL` with an empty error queue, which
    /// OpenSSL 4.1 reports when it buffers next-epoch records without
    /// touching the BIO. Diagnostic only: OpenSSL documents SYSCALL as fatal.
    pub tolerate_silent_syscall: bool,
}

impl Default for OsslConfig {
    fn default() -> Self {
        OsslConfig {
            versions: Versions::Any,
            ciphersuites: None,
            groups: None,
            mtu: 1150,
            num_tickets: None,
            grease: false,
            cookie_exchange: false,
            fast_timer: false,
            // Set DIMPL_INTEROP_TOLERATE_SYSCALL to look past that OpenSSL bug.
            tolerate_silent_syscall: std::env::var_os("DIMPL_INTEROP_TOLERATE_SYSCALL").is_some(),
        }
    }
}

/// Something observable that OpenSSL reported to the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OsslEvent {
    Connected,
    Data(Vec<u8>),
    CloseNotify,
}

pub struct OsslPeer {
    _context: SslContext,
    stage: Stage,
    outgoing: VecDeque<Vec<u8>>,
    events: VecDeque<OsslEvent>,
    pending_writes: VecDeque<Vec<u8>>,
    close_notify: bool,
    tolerate_silent_syscall: bool,
    /// Times a silent `SSL_ERROR_SYSCALL` was tolerated.
    pub silent_syscalls: usize,
}

enum Stage {
    Init(Ssl, Wire, bool),
    Handshaking(MidHandshakeSslStream<Wire>),
    Established(SslStream<Wire>),
    Failed(String),
    Empty,
}

/// Datagram socket stand-in: each read or write is exactly one datagram.
#[derive(Default)]
struct Wire {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}

impl OsslPeer {
    pub fn new(cert: &OsslDtlsCert, config: &OsslConfig, active: bool) -> Self {
        let context = context(cert, config);
        let mut ssl = Ssl::new(&context).expect("OpenSSL SSL object");
        ssl.set_mtu(config.mtu).expect("OpenSSL MTU");

        let (min, max) = match config.versions {
            Versions::Any => (0, 0),
            Versions::Dtls12Only => (DTLS1_2_VERSION, DTLS1_2_VERSION),
            Versions::Dtls13Only => (DTLS1_3_VERSION, DTLS1_3_VERSION),
        };
        let raw = ssl.as_ptr() as *mut c_void;
        // SAFETY: `raw` is a live SSL object owned by `ssl`.
        unsafe {
            assert_eq!(
                SSL_ctrl(raw, SSL_CTRL_SET_MIN_PROTO_VERSION, min, ptr::null_mut()),
                1
            );
            assert_eq!(
                SSL_ctrl(raw, SSL_CTRL_SET_MAX_PROTO_VERSION, max, ptr::null_mut()),
                1
            );
            if config.fast_timer {
                DTLS_set_timer_cb(raw, Some(fast_timer));
            }
        }

        OsslPeer {
            _context: context,
            stage: Stage::Init(ssl, Wire::default(), active),
            outgoing: VecDeque::new(),
            events: VecDeque::new(),
            pending_writes: VecDeque::new(),
            close_notify: false,
            tolerate_silent_syscall: config.tolerate_silent_syscall,
            silent_syscalls: 0,
        }
    }

    /// Start the handshake. Clients emit their ClientHello.
    pub fn start(&mut self) -> Result<(), String> {
        self.drive()
    }

    pub fn handle_datagram(&mut self, datagram: &[u8]) -> Result<(), String> {
        match self.wire() {
            Some(wire) => wire.incoming.push_back(datagram.to_vec()),
            None => return Err("OpenSSL endpoint already failed".into()),
        }
        self.drive()
    }

    /// Fire an expired OpenSSL retransmission timer. Returns true on resend.
    pub fn handle_timeout(&mut self) -> Result<bool, String> {
        let Some(raw) = self.raw() else {
            return Ok(false);
        };
        // SAFETY: `raw` is a live SSL object owned by `self.stage`.
        let result = unsafe { SSL_ctrl(raw, DTLS_CTRL_HANDLE_TIMEOUT, 0, ptr::null_mut()) };
        self.collect();
        if result < 0 {
            return Err(format!(
                "OpenSSL DTLSv1_handle_timeout failed: {:?}",
                ErrorStack::get()
            ));
        }
        self.drive()?;
        Ok(result > 0)
    }

    /// Remaining time on OpenSSL's retransmission timer, if armed.
    pub fn timer(&self) -> Option<Duration> {
        let raw = self.raw()?;
        let mut remaining = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: `raw` is live and `remaining` outlives the call.
        let armed = unsafe {
            SSL_ctrl(
                raw,
                DTLS_CTRL_GET_TIMEOUT,
                0,
                &mut remaining as *mut libc::timeval as *mut c_void,
            )
        };
        (armed == 1).then(|| {
            Duration::from_secs(remaining.tv_sec as u64)
                + Duration::from_micros(remaining.tv_usec as u64)
        })
    }

    pub fn take_datagrams(&mut self) -> Vec<Vec<u8>> {
        self.outgoing.drain(..).collect()
    }

    pub fn take_events(&mut self) -> Vec<OsslEvent> {
        self.events.drain(..).collect()
    }

    /// Queue application data; OpenSSL may hold it until its KeyUpdate is ACKed.
    pub fn send(&mut self, data: &[u8]) -> Result<(), String> {
        if !matches!(self.stage, Stage::Established(_)) {
            return Err("OpenSSL endpoint is not connected".into());
        }
        self.pending_writes.push_back(data.to_vec());
        self.flush_writes()
    }

    /// Writes OpenSSL has not accepted yet.
    pub fn pending_writes(&self) -> usize {
        self.pending_writes.len()
    }

    /// Send close_notify.
    pub fn shutdown(&mut self) -> Result<(), String> {
        let Stage::Established(stream) = &mut self.stage else {
            return Err("OpenSSL endpoint is not connected".into());
        };
        stream
            .shutdown()
            .map_err(|e| format!("OpenSSL shutdown failed: {e:?}"))?;
        self.collect();
        Ok(())
    }

    /// Send a post-handshake NewSessionTicket (servers only).
    ///
    /// RFC 8446 §4.6.1 lets a server send one at any time after the client
    /// Finished, even when the client did not offer `psk_key_exchange_modes`.
    pub fn new_session_ticket(&mut self) -> Result<(), String> {
        let Stage::Established(stream) = &mut self.stage else {
            return Err("OpenSSL endpoint is not connected".into());
        };
        let raw = stream.ssl().as_ptr() as *mut c_void;
        // SAFETY: `raw` is the live SSL object inside `stream`.
        if unsafe { SSL_new_session_ticket(raw) } != 1 {
            return Err(format!(
                "OpenSSL SSL_new_session_ticket failed: {:?}",
                ErrorStack::get()
            ));
        }
        // DTLS 1.3 waits for the peer's ACK, so WANT_READ means "sent".
        match stream.do_handshake() {
            Ok(()) => {}
            Err(e) if e.code() == ErrorCode::WANT_READ => {}
            Err(e) => return Err(format!("OpenSSL failed to send NewSessionTicket: {e:?}")),
        }
        self.collect();
        Ok(())
    }

    /// Send a KeyUpdate, optionally asking the peer to update its keys too.
    pub fn key_update(&mut self, request_peer_update: bool) -> Result<(), String> {
        let Stage::Established(stream) = &mut self.stage else {
            return Err("OpenSSL endpoint is not connected".into());
        };
        let raw = stream.ssl().as_ptr() as *mut c_void;
        // SAFETY: `raw` is the live SSL object inside `stream`.
        if unsafe { SSL_key_update(raw, c_int::from(request_peer_update)) } != 1 {
            return Err(format!(
                "OpenSSL SSL_key_update failed: {:?}",
                ErrorStack::get()
            ));
        }
        // DTLS 1.3 waits for the peer's ACK, so WANT_READ means "sent".
        match stream.do_handshake() {
            Ok(()) => {}
            Err(e) if e.code() == ErrorCode::WANT_READ => {}
            Err(e) => return Err(format!("OpenSSL failed to send KeyUpdate: {e:?}")),
        }
        self.collect();
        Ok(())
    }

    /// Negotiated protocol, e.g. `DTLSv1.3`.
    pub fn version(&self) -> Option<&'static str> {
        self.ssl().map(|ssl| ssl.version_str())
    }

    pub fn cipher(&self) -> Option<&'static str> {
        self.ssl()?.current_cipher().map(|cipher| cipher.name())
    }

    pub fn group(&self) -> Option<String> {
        let raw = self.raw()?;
        // SAFETY: `raw` is live; OpenSSL returns a static string or null.
        let name = unsafe { SSL_get0_group_name(raw) };
        // SAFETY: non-null names are NUL-terminated static strings.
        (!name.is_null()).then(|| {
            unsafe { CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned()
        })
    }

    /// Selected SRTP profile and exported `EXTRACTOR-dtls_srtp` material.
    pub fn srtp(&self) -> Option<(SrtpProfile, Vec<u8>)> {
        let ssl = self.ssl()?;
        let profile = match ssl.selected_srtp_profile()?.id() {
            SrtpProfileId::SRTP_AES128_CM_SHA1_80 => SrtpProfile::AES128_CM_SHA1_80,
            SrtpProfileId::SRTP_AEAD_AES_128_GCM => SrtpProfile::AEAD_AES_128_GCM,
            SrtpProfileId::SRTP_AEAD_AES_256_GCM => SrtpProfile::AEAD_AES_256_GCM,
            other => panic!("unexpected SRTP profile {:#x}", other.as_raw()),
        };
        let mut material = vec![0; profile.keying_material_len()];
        ssl.export_keying_material(&mut material, SRTP_LABEL, None)
            .expect("OpenSSL SRTP keying material export");
        Some((profile, material))
    }

    pub fn peer_certificate(&self) -> Option<Vec<u8>> {
        let certificate = self.ssl()?.peer_certificate()?;
        Some(certificate.to_der().expect("peer certificate DER"))
    }

    fn drive(&mut self) -> Result<(), String> {
        loop {
            let result = match mem::replace(&mut self.stage, Stage::Empty) {
                Stage::Init(ssl, wire, true) => ssl.connect(wire),
                Stage::Init(ssl, wire, false) => ssl.accept(wire),
                Stage::Handshaking(handshake) => handshake.handshake(),
                Stage::Established(stream) => {
                    self.stage = Stage::Established(stream);
                    return self.read_records();
                }
                Stage::Failed(error) => {
                    self.stage = Stage::Failed(error.clone());
                    return Err(error);
                }
                Stage::Empty => unreachable!("stage is restored after every transition"),
            };

            match result {
                // Loop again to read records that arrived with the final flight.
                Ok(stream) => {
                    self.events.push_back(OsslEvent::Connected);
                    self.stage = Stage::Established(stream);
                }
                Err(HandshakeError::WouldBlock(handshake)) => {
                    self.stage = Stage::Handshaking(handshake);
                    self.collect();
                    return Ok(());
                }
                Err(HandshakeError::Failure(handshake))
                    if self.tolerate_silent_syscall && is_silent_syscall(handshake.error()) =>
                {
                    self.silent_syscalls += 1;
                    self.stage = Stage::Handshaking(handshake);
                    self.collect();
                    return Ok(());
                }
                Err(HandshakeError::Failure(mut handshake)) => {
                    // Keep the alert OpenSSL queued so the caller can trace it.
                    self.outgoing.extend(handshake.get_mut().outgoing.drain(..));
                    let error = format!("OpenSSL handshake failed: {:?}", handshake.error());
                    self.stage = Stage::Failed(error.clone());
                    return Err(error);
                }
                Err(HandshakeError::SetupFailure(stack)) => {
                    let error = format!("OpenSSL handshake setup failed: {stack:?}");
                    self.stage = Stage::Failed(error.clone());
                    return Err(error);
                }
            }
        }
    }

    fn read_records(&mut self) -> Result<(), String> {
        let Stage::Established(stream) = &mut self.stage else {
            return Ok(());
        };
        let mut buffer = vec![0; 1 << 15];
        let mut result = Ok(());
        loop {
            let pending = stream.get_ref().incoming.len();
            match stream.ssl_read(&mut buffer) {
                Ok(len) => self
                    .events
                    .push_back(OsslEvent::Data(buffer[..len].to_vec())),
                Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                    if !self.close_notify {
                        self.close_notify = true;
                        self.events.push_back(OsslEvent::CloseNotify);
                    }
                    break;
                }
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                    let remaining = stream.get_ref().incoming.len();
                    if remaining == 0 || remaining == pending {
                        break;
                    }
                }
                Err(e) => {
                    result = Err(format!("OpenSSL read failed: {e:?}"));
                    break;
                }
            }
        }
        self.collect();
        result?;
        self.flush_writes()
    }

    fn flush_writes(&mut self) -> Result<(), String> {
        let Stage::Established(stream) = &mut self.stage else {
            return Ok(());
        };
        let mut result = Ok(());
        while let Some(data) = self.pending_writes.front() {
            let len = data.len();
            match stream.ssl_write(data) {
                Ok(written) => {
                    assert_eq!(written, len, "OpenSSL accepted a partial write");
                    self.pending_writes.pop_front();
                }
                // DTLS 1.3 holds writes while its own KeyUpdate awaits an ACK.
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                    break;
                }
                Err(e) => {
                    result = Err(format!("OpenSSL write failed: {e:?}"));
                    break;
                }
            }
        }
        self.collect();
        result
    }

    fn collect(&mut self) {
        let datagrams: Vec<Vec<u8>> = match self.wire() {
            Some(wire) => wire.outgoing.drain(..).collect(),
            None => Vec::new(),
        };
        self.outgoing.extend(datagrams);
    }

    fn wire(&mut self) -> Option<&mut Wire> {
        match &mut self.stage {
            Stage::Init(_, wire, _) => Some(wire),
            Stage::Handshaking(handshake) => Some(handshake.get_mut()),
            Stage::Established(stream) => Some(stream.get_mut()),
            Stage::Failed(_) | Stage::Empty => None,
        }
    }

    fn ssl(&self) -> Option<&SslRef> {
        match &self.stage {
            Stage::Init(ssl, _, _) => Some(&**ssl),
            Stage::Handshaking(handshake) => Some(handshake.ssl()),
            Stage::Established(stream) => Some(stream.ssl()),
            Stage::Failed(_) | Stage::Empty => None,
        }
    }

    fn raw(&self) -> Option<*mut c_void> {
        self.ssl().map(|ssl| ssl.as_ptr() as *mut c_void)
    }
}

fn context(cert: &OsslDtlsCert, config: &OsslConfig) -> SslContext {
    let mut context = SslContextBuilder::new(SslMethod::dtls()).expect("OpenSSL DTLS context");
    // Keep the configured MTU; the in-memory BIO has no path MTU to query.
    context.set_options(SslOptions::NO_QUERY_MTU);
    if let Some(suites) = config.ciphersuites {
        context
            .set_ciphersuites(suites)
            .expect("OpenSSL cipher suites");
    }
    if let Some(groups) = config.groups {
        context.set_groups_list(groups).expect("OpenSSL groups");
    }
    if let Some(tickets) = config.num_tickets {
        context
            .set_num_tickets(tickets)
            .expect("OpenSSL ticket count");
    }
    if config.grease {
        context.set_options(SslOptions::from_bits_retain(SSL_OP_GREASE));
    }
    if config.cookie_exchange {
        context.set_options(SslOptions::COOKIE_EXCHANGE);
        context.set_cookie_generate_cb(|_, cookie| {
            cookie[..COOKIE.len()].copy_from_slice(COOKIE);
            Ok(COOKIE.len())
        });
        context.set_cookie_verify_cb(|_, cookie| cookie == COOKIE);
        context.set_stateless_cookie_generate_cb(|_, cookie| {
            cookie[..COOKIE.len()].copy_from_slice(COOKIE);
            Ok(COOKIE.len())
        });
        context.set_stateless_cookie_verify_cb(|_, cookie| cookie == COOKIE);
    }
    context
        .set_tlsext_use_srtp(SRTP_PROFILES)
        .expect("OpenSSL SRTP profiles");
    // Tickets are only minted when a session id context is set.
    context
        .set_session_id_context(b"dimpl-interop")
        .expect("OpenSSL session id context");
    // Request and accept any peer certificate; the tests compare DER directly.
    context.set_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |_, _| true,
    );
    context
        .set_certificate(&cert.x509)
        .expect("OpenSSL certificate");
    context
        .set_private_key(&cert.pkey)
        .expect("OpenSSL private key");
    context.build()
}

unsafe extern "C" fn fast_timer(_ssl: *mut c_void, timer_us: c_uint) -> c_uint {
    if timer_us == 0 {
        20_000
    } else {
        timer_us.saturating_mul(2).min(320_000)
    }
}

/// `SSL_ERROR_SYSCALL` with neither an OpenSSL error nor an I/O error.
pub fn is_silent_syscall(error: &openssl::ssl::Error) -> bool {
    error.code() == ErrorCode::SYSCALL && error.ssl_error().is_none() && error.io_error().is_none()
}

impl io::Read for Wire {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(datagram) = self.incoming.pop_front() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };
        assert!(
            datagram.len() <= buffer.len(),
            "{}-byte datagram exceeds OpenSSL's {}-byte read",
            datagram.len(),
            buffer.len()
        );
        buffer[..datagram.len()].copy_from_slice(&datagram);
        Ok(datagram.len())
    }
}

impl io::Write for Wire {
    fn write(&mut self, datagram: &[u8]) -> io::Result<usize> {
        self.outgoing.push_back(datagram.to_vec());
        Ok(datagram.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
