//! A DTLS 1.2 implementation for WebRTC.
//!
//! This crate provides a DTLS 1.2 implementation.
//!
//! It is specifically the str0m WebRTC crate.
//!
#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
#![allow(mismatched_lifetime_syntaxes)]
#![allow(clippy::len_without_is_empty)]
#![deny(missing_docs)]

// const MAX_MTU: usize = 2200;

#[macro_use]
extern crate log;

use std::sync::Arc;
use std::time::Instant;

mod client;
use client::Client;

mod server;
use server::Server;

mod message;
pub use message::{CipherSuite, SignatureAlgorithm};

mod time_tricks;

mod buffer;
mod crypto;
pub use crypto::CertVerifier;
mod engine;
mod incoming;

mod util;

mod error;
pub use error::Error;

mod config;
pub use config::Config;

pub mod certificate;

pub use crypto::{KeyingMaterial, SrtpProfile};

mod timer;

/// Public DTLS endpoint wrapping either a client or server state.
///
/// Use the role helpers to query or switch between client and server modes
/// and drive the handshake and record processing.
pub struct Dtls {
    inner: Option<Inner>,
}

enum Inner {
    Client(Client),
    Server(Server),
}

impl Dtls {
    /// Create a new DTLS instance.
    ///
    /// The instance is initialized with the provided `now`, `config`,
    /// certificate, private key, and certificate verifier.
    pub fn new(
        now: Instant,
        config: Arc<Config>,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        cert_verifier: Box<dyn CertVerifier>,
    ) -> Self {
        let inner = Inner::Server(Server::new(
            now,
            config,
            certificate,
            private_key,
            cert_verifier,
        ));
        Dtls { inner: Some(inner) }
    }

    /// Return true if the instance is operating in the client role.
    pub fn is_active(&self) -> bool {
        matches!(self.inner, Some(Inner::Client(_)))
    }

    /// Switch between server and client roles.
    ///
    /// Set `active` to true for client role, false for server role.
    pub fn set_active(&mut self, active: bool) {
        match (self.is_active(), active) {
            (true, false) => {
                let inner = self.inner.take().unwrap();
                let Inner::Client(inner) = inner else {
                    unreachable!();
                };
                self.inner = Some(Inner::Server(inner.into_server()));
            }
            (false, true) => {
                let inner = self.inner.take().unwrap();
                let Inner::Server(inner) = inner else {
                    unreachable!();
                };
                self.inner = Some(Inner::Client(inner.into_client()));
            }
            _ => {}
        }
    }

    /// Process an incoming DTLS datagram.
    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.handle_packet(packet),
            Inner::Server(server) => server.handle_packet(packet),
        }
    }

    /// Poll for pending output from the DTLS engine.
    pub fn poll_output(&mut self) -> Output {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.poll_output(),
            Inner::Server(server) => server.poll_output(),
        }
    }

    /// Handle time-based events such as retransmission timers.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.handle_timeout(now),
            Inner::Server(server) => server.handle_timeout(now),
        }
    }

    /// Send application data over the established DTLS session.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.inner.as_mut().unwrap() {
            Inner::Client(client) => client.send_application_data(data),
            Inner::Server(server) => server.send_application_data(data),
        }
    }
}

// This is the full DTLS 1.2 handshake flow
//
// Client                                               Server
//
//       ClientHello                  -------->
//
//                                    <--------   HelloVerifyRequest
//                                                 (contains cookie)
//
//       ClientHello                  -------->
//       (with cookie)
//                                                       ServerHello
//                                                      Certificate*
//                                                ServerKeyExchange*
//                                               CertificateRequest*
//                                    <--------      ServerHelloDone
//       Certificate*
//       ClientKeyExchange
//       CertificateVerify*
//       [ChangeCipherSpec]
//       Finished                     -------->
//                                                [ChangeCipherSpec]
//                                    <--------             Finished
//       Application Data             <------->     Application Data
/// Output events produced by the DTLS engine when polled.
pub enum Output<'a> {
    /// A DTLS record to transmit on the wire.
    Packet(&'a [u8]),
    /// A timeout instant for scheduling retransmission or handshake timers.
    Timeout(Instant),
    /// The handshake completed and the connection is established.
    Connected,
    /// The peer's leaf certificate in DER encoding.
    PeerCert(Vec<u8>),
    /// Extracted DTLS-SRTP keying material and selected SRTP profile.
    KeyingMaterial(KeyingMaterial, SrtpProfile),
    /// Received application data plaintext.
    ApplicationData(Vec<u8>),
}

#[cfg(test)]
mod test {
    use crate::certificate::generate_self_signed_certificate;

    use super::*;

    #[test]
    fn test_dtls_default() {
        let client_cert =
            generate_self_signed_certificate().expect("Failed to generate client cert");

        // Initialize client
        let now = Instant::now();
        let config = Arc::new(Config::default());

        // Simple certificate verifier that accepts any certificate
        struct DummyVerifier;
        impl CertVerifier for DummyVerifier {
            fn verify_certificate(&self, _der: &[u8]) -> Result<(), String> {
                Ok(())
            }
        }

        let mut dtls = Dtls::new(
            now,
            config,
            client_cert.certificate,
            client_cert.private_key,
            Box::new(DummyVerifier),
        );

        assert!(!dtls.is_active());
        dtls.set_active(true);
        assert!(dtls.is_active());
        dtls.set_active(false);
    }
}
