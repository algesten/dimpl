#![forbid(unsafe_code)]
// #![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
#![allow(mismatched_lifetime_syntaxes)]
// #![deny(missing_docs)]

// const MAX_MTU: usize = 2200;

#[macro_use]
extern crate log;

use std::time::Instant;

pub mod state;

mod client;
pub use client::Client;

// mod server;
// pub use server::Server;

mod message;
pub use message::{CipherSuite, SignatureAlgorithm};

mod time_tricks;

pub mod buffer;
mod crypto;
pub use crypto::CertVerifier;
mod engine;
pub mod incoming;

mod util;

mod error;
pub use error::Error;

mod config;
pub use config::Config;

pub mod certificate;

pub use crypto::{KeyingMaterial, SrtpProfile};

// This is the full DTLS1.2 flow
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
pub enum Output<'a> {
    Packet(&'a [u8]),
    Timeout(Instant),
    Connected,
    PeerCert(Vec<u8>),
    KeyingMaterial(KeyingMaterial, SrtpProfile),
    ApplicationData(Vec<u8>),
}
