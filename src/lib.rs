#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
// #![deny(missing_docs)]

const MAX_MTU: usize = 2200;

#[macro_use]
extern crate log;

pub mod state;

mod client;
use std::time::Instant;

pub use client::Client;

pub(crate) mod message;

mod time_tricks;

mod buffer;
mod crypto;
mod engine;
mod incoming;

mod util;

mod error;
pub use error::Error;

mod config;
pub use config::Config;

pub mod certificate;
pub use certificate::{
    calculate_fingerprint, format_fingerprint, generate_self_signed_certificate, CertificateError,
    DtlsCertificate,
};

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
}
