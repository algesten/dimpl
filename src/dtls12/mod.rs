//! DTLS 1.2 implementation module.
//!
//! This module contains the DTLS 1.2 client and server state machines.
//!
//! ## DTLS 1.2 Handshake Flow (RFC 6347)
//!
//! ```text
//! Client                                               Server
//!
//! 1     ClientHello                  -------->
//!
//! 2                                  <--------   HelloVerifyRequest
//!                                                  (contains cookie)
//!
//! 3     ClientHello                  -------->
//!       (with cookie)
//! 4                                                      ServerHello
//!                                                       Certificate*
//!                                                 ServerKeyExchange*
//!                                                CertificateRequest*
//!                                    <--------       ServerHelloDone
//! 5     Certificate*
//!       ClientKeyExchange
//!       CertificateVerify*
//!       [ChangeCipherSpec]
//!       Finished                     -------->
//! 6                                               [ChangeCipherSpec]
//!                                    <--------              Finished
//!       Application Data             <------->      Application Data
//! ```
//!
//! Key points:
//! - HelloVerifyRequest prevents DoS amplification attacks
//! - ChangeCipherSpec signals transition to encrypted records
//! - Certificate* messages are optional (depends on authentication mode)
//! - All handshake messages use epoch 0 until ChangeCipherSpec
//! - Application data uses epoch 1 with AEAD encryption

mod client;
mod engine;
mod incoming;
mod server;

pub(crate) use client::Client;
pub(crate) use server::Server;
