//! DTLS 1.3 implementation module.
//!
//! This module contains the DTLS 1.3 client and server state machines.
//!
//! ## DTLS 1.3 Handshake Flow (RFC 9147)
//!
//! ```text
//! Client                                               Server
//!
//! 1     ClientHello                  -------->
//!       + key_share
//!       + supported_versions
//!
//! 2                                  <--------   HelloRetryRequest
//!                                                  + cookie (optional)
//!
//! 3     ClientHello                  -------->
//!       + key_share
//!       + cookie
//!
//! 4                                                      ServerHello
//!                                                        + key_share
//!                                    <--------   + supported_versions
//!                                    {EncryptedExtensions}
//!                                    {CertificateRequest*}
//!                                    {Certificate*}
//!                                    {CertificateVerify*}
//!                                    <--------   {Finished}
//!
//! 5     {Certificate*}
//!       {CertificateVerify*}
//!       {Finished}                   -------->
//!
//!       [Application Data]           <------->   [Application Data]
//! ```
//!
//! Key differences from DTLS 1.2:
//! - No ChangeCipherSpec message (encryption starts immediately after ServerHello)
//! - HelloRetryRequest replaces HelloVerifyRequest for stateless retry
//! - Key exchange happens in ClientHello/ServerHello via key_share extension
//! - {} denotes encrypted handshake messages (epoch 2)
//! - [] denotes encrypted application data (epoch 3)
//! - Unified record header format for encrypted records
//! - Encrypted sequence numbers for anti-traffic analysis
//! - 0-RTT not supported in this implementation

mod client;
mod engine;
mod incoming;
mod server;

pub(crate) use client::Client13;
pub(crate) use server::Server13;
