//! Low-level DTLS 1.3 message parsing and serialization types.
//!
//! This module exposes enums and helpers used for parsing TLS 1.3 handshake
//! messages over DTLS 1.3 (RFC 9147).

mod certificate;
mod certificate_verify;
mod client_hello;
mod digitally_signed;
mod encrypted_extensions;
mod extension;
mod extensions;
mod finished;
mod handshake;
mod id;
mod random;
mod server_hello;
mod wrapped;

pub use certificate::{Certificate, CertificateEntry};
pub use certificate_verify::CertificateVerify;
pub use client_hello::ClientHello;
pub use digitally_signed::DigitallySigned;
pub use encrypted_extensions::EncryptedExtensions;
pub use extension::{Extension, ExtensionType};
pub use extensions::key_share::{
    KeyShareClientHello, KeyShareHelloRetryRequest, KeyShareServerHello,
};
pub use extensions::signature_algorithms::SignatureAlgorithmsExtension;
pub use extensions::supported_groups::SupportedGroupsExtension;
pub use extensions::supported_versions::{
    SupportedVersionsClientHello, SupportedVersionsServerHello,
};
pub use extensions::use_srtp::{SrtpProfileId, UseSrtpExtension};
pub use finished::Finished;
pub use handshake::{Body, Handshake, Header, MessageType};
pub use id::{Cookie, SessionId};
pub use random::Random;
pub use server_hello::ServerHello;
pub use wrapped::{Asn1Cert, DistinguishedName};

// Re-export shared types
pub use crate::types::{
    CompressionMethod, Dtls13CipherSuite, NamedGroup, ProtocolVersion, SignatureScheme,
};
