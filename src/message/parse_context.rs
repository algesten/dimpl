//! Parsing context for version-aware DTLS message parsing.
//!
//! The `ParseContext` carries the negotiated DTLS version and enforces
//! strictness rules to reject messages that are invalid for a given version.
//!
//! NOTE: This module is prepared for version-aware parsing but not yet
//! integrated into the main parsing paths. Will be connected in future work.

#![allow(dead_code)]

use crate::config::DtlsVersion;
use crate::message::{CipherSuite, ExtensionType, MessageType};

/// Context passed through message parsing to enforce version-specific rules.
#[derive(Debug, Clone, Copy)]
pub struct ParseContext {
    /// The DTLS version being used.
    pub version: DtlsVersion,
    /// The negotiated cipher suite (if any).
    pub cipher_suite: Option<CipherSuite>,
}

impl ParseContext {
    /// Create a new parse context for the given DTLS version.
    pub fn new(version: DtlsVersion) -> Self {
        Self {
            version,
            cipher_suite: None,
        }
    }

    /// Create a parse context with a cipher suite.
    pub fn with_cipher_suite(version: DtlsVersion, cipher_suite: Option<CipherSuite>) -> Self {
        Self {
            version,
            cipher_suite,
        }
    }

    /// Check if a handshake message type is allowed for this version.
    ///
    /// Returns `Ok(())` if allowed, `Err` with a description if not.
    pub fn check_message_type(&self, msg_type: MessageType) -> Result<(), &'static str> {
        match self.version {
            DtlsVersion::Dtls12 => self.check_message_type_dtls12(msg_type),
            DtlsVersion::Dtls13 => self.check_message_type_dtls13(msg_type),
        }
    }

    /// DTLS 1.2 message type validation.
    fn check_message_type_dtls12(&self, msg_type: MessageType) -> Result<(), &'static str> {
        match msg_type {
            // DTLS 1.2 allowed messages
            MessageType::HelloRequest
            | MessageType::ClientHello
            | MessageType::HelloVerifyRequest
            | MessageType::ServerHello
            | MessageType::Certificate
            | MessageType::ServerKeyExchange
            | MessageType::CertificateRequest
            | MessageType::ServerHelloDone
            | MessageType::CertificateVerify
            | MessageType::ClientKeyExchange
            | MessageType::NewSessionTicket
            | MessageType::Finished => Ok(()),

            // DTLS 1.3-only messages are rejected in DTLS 1.2
            MessageType::EncryptedExtensions => Err("EncryptedExtensions not allowed in DTLS 1.2"),
            MessageType::EndOfEarlyData => Err("EndOfEarlyData not allowed in DTLS 1.2"),
            MessageType::HelloRetryRequest => Err("HelloRetryRequest not allowed in DTLS 1.2"),
            MessageType::KeyUpdate => Err("KeyUpdate not allowed in DTLS 1.2"),
            MessageType::MessageHash => Err("MessageHash not allowed in DTLS 1.2"),

            MessageType::Unknown(_) => Ok(()), // Allow unknown for forward compatibility
        }
    }

    /// DTLS 1.3 message type validation.
    fn check_message_type_dtls13(&self, msg_type: MessageType) -> Result<(), &'static str> {
        match msg_type {
            // DTLS 1.3 allowed messages
            MessageType::ClientHello
            | MessageType::ServerHello
            | MessageType::HelloRetryRequest
            | MessageType::EncryptedExtensions
            | MessageType::Certificate
            | MessageType::CertificateRequest
            | MessageType::CertificateVerify
            | MessageType::Finished
            | MessageType::NewSessionTicket
            | MessageType::KeyUpdate
            | MessageType::MessageHash => Ok(()),

            // DTLS 1.2-only messages are rejected in DTLS 1.3
            MessageType::HelloRequest => Err("HelloRequest not allowed in DTLS 1.3"),
            MessageType::HelloVerifyRequest => Err("HelloVerifyRequest not allowed in DTLS 1.3"),
            MessageType::ServerKeyExchange => Err("ServerKeyExchange not allowed in DTLS 1.3"),
            MessageType::ServerHelloDone => Err("ServerHelloDone not allowed in DTLS 1.3"),
            MessageType::ClientKeyExchange => Err("ClientKeyExchange not allowed in DTLS 1.3"),

            // EndOfEarlyData is technically TLS 1.3 but we refuse 0-RTT
            MessageType::EndOfEarlyData => Err("EndOfEarlyData not allowed (0-RTT disabled)"),

            MessageType::Unknown(_) => Ok(()), // Allow unknown for forward compatibility
        }
    }

    /// Check if an extension type is allowed for this version.
    ///
    /// Returns `Ok(())` if allowed, `Err` with a description if not.
    pub fn check_extension_type(&self, ext_type: ExtensionType) -> Result<(), &'static str> {
        match self.version {
            DtlsVersion::Dtls12 => self.check_extension_type_dtls12(ext_type),
            DtlsVersion::Dtls13 => self.check_extension_type_dtls13(ext_type),
        }
    }

    /// DTLS 1.2 extension type validation.
    fn check_extension_type_dtls12(&self, ext_type: ExtensionType) -> Result<(), &'static str> {
        match ext_type {
            // DTLS 1.3-only extensions rejected in DTLS 1.2
            ExtensionType::PreSharedKey => Err("PreSharedKey not allowed in DTLS 1.2"),
            ExtensionType::EarlyData => Err("EarlyData not allowed in DTLS 1.2"),
            ExtensionType::SupportedVersions => Err("SupportedVersions not allowed in DTLS 1.2"),
            ExtensionType::PskKeyExchangeModes => {
                Err("PskKeyExchangeModes not allowed in DTLS 1.2")
            }
            ExtensionType::KeyShare => Err("KeyShare not allowed in DTLS 1.2"),
            ExtensionType::PostHandshakeAuth => Err("PostHandshakeAuth not allowed in DTLS 1.2"),

            // All other extensions are allowed
            _ => Ok(()),
        }
    }

    /// DTLS 1.3 extension type validation.
    fn check_extension_type_dtls13(&self, ext_type: ExtensionType) -> Result<(), &'static str> {
        match ext_type {
            // We refuse 0-RTT and PSK, so reject those extensions
            ExtensionType::EarlyData => Err("EarlyData not allowed (0-RTT disabled)"),
            ExtensionType::PreSharedKey => Err("PreSharedKey not allowed (PSK disabled)"),
            ExtensionType::PskKeyExchangeModes => {
                Err("PskKeyExchangeModes not allowed (PSK disabled)")
            }

            // DTLS 1.2-only extensions rejected in DTLS 1.3
            ExtensionType::EncryptThenMac => Err("EncryptThenMac not allowed in DTLS 1.3"),
            ExtensionType::ExtendedMasterSecret => {
                Err("ExtendedMasterSecret not allowed in DTLS 1.3")
            }

            // All other extensions are allowed
            _ => Ok(()),
        }
    }

    /// Returns true if this is DTLS 1.3.
    #[inline]
    pub fn is_dtls13(&self) -> bool {
        matches!(self.version, DtlsVersion::Dtls13)
    }

    /// Returns true if this is DTLS 1.2.
    #[inline]
    pub fn is_dtls12(&self) -> bool {
        matches!(self.version, DtlsVersion::Dtls12)
    }
}

impl Default for ParseContext {
    fn default() -> Self {
        Self::new(DtlsVersion::Dtls12)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls12_rejects_dtls13_messages() {
        let ctx = ParseContext::new(DtlsVersion::Dtls12);

        // DTLS 1.2 should reject DTLS 1.3-only messages
        assert!(ctx
            .check_message_type(MessageType::EncryptedExtensions)
            .is_err());
        assert!(ctx
            .check_message_type(MessageType::HelloRetryRequest)
            .is_err());
        assert!(ctx.check_message_type(MessageType::KeyUpdate).is_err());

        // DTLS 1.2 should accept its own messages
        assert!(ctx
            .check_message_type(MessageType::HelloVerifyRequest)
            .is_ok());
        assert!(ctx
            .check_message_type(MessageType::ServerKeyExchange)
            .is_ok());
        assert!(ctx.check_message_type(MessageType::ServerHelloDone).is_ok());
        assert!(ctx
            .check_message_type(MessageType::ClientKeyExchange)
            .is_ok());
    }

    #[test]
    fn test_dtls13_rejects_dtls12_messages() {
        let ctx = ParseContext::new(DtlsVersion::Dtls13);

        // DTLS 1.3 should reject DTLS 1.2-only messages
        assert!(ctx
            .check_message_type(MessageType::HelloVerifyRequest)
            .is_err());
        assert!(ctx
            .check_message_type(MessageType::ServerKeyExchange)
            .is_err());
        assert!(ctx
            .check_message_type(MessageType::ServerHelloDone)
            .is_err());
        assert!(ctx
            .check_message_type(MessageType::ClientKeyExchange)
            .is_err());
        assert!(ctx.check_message_type(MessageType::HelloRequest).is_err());

        // DTLS 1.3 should accept its own messages
        assert!(ctx
            .check_message_type(MessageType::EncryptedExtensions)
            .is_ok());
        assert!(ctx
            .check_message_type(MessageType::HelloRetryRequest)
            .is_ok());
    }

    #[test]
    fn test_dtls12_rejects_dtls13_extensions() {
        let ctx = ParseContext::new(DtlsVersion::Dtls12);

        // DTLS 1.2 should reject DTLS 1.3-only extensions
        assert!(ctx.check_extension_type(ExtensionType::KeyShare).is_err());
        assert!(ctx
            .check_extension_type(ExtensionType::SupportedVersions)
            .is_err());
        assert!(ctx
            .check_extension_type(ExtensionType::PreSharedKey)
            .is_err());

        // DTLS 1.2 should accept common extensions
        assert!(ctx
            .check_extension_type(ExtensionType::SupportedGroups)
            .is_ok());
        assert!(ctx
            .check_extension_type(ExtensionType::SignatureAlgorithms)
            .is_ok());
        assert!(ctx
            .check_extension_type(ExtensionType::ExtendedMasterSecret)
            .is_ok());
    }

    #[test]
    fn test_dtls13_rejects_psk_and_0rtt() {
        let ctx = ParseContext::new(DtlsVersion::Dtls13);

        // DTLS 1.3 should reject PSK and 0-RTT extensions (per our goals)
        assert!(ctx
            .check_extension_type(ExtensionType::PreSharedKey)
            .is_err());
        assert!(ctx.check_extension_type(ExtensionType::EarlyData).is_err());
        assert!(ctx
            .check_extension_type(ExtensionType::PskKeyExchangeModes)
            .is_err());

        // DTLS 1.3 should reject DTLS 1.2-only extensions
        assert!(ctx
            .check_extension_type(ExtensionType::ExtendedMasterSecret)
            .is_err());
        assert!(ctx
            .check_extension_type(ExtensionType::EncryptThenMac)
            .is_err());

        // DTLS 1.3 should accept common extensions
        assert!(ctx
            .check_extension_type(ExtensionType::SupportedGroups)
            .is_ok());
        assert!(ctx.check_extension_type(ExtensionType::KeyShare).is_ok());
    }
}
