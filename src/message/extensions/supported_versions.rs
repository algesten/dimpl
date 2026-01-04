//! SupportedVersions extension (RFC 8446 Section 4.2.1)
//!
//! In TLS/DTLS 1.3, version negotiation happens via this extension rather than
//! the legacy version field. The client sends a list of supported versions,
//! and the server responds with a single selected version.
//!
//! NOTE: This module is prepared for DTLS 1.3 but not yet fully integrated
//! into the main extension parsing paths.

use crate::buffer::Buf;
use crate::message::ProtocolVersion;
use arrayvec::ArrayVec;
use nom::number::complete::be_u8;
use nom::IResult;

/// Maximum number of versions we track in the client's supported_versions list.
const MAX_VERSIONS: usize = 8;

/// SupportedVersions extension for ClientHello.
///
/// Contains a list of protocol versions the client supports, in preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedVersionsClientHello {
    pub versions: ArrayVec<ProtocolVersion, MAX_VERSIONS>,
}

impl SupportedVersionsClientHello {
    /// Create a new SupportedVersions extension for a DTLS 1.3 ClientHello.
    /// Includes DTLS 1.3 and optionally DTLS 1.2 for backwards compatibility.
    pub fn new_dtls13(include_dtls12: bool) -> Self {
        let mut versions = ArrayVec::new();
        versions.push(ProtocolVersion::DTLS1_3);
        if include_dtls12 {
            versions.push(ProtocolVersion::DTLS1_2);
        }
        Self { versions }
    }

    /// Parse the extension data from a ClientHello.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (mut input, list_len) = be_u8(input)?;
        let mut versions = ArrayVec::new();
        let mut remaining = list_len as usize;

        while remaining >= 2 {
            let (rest, version) = ProtocolVersion::parse(input)?;
            input = rest;
            remaining -= 2;
            // Only keep known DTLS versions
            if !matches!(version, ProtocolVersion::Unknown(_)) {
                let _ = versions.try_push(version);
            }
        }

        Ok((input, Self { versions }))
    }

    /// Serialize the extension data for a ClientHello.
    pub fn serialize(&self, output: &mut Buf) {
        // Length byte: 2 bytes per version
        output.push((self.versions.len() * 2) as u8);
        for version in &self.versions {
            output.extend_from_slice(&version.as_u16().to_be_bytes());
        }
    }
}

/// SupportedVersions extension for ServerHello / HelloRetryRequest.
///
/// Contains the single version selected by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportedVersionsServerHello {
    pub selected_version: ProtocolVersion,
}

impl SupportedVersionsServerHello {
    /// Parse the extension data from a ServerHello.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, selected_version) = ProtocolVersion::parse(input)?;
        Ok((input, Self { selected_version }))
    }

    /// Serialize the extension data for a ServerHello.
    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.selected_version.as_u16().to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_supported_versions_roundtrip() {
        let ext = SupportedVersionsClientHello::new_dtls13(true);

        let mut buf = Buf::new();
        ext.serialize(&mut buf);

        // Expected: length byte + DTLS 1.3 + DTLS 1.2
        // DTLS 1.3 = 0xFEFC, DTLS 1.2 = 0xFEFD
        assert_eq!(
            &*buf,
            &[
                0x04, // 4 bytes (2 versions * 2 bytes each)
                0xFE, 0xFC, // DTLS 1.3
                0xFE, 0xFD, // DTLS 1.2
            ]
        );

        let (rest, parsed) = SupportedVersionsClientHello::parse(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.versions.len(), 2);
        assert!(parsed.versions.contains(&ProtocolVersion::DTLS1_3));
        assert!(parsed.versions.contains(&ProtocolVersion::DTLS1_2));
    }

    #[test]
    fn test_server_hello_supported_versions_roundtrip() {
        // Wire format: just the version bytes
        let buf: [u8; 2] = [0xFE, 0xFC]; // DTLS 1.3

        let (rest, parsed) = SupportedVersionsServerHello::parse(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.selected_version, ProtocolVersion::DTLS1_3);
    }

    #[test]
    fn test_dtls13_only() {
        let ext = SupportedVersionsClientHello::new_dtls13(false);

        let mut buf = Buf::new();
        ext.serialize(&mut buf);

        assert_eq!(
            &*buf,
            &[
                0x02, // 2 bytes (1 version)
                0xFE, 0xFC, // DTLS 1.3
            ]
        );

        let (rest, parsed) = SupportedVersionsClientHello::parse(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.versions.len(), 1);
        assert!(parsed.versions.contains(&ProtocolVersion::DTLS1_3));
        assert!(!parsed.versions.contains(&ProtocolVersion::DTLS1_2));
    }
}
