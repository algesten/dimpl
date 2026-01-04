//! EncryptedExtensions message (RFC 8446 Section 4.3.1)
//!
//! In TLS/DTLS 1.3, the server sends EncryptedExtensions immediately after
//! ServerHello (but encrypted with the handshake traffic keys). This message
//! contains extensions that don't need to be in the clear (everything except
//! key_share, pre_shared_key, and supported_versions).
//!
//! NOTE: This module is prepared for DTLS 1.3 but not yet fully integrated
//! into the main handshake paths.

use crate::buffer::Buf;
use crate::message::Extension;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;

/// Maximum number of extensions in EncryptedExtensions.
const MAX_EXTENSIONS: usize = 16;

/// EncryptedExtensions message for DTLS 1.3.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedExtensions {
    pub extensions: ArrayVec<Extension, MAX_EXTENSIONS>,
}

impl EncryptedExtensions {
    /// Create a new empty EncryptedExtensions.
    pub fn new() -> Self {
        Self {
            extensions: ArrayVec::new(),
        }
    }

    /// Parse EncryptedExtensions from wire format.
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let (mut input, extensions_len) = be_u16(input)?;
        let mut extensions = ArrayVec::new();
        let mut remaining = extensions_len as usize;

        // Calculate offset for extensions (after the 2-byte length)
        let extensions_base = base_offset + 2;
        let mut ext_offset = extensions_base;

        while remaining >= 4 {
            // minimum: 2 bytes type + 2 bytes length
            let ext_start = input;
            let (rest, ext) = Extension::parse(input, ext_offset)?;
            let consumed = ext_start.len() - rest.len();
            ext_offset += consumed;
            remaining -= consumed;
            input = rest;

            let _ = extensions.try_push(ext);
        }

        // Skip any remaining bytes
        if remaining > 0 {
            let (rest, _) = take(remaining)(input)?;
            input = rest;
        }

        Ok((input, Self { extensions }))
    }

    /// Serialize EncryptedExtensions to wire format.
    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        // Calculate total extensions length
        let mut ext_len: u16 = 0;
        for ext in &self.extensions {
            ext_len += 4 + ext.extension_data(buf).len() as u16; // type(2) + len(2) + data
        }

        output.extend_from_slice(&ext_len.to_be_bytes());
        for ext in &self.extensions {
            ext.serialize(buf, output);
        }
    }
}

impl Default for EncryptedExtensions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::ExtensionType;

    #[test]
    fn test_empty_encrypted_extensions() {
        let ee = EncryptedExtensions::new();
        let source_buf = Buf::new();

        let mut output = Buf::new();
        ee.serialize(&source_buf, &mut output);

        assert_eq!(&*output, &[0x00, 0x00]); // empty extensions list

        let (rest, parsed) = EncryptedExtensions::parse(&output, 0).unwrap();
        assert!(rest.is_empty());
        assert!(parsed.extensions.is_empty());
    }

    #[test]
    fn test_encrypted_extensions_with_data() {
        // Create a source buffer with extension data
        let srtp_data = [0x00, 0x02, 0x00, 0x01, 0x00]; // use_srtp extension data
        let mut source_buf = Buf::new();
        source_buf.extend_from_slice(&srtp_data);

        let mut ee = EncryptedExtensions::new();
        ee.extensions.push(Extension {
            extension_type: ExtensionType::UseSrtp,
            extension_data_range: 0..5,
        });

        let mut output = Buf::new();
        ee.serialize(&source_buf, &mut output);

        // Expected: extensions_len(2) + type(2) + data_len(2) + data(5) = 11
        assert_eq!(output.len(), 11);

        let (rest, parsed) = EncryptedExtensions::parse(&output, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.extensions.len(), 1);
        assert_eq!(parsed.extensions[0].extension_type, ExtensionType::UseSrtp);
    }
}
