//! HKDF implementation using RustCrypto crates for TLS 1.3 key derivation.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

use crate::buffer::Buf;
use crate::crypto::provider::HkdfProvider;
use crate::types::HashAlgorithm;

/// HKDF provider implementation using RustCrypto.
#[derive(Debug)]
pub(super) struct RustCryptoHkdfProvider;

impl HkdfProvider for RustCryptoHkdfProvider {
    fn hkdf_extract(
        &self,
        hash: HashAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        out: &mut Buf,
    ) -> Result<(), String> {
        out.clear();

        match hash {
            HashAlgorithm::SHA256 => {
                let salt = if salt.is_empty() { None } else { Some(salt) };
                let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
                out.extend_from_slice(prk.as_slice());
            }
            HashAlgorithm::SHA384 => {
                let salt = if salt.is_empty() { None } else { Some(salt) };
                let (prk, _) = Hkdf::<Sha384>::extract(salt, ikm);
                out.extend_from_slice(prk.as_slice());
            }
            _ => return Err(format!("Unsupported hash for HKDF: {:?}", hash)),
        }

        Ok(())
    }

    fn hkdf_expand(
        &self,
        hash: HashAlgorithm,
        prk: &[u8],
        info: &[u8],
        out: &mut Buf,
        output_len: usize,
    ) -> Result<(), String> {
        out.clear();
        let mut output = vec![0u8; output_len];

        match hash {
            HashAlgorithm::SHA256 => {
                let hk =
                    Hkdf::<Sha256>::from_prk(prk).map_err(|e| format!("Invalid PRK: {:?}", e))?;
                hk.expand(info, &mut output)
                    .map_err(|e| format!("HKDF expand failed: {:?}", e))?;
            }
            HashAlgorithm::SHA384 => {
                let hk =
                    Hkdf::<Sha384>::from_prk(prk).map_err(|e| format!("Invalid PRK: {:?}", e))?;
                hk.expand(info, &mut output)
                    .map_err(|e| format!("HKDF expand failed: {:?}", e))?;
            }
            _ => return Err(format!("Unsupported hash for HKDF: {:?}", hash)),
        }

        out.extend_from_slice(&output);
        Ok(())
    }

    fn hkdf_expand_label(
        &self,
        hash: HashAlgorithm,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut Buf,
        output_len: usize,
    ) -> Result<(), String> {
        // Build the HkdfLabel structure per RFC 8446 Section 7.1
        let full_label_len = 6 + label.len(); // "tls13 " + label

        if full_label_len > 255 {
            return Err("Label too long for HKDF-Expand-Label".to_string());
        }
        if context.len() > 255 {
            return Err("Context too long for HKDF-Expand-Label".to_string());
        }
        if output_len > 65535 {
            return Err("Output length too large for HKDF-Expand-Label".to_string());
        }

        // Build the info (HkdfLabel)
        let info_len = 2 + 1 + full_label_len + 1 + context.len();
        let mut info = Vec::with_capacity(info_len);

        // uint16 length
        info.extend_from_slice(&(output_len as u16).to_be_bytes());

        // opaque label<7..255> = "tls13 " + Label
        info.push(full_label_len as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);

        // opaque context<0..255>
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        // Now do regular HKDF-Expand
        self.hkdf_expand(hash, secret, &info, out, output_len)
    }

    fn hkdf_expand_label_dtls13(
        &self,
        hash: HashAlgorithm,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut Buf,
        output_len: usize,
    ) -> Result<(), String> {
        // Build the HkdfLabel structure for DTLS 1.3 per RFC 9147
        let full_label_len = 6 + label.len(); // "dtls13" + label

        if full_label_len > 255 {
            return Err("Label too long for HKDF-Expand-Label".to_string());
        }
        if context.len() > 255 {
            return Err("Context too long for HKDF-Expand-Label".to_string());
        }
        if output_len > 65535 {
            return Err("Output length too large for HKDF-Expand-Label".to_string());
        }

        // Build the info (HkdfLabel)
        let info_len = 2 + 1 + full_label_len + 1 + context.len();
        let mut info = Vec::with_capacity(info_len);

        // uint16 length
        info.extend_from_slice(&(output_len as u16).to_be_bytes());

        // opaque label<6..255> = "dtls13" + Label
        info.push(full_label_len as u8);
        info.extend_from_slice(b"dtls13");
        info.extend_from_slice(label);

        // opaque context<0..255>
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        // Now do regular HKDF-Expand
        self.hkdf_expand(hash, secret, &info, out, output_len)
    }
}

/// Static instance of the HKDF provider.
pub(super) static HKDF_PROVIDER: RustCryptoHkdfProvider = RustCryptoHkdfProvider;

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1 - Basic test case with SHA-256
    #[test]
    fn test_hkdf_sha256_rfc5869_case1() {
        let provider = RustCryptoHkdfProvider;

        // IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
        let ikm = [0x0b; 22];

        // salt = 0x000102030405060708090a0b0c (13 bytes)
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];

        // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        // Expected PRK (32 bytes)
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];

        // Expected OKM (42 bytes)
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        // Test extract
        let mut prk = Buf::new();
        provider
            .hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
            .unwrap();
        assert_eq!(&*prk, &expected_prk[..]);

        // Test expand
        let mut okm = Buf::new();
        provider
            .hkdf_expand(HashAlgorithm::SHA256, &prk, &info, &mut okm, 42)
            .unwrap();
        assert_eq!(&*okm, &expected_okm[..]);
    }

    // RFC 5869 Test Case 2 - Longer inputs/outputs with SHA-256
    #[test]
    fn test_hkdf_sha256_rfc5869_case2() {
        let provider = RustCryptoHkdfProvider;

        // IKM = 0x000102...4f (80 bytes)
        let ikm: Vec<u8> = (0x00..=0x4f).collect();

        // salt = 0x606162...af (80 bytes)
        let salt: Vec<u8> = (0x60..=0xaf).collect();

        // info = 0xb0b1b2...ff (80 bytes)
        let info: Vec<u8> = (0xb0..=0xff).collect();

        // Expected PRK (32 bytes)
        let expected_prk = [
            0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35,
            0xb4, 0x5c, 0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40,
            0xc1, 0x5f, 0xc2, 0x44,
        ];

        // Expected OKM (82 bytes)
        let expected_okm = [
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
            0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
            0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
            0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
            0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
        ];

        // Test extract
        let mut prk = Buf::new();
        provider
            .hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
            .unwrap();
        assert_eq!(&*prk, &expected_prk[..]);

        // Test expand
        let mut okm = Buf::new();
        provider
            .hkdf_expand(HashAlgorithm::SHA256, &prk, &info, &mut okm, 82)
            .unwrap();
        assert_eq!(&*okm, &expected_okm[..]);
    }

    // RFC 5869 Test Case 3 - Zero-length salt and info with SHA-256
    #[test]
    fn test_hkdf_sha256_rfc5869_case3() {
        let provider = RustCryptoHkdfProvider;

        // IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
        let ikm = [0x0b; 22];

        // salt = empty
        let salt: [u8; 0] = [];

        // info = empty
        let info: [u8; 0] = [];

        // Expected PRK (32 bytes)
        let expected_prk = [
            0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64,
            0x8b, 0xdf, 0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c,
            0x29, 0x3c, 0xcb, 0x04,
        ];

        // Expected OKM (42 bytes)
        let expected_okm = [
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
        ];

        // Test extract
        let mut prk = Buf::new();
        provider
            .hkdf_extract(HashAlgorithm::SHA256, &salt, &ikm, &mut prk)
            .unwrap();
        assert_eq!(&*prk, &expected_prk[..]);

        // Test expand
        let mut okm = Buf::new();
        provider
            .hkdf_expand(HashAlgorithm::SHA256, &prk, &info, &mut okm, 42)
            .unwrap();
        assert_eq!(&*okm, &expected_okm[..]);
    }

    // Test HKDF-Expand-Label structure is built correctly
    #[test]
    fn test_hkdf_expand_label_basic() {
        let provider = RustCryptoHkdfProvider;
        let secret = [0u8; 32];
        let mut out = Buf::new();

        // Should succeed with valid inputs
        provider
            .hkdf_expand_label(HashAlgorithm::SHA256, &secret, b"key", &[], &mut out, 16)
            .unwrap();
        assert_eq!(out.len(), 16);

        // Should succeed with context
        provider
            .hkdf_expand_label(
                HashAlgorithm::SHA256,
                &secret,
                b"iv",
                &[1, 2, 3, 4],
                &mut out,
                12,
            )
            .unwrap();
        assert_eq!(out.len(), 12);
    }

    // Test DTLS 1.3 expand label
    #[test]
    fn test_hkdf_expand_label_dtls13_basic() {
        let provider = RustCryptoHkdfProvider;
        let secret = [0u8; 32];
        let mut out = Buf::new();

        // Should succeed with valid inputs
        provider
            .hkdf_expand_label_dtls13(HashAlgorithm::SHA256, &secret, b"key", &[], &mut out, 16)
            .unwrap();
        assert_eq!(out.len(), 16);

        // TLS 1.3 and DTLS 1.3 with same inputs should produce different outputs
        // due to different label prefixes ("tls13 " vs "dtls13")
        let mut tls_out = Buf::new();
        let mut dtls_out = Buf::new();

        provider
            .hkdf_expand_label(
                HashAlgorithm::SHA256,
                &secret,
                b"key",
                &[],
                &mut tls_out,
                16,
            )
            .unwrap();
        provider
            .hkdf_expand_label_dtls13(
                HashAlgorithm::SHA256,
                &secret,
                b"key",
                &[],
                &mut dtls_out,
                16,
            )
            .unwrap();

        assert_ne!(&*tls_out, &*dtls_out);
    }
}
