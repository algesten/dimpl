//! HKDF implementation using aws-lc-rs for TLS 1.3 key derivation.

use aws_lc_rs::hkdf::{KeyType, Prk, HKDF_SHA256, HKDF_SHA384};
use aws_lc_rs::hmac;

use crate::buffer::Buf;
use crate::crypto::provider::HkdfProvider;
use crate::types::HashAlgorithm;

/// Custom KeyType implementation for arbitrary output lengths.
struct OutputLen(usize);

impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF provider implementation using aws-lc-rs.
#[derive(Debug)]
pub(super) struct AwsLcHkdfProvider;

impl HkdfProvider for AwsLcHkdfProvider {
    fn hkdf_extract(
        &self,
        hash: HashAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        out: &mut Buf,
    ) -> Result<(), String> {
        out.clear();

        // HKDF-Extract is defined as HMAC-Hash(salt, IKM)
        // Per RFC 5869: PRK = HMAC-Hash(salt, IKM)
        // If salt is empty, use a string of HashLen zeros
        let hash_len = hash.output_len();
        let algorithm = match hash {
            HashAlgorithm::SHA256 => hmac::HMAC_SHA256,
            HashAlgorithm::SHA384 => hmac::HMAC_SHA384,
            _ => return Err(format!("Unsupported hash for HKDF: {:?}", hash)),
        };

        // If salt is empty, use zero-filled salt of hash length
        let salt_bytes: Vec<u8>;
        let actual_salt = if salt.is_empty() {
            salt_bytes = vec![0u8; hash_len];
            &salt_bytes[..]
        } else {
            salt
        };

        let key = hmac::Key::new(algorithm, actual_salt);
        let prk = hmac::sign(&key, ikm);

        out.extend_from_slice(prk.as_ref());
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

        let algorithm = match hash {
            HashAlgorithm::SHA256 => HKDF_SHA256,
            HashAlgorithm::SHA384 => HKDF_SHA384,
            _ => return Err(format!("Unsupported hash for HKDF: {:?}", hash)),
        };

        let prk = Prk::new_less_safe(algorithm, prk);
        let info_slice = [info];
        let okm = prk
            .expand(&info_slice, OutputLen(output_len))
            .map_err(|e| format!("HKDF expand failed: {:?}", e))?;

        let mut output = vec![0u8; output_len];
        okm.fill(&mut output)
            .map_err(|e| format!("HKDF fill failed: {:?}", e))?;

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
        // Build the HkdfLabel structure per RFC 8446 Section 7.1:
        //
        // struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // } HkdfLabel;
        //
        // The label must be prefixed with "tls13 " (6 bytes)

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
        // Build the HkdfLabel structure for DTLS 1.3 per RFC 9147:
        //
        // struct {
        //     uint16 length = Length;
        //     opaque label<6..255> = "dtls13" + Label;
        //     opaque context<0..255> = Context;
        // } HkdfLabel;
        //
        // Note: DTLS 1.3 uses "dtls13" prefix (6 bytes, no space) instead of "tls13 "

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
pub(super) static HKDF_PROVIDER: AwsLcHkdfProvider = AwsLcHkdfProvider;
