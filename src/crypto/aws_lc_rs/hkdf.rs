//! HKDF implementation using aws-lc-rs for TLS 1.3 key derivation.

use aws_lc_rs::hkdf::{KeyType, Prk, HKDF_SHA256, HKDF_SHA384};
use aws_lc_rs::hmac;

use crate::buffer::Buf;
use crate::crypto::provider::HkdfProvider;
use crate::message::HashAlgorithm;

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

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1
    #[test]
    fn test_hkdf_sha256_rfc5869_case1() {
        let provider = AwsLcHkdfProvider;

        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        // Expected PRK from RFC 5869
        let expected_prk =
            hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                .unwrap();

        // Expected OKM from RFC 5869
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

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

    // TLS 1.3 HKDF-Expand-Label test vector (from RFC 8448)
    #[test]
    fn test_hkdf_expand_label_tls13() {
        let provider = AwsLcHkdfProvider;

        // From RFC 8448 Simple 1-RTT Handshake
        // early_secret when using (EC)DHE with no PSK
        let zeros = [0u8; 32];
        let mut early_secret = Buf::new();
        provider
            .hkdf_extract(HashAlgorithm::SHA256, &[], &zeros, &mut early_secret)
            .unwrap();

        // derived secret = Derive-Secret(early_secret, "derived", "")
        // which is HKDF-Expand-Label(early_secret, "derived", Hash(""), 32)
        // Hash("") for SHA-256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let empty_hash =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();

        let mut derived = Buf::new();
        provider
            .hkdf_expand_label(
                HashAlgorithm::SHA256,
                &early_secret,
                b"derived",
                &empty_hash,
                &mut derived,
                32,
            )
            .unwrap();

        // This is an intermediate value, just verify it doesn't panic
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_hkdf_expand_label_structure() {
        // Test that the HkdfLabel structure is built correctly
        let provider = AwsLcHkdfProvider;

        let secret = [0u8; 32];
        let mut out = Buf::new();

        // Should not panic with valid inputs
        provider
            .hkdf_expand_label(HashAlgorithm::SHA256, &secret, b"key", &[], &mut out, 16)
            .unwrap();
        assert_eq!(out.len(), 16);

        // Should not panic with context
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
}
