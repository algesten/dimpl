//! HKDF implementation using RustCrypto crates for TLS 1.3 key derivation.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

use crate::buffer::Buf;
use crate::crypto::provider::HkdfProvider;
use crate::message::HashAlgorithm;

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

    // RFC 5869 Test Case 1
    #[test]
    fn test_hkdf_sha256_rfc5869_case1() {
        let provider = RustCryptoHkdfProvider;

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
}
