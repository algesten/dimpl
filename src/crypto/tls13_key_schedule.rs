//! TLS 1.3 Key Schedule (RFC 8446 Section 7.1)
//!
//! This module implements the TLS 1.3 key schedule, which derives all keys
//! and secrets used during the handshake and application data phases.
//!
//! The key schedule uses HKDF with the following structure:
//!
//! ```text
//!              0
//!              |
//!              v
//!    PSK ->  HKDF-Extract = Early Secret
//!              |
//!              +-----> Derive-Secret(., "ext binder" | "res binder", "")
//!              |                     = binder_key
//!              |
//!              +-----> Derive-Secret(., "c e traffic", ClientHello)
//!              |                     = client_early_traffic_secret
//!              |
//!              +-----> Derive-Secret(., "e exp master", ClientHello)
//!              |                     = early_exporter_master_secret
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!    (EC)DHE -> HKDF-Extract = Handshake Secret
//!              |
//!              +-----> Derive-Secret(., "c hs traffic",
//!              |                     ClientHello...ServerHello)
//!              |                     = client_handshake_traffic_secret
//!              |
//!              +-----> Derive-Secret(., "s hs traffic",
//!              |                     ClientHello...ServerHello)
//!              |                     = server_handshake_traffic_secret
//!              v
//!        Derive-Secret(., "derived", "")
//!              |
//!              v
//!    0 -> HKDF-Extract = Master Secret
//!              |
//!              +-----> Derive-Secret(., "c ap traffic",
//!              |                     ClientHello...server Finished)
//!              |                     = client_application_traffic_secret_0
//!              |
//!              +-----> Derive-Secret(., "s ap traffic",
//!              |                     ClientHello...server Finished)
//!              |                     = server_application_traffic_secret_0
//!              |
//!              +-----> Derive-Secret(., "exp master",
//!              |                     ClientHello...server Finished)
//!              |                     = exporter_master_secret
//!              |
//!              +-----> Derive-Secret(., "res master",
//!                                    ClientHello...client Finished)
//!                                    = resumption_master_secret
//! ```
//!
//! For dimpl's DTLS 1.3 implementation (WebRTC focus, no 0-RTT/PSK):
//! - We skip early secret derivation (no PSK support)
//! - We derive handshake secrets from ECDHE shared secret
//! - We derive application secrets for record encryption

use crate::buffer::Buf;
use crate::crypto::provider::HkdfProvider;
use crate::message::HashAlgorithm;

/// TLS 1.3 Key Schedule.
///
/// This struct tracks the key schedule state and derives secrets as needed.
/// It does not store derived secrets - those are returned to the caller.
#[derive(Debug)]
pub struct KeySchedule<'a> {
    /// The HKDF provider to use for key derivation.
    hkdf: &'a dyn HkdfProvider,
    /// The hash algorithm (determines secret sizes).
    hash: HashAlgorithm,
    /// Current secret (early, handshake, or master).
    current_secret: Buf,
}

impl<'a> KeySchedule<'a> {
    /// Create a new key schedule for DTLS 1.3 without PSK.
    ///
    /// This starts from zeros (no PSK) and immediately derives to the
    /// "derived" secret, ready for ECDHE input.
    pub fn new(hkdf: &'a dyn HkdfProvider, hash: HashAlgorithm) -> Result<Self, String> {
        let hash_len = hash.output_len();
        let zeros = vec![0u8; hash_len];

        // Early Secret = HKDF-Extract(0, 0)
        // (salt = 0, IKM = 0 since no PSK)
        let mut early_secret = Buf::new();
        hkdf.hkdf_extract(hash, &[], &zeros, &mut early_secret)?;

        // Derive-Secret(Early Secret, "derived", "") to prepare for handshake secret
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let empty_hash = Self::compute_empty_hash(hkdf, hash)?;
        let mut derived = Buf::new();
        hkdf.hkdf_expand_label_dtls13(
            hash,
            &early_secret,
            b"derived",
            &empty_hash,
            &mut derived,
            hash_len,
        )?;

        Ok(Self {
            hkdf,
            hash,
            current_secret: derived,
        })
    }

    /// Inject the ECDHE shared secret and derive handshake secrets.
    ///
    /// Returns (client_handshake_traffic_secret, server_handshake_traffic_secret).
    pub fn derive_handshake_secrets(
        &mut self,
        ecdhe_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<(Buf, Buf), String> {
        let hash_len = self.hash.output_len();

        // Handshake Secret = HKDF-Extract(derived, ECDHE)
        let mut handshake_secret = Buf::new();
        self.hkdf.hkdf_extract(
            self.hash,
            &self.current_secret,
            ecdhe_secret,
            &mut handshake_secret,
        )?;

        // client_handshake_traffic_secret = Derive-Secret(
        //     Handshake Secret, "c hs traffic", ClientHello...ServerHello)
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut client_hs_secret = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            &handshake_secret,
            b"c hs traffic",
            transcript_hash,
            &mut client_hs_secret,
            hash_len,
        )?;

        // server_handshake_traffic_secret = Derive-Secret(
        //     Handshake Secret, "s hs traffic", ClientHello...ServerHello)
        let mut server_hs_secret = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            &handshake_secret,
            b"s hs traffic",
            transcript_hash,
            &mut server_hs_secret,
            hash_len,
        )?;

        // Derive-Secret(Handshake Secret, "derived", "") for master secret
        let empty_hash = Self::compute_empty_hash(self.hkdf, self.hash)?;
        let mut derived = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            &handshake_secret,
            b"derived",
            &empty_hash,
            &mut derived,
            hash_len,
        )?;

        self.current_secret = derived;

        Ok((client_hs_secret, server_hs_secret))
    }

    /// Derive application traffic secrets after handshake completes.
    ///
    /// Returns (client_application_traffic_secret_0, server_application_traffic_secret_0).
    pub fn derive_application_secrets(
        &mut self,
        transcript_hash: &[u8],
    ) -> Result<(Buf, Buf), String> {
        let hash_len = self.hash.output_len();
        let zeros = vec![0u8; hash_len];

        // Master Secret = HKDF-Extract(derived, 0)
        let mut master_secret = Buf::new();
        self.hkdf
            .hkdf_extract(self.hash, &self.current_secret, &zeros, &mut master_secret)?;

        // client_application_traffic_secret_0 = Derive-Secret(
        //     Master Secret, "c ap traffic", ClientHello...server Finished)
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut client_app_secret = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            &master_secret,
            b"c ap traffic",
            transcript_hash,
            &mut client_app_secret,
            hash_len,
        )?;

        // server_application_traffic_secret_0 = Derive-Secret(
        //     Master Secret, "s ap traffic", ClientHello...server Finished)
        let mut server_app_secret = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            &master_secret,
            b"s ap traffic",
            transcript_hash,
            &mut server_app_secret,
            hash_len,
        )?;

        // Update current secret to master for potential exporter use
        self.current_secret = master_secret;

        Ok((client_app_secret, server_app_secret))
    }

    /// Derive exporter master secret (for DTLS-SRTP key export).
    pub fn derive_exporter_secret(&self, transcript_hash: &[u8]) -> Result<Buf, String> {
        let hash_len = self.hash.output_len();

        // exporter_master_secret = Derive-Secret(
        //     Master Secret, "exp master", ClientHello...server Finished)
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut exporter_secret = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            &self.current_secret,
            b"exp master",
            transcript_hash,
            &mut exporter_secret,
            hash_len,
        )?;

        Ok(exporter_secret)
    }

    /// TLS 1.3 Exporter (RFC 8446 Section 7.5)
    ///
    /// ```text
    /// TLS-Exporter(label, context_value, key_length) =
    ///     HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
    ///                       "exporter", Hash(context_value), key_length)
    /// ```
    ///
    /// This is used for DTLS-SRTP keying material export with label "EXTRACTOR-dtls_srtp".
    pub fn export_keying_material(
        &self,
        exporter_secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
        hash_provider: &dyn crate::crypto::provider::HashProvider,
    ) -> Result<Buf, String> {
        let hash_len = self.hash.output_len();

        // Step 1: Derive-Secret(exporter_master_secret, label, "")
        // This is HKDF-Expand-Label with empty context
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut derived_secret = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            exporter_secret,
            label,
            &[], // Empty transcript hash
            &mut derived_secret,
            hash_len,
        )?;

        // Step 2: Hash(context_value)
        let mut hash_ctx = hash_provider.create_hash(self.hash);
        hash_ctx.update(context);
        let mut context_hash = Buf::new();
        hash_ctx.clone_and_finalize(&mut context_hash);

        // Step 3: HKDF-Expand-Label(derived_secret, "exporter", Hash(context), length)
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut result = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            &derived_secret,
            b"exporter",
            &context_hash,
            &mut result,
            length,
        )?;

        Ok(result)
    }

    /// Derive traffic keys and IV from a traffic secret.
    ///
    /// Returns (key, iv).
    pub fn derive_traffic_keys(
        &self,
        traffic_secret: &[u8],
        key_len: usize,
        iv_len: usize,
    ) -> Result<(Buf, Buf), String> {
        // key = HKDF-Expand-Label(Secret, "key", "", key_length)
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut key = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            traffic_secret,
            b"key",
            &[],
            &mut key,
            key_len,
        )?;

        // iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
        let mut iv = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            traffic_secret,
            b"iv",
            &[],
            &mut iv,
            iv_len,
        )?;

        Ok((key, iv))
    }

    /// Derive traffic keys, IV, and sequence number key from a traffic secret.
    /// The sn_key is used for DTLS 1.3 record number encryption (RFC 9147 Section 4.2.3).
    ///
    /// Returns (key, iv, sn_key).
    pub fn derive_traffic_keys_dtls13(
        &self,
        traffic_secret: &[u8],
        key_len: usize,
        iv_len: usize,
    ) -> Result<(Buf, Buf, Buf), String> {
        // key = HKDF-Expand-Label(Secret, "key", "", key_length)
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut key = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            traffic_secret,
            b"key",
            &[],
            &mut key,
            key_len,
        )?;

        // iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
        let mut iv = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            traffic_secret,
            b"iv",
            &[],
            &mut iv,
            iv_len,
        )?;

        // sn_key = HKDF-Expand-Label(Secret, "sn", "", key_length)
        // Used for DTLS 1.3 record sequence number encryption
        // RFC 9147: DTLS 1.3 uses "dtls13" prefix for all labels
        let mut sn_key = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            traffic_secret,
            b"sn",
            &[],
            &mut sn_key,
            key_len,
        )?;

        Ok((key, iv, sn_key))
    }

    /// Derive the next application traffic secret for KeyUpdate (RFC 8446 Section 7.2).
    ///
    /// application_traffic_secret_N+1 =
    ///     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
    pub fn derive_next_traffic_secret(&self, current_secret: &[u8]) -> Result<Buf, String> {
        let hash_len = self.hash.output_len();

        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut next_secret = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            current_secret,
            b"traffic upd",
            &[],
            &mut next_secret,
            hash_len,
        )?;

        Ok(next_secret)
    }

    /// Derive Finished verify_data.
    ///
    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    /// verify_data = HMAC(finished_key, transcript_hash)
    pub fn derive_finished(
        &self,
        base_key: &[u8],
        transcript_hash: &[u8],
        hmac_provider: &dyn crate::crypto::provider::HmacProvider,
    ) -> Result<Buf, String> {
        let hash_len = self.hash.output_len();

        // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
        // DTLS 1.3 uses "dtls13" prefix per RFC 9147
        let mut finished_key = Buf::new();
        self.hkdf.hkdf_expand_label_dtls13(
            self.hash,
            base_key,
            b"finished",
            &[],
            &mut finished_key,
            hash_len,
        )?;

        // verify_data = HMAC(finished_key, transcript_hash)
        let mut verify_data = Buf::new();
        match self.hash {
            HashAlgorithm::SHA256 => {
                let hmac = hmac_provider.hmac_sha256(&finished_key, transcript_hash)?;
                verify_data.extend_from_slice(&hmac);
            }
            HashAlgorithm::SHA384 => {
                let hmac = hmac_provider.hmac_sha384(&finished_key, transcript_hash)?;
                verify_data.extend_from_slice(&hmac);
            }
            _ => return Err(format!("Unsupported hash for Finished: {:?}", self.hash)),
        }

        Ok(verify_data)
    }

    /// Compute hash of empty message for "derived" derivations.
    fn compute_empty_hash(_hkdf: &dyn HkdfProvider, hash: HashAlgorithm) -> Result<Buf, String> {
        // For "derived" secret, context is Hash("") which is the hash of empty string
        // SHA-256("") = e3b0c442...7852b855
        // SHA-384("") = 38b060a7...4898b95b
        let empty_hash = match hash {
            HashAlgorithm::SHA256 => {
                hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?
            }
            HashAlgorithm::SHA384 => hex_decode(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                     274edebfe76f65fbd51ad2f14898b95b",
            )?,
            _ => return Err(format!("Unsupported hash: {:?}", hash)),
        };
        let mut buf = Buf::new();
        buf.extend_from_slice(&empty_hash);
        Ok(buf)
    }
}

/// Simple hex decode helper (avoids dependency for small internal use).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| "Invalid hex character".to_string())?;
        result.push(byte);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoProvider;

    fn get_provider() -> CryptoProvider {
        #[cfg(feature = "aws-lc-rs")]
        {
            crate::crypto::aws_lc_rs::default_provider()
        }
        #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
        {
            crate::crypto::rust_crypto::default_provider()
        }
    }

    #[test]
    fn test_key_schedule_creation() {
        let provider = get_provider();
        let ks = KeySchedule::new(provider.hkdf_provider, HashAlgorithm::SHA256).unwrap();

        // Current secret should be 32 bytes (derived from early secret)
        assert_eq!(ks.current_secret.len(), 32);
    }

    #[test]
    fn test_derive_handshake_secrets() {
        let provider = get_provider();
        let mut ks = KeySchedule::new(provider.hkdf_provider, HashAlgorithm::SHA256).unwrap();

        // Fake ECDHE secret and transcript
        let ecdhe_secret = [0x42u8; 32];
        let transcript_hash = [0x01u8; 32];

        let (client_hs, server_hs) = ks
            .derive_handshake_secrets(&ecdhe_secret, &transcript_hash)
            .unwrap();

        // Both should be 32 bytes for SHA-256
        assert_eq!(client_hs.len(), 32);
        assert_eq!(server_hs.len(), 32);

        // They should be different
        assert_ne!(&*client_hs, &*server_hs);
    }

    #[test]
    fn test_derive_traffic_keys() {
        let provider = get_provider();
        let ks = KeySchedule::new(provider.hkdf_provider, HashAlgorithm::SHA256).unwrap();

        let traffic_secret = [0x55u8; 32];

        // AES-128-GCM: 16 byte key, 12 byte IV
        let (key, iv) = ks.derive_traffic_keys(&traffic_secret, 16, 12).unwrap();

        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_derive_finished() {
        let provider = get_provider();
        let ks = KeySchedule::new(provider.hkdf_provider, HashAlgorithm::SHA256).unwrap();

        let base_key = [0x33u8; 32];
        let transcript_hash = [0x44u8; 32];

        let verify_data = ks
            .derive_finished(&base_key, &transcript_hash, provider.hmac_provider)
            .unwrap();

        // Should be hash length
        assert_eq!(verify_data.len(), 32);
    }

    #[test]
    fn test_full_key_schedule() {
        let provider = get_provider();
        let mut ks = KeySchedule::new(provider.hkdf_provider, HashAlgorithm::SHA256).unwrap();

        // Simulate handshake
        let ecdhe_secret = [0x11u8; 32];
        let ch_sh_hash = [0x22u8; 32];
        let full_hash = [0x33u8; 32];

        // Derive handshake secrets
        let (client_hs, server_hs) = ks
            .derive_handshake_secrets(&ecdhe_secret, &ch_sh_hash)
            .unwrap();
        assert_eq!(client_hs.len(), 32);
        assert_eq!(server_hs.len(), 32);

        // Derive application secrets
        let (client_app, server_app) = ks.derive_application_secrets(&full_hash).unwrap();
        assert_eq!(client_app.len(), 32);
        assert_eq!(server_app.len(), 32);

        // Derive exporter secret
        let exporter = ks.derive_exporter_secret(&full_hash).unwrap();
        assert_eq!(exporter.len(), 32);
    }

    #[test]
    fn test_export_keying_material() {
        let provider = get_provider();
        let mut ks = KeySchedule::new(provider.hkdf_provider, HashAlgorithm::SHA256).unwrap();

        // Simulate handshake to get to master secret
        let ecdhe_secret = [0x11u8; 32];
        let ch_sh_hash = [0x22u8; 32];
        let full_hash = [0x33u8; 32];

        ks.derive_handshake_secrets(&ecdhe_secret, &ch_sh_hash)
            .unwrap();
        ks.derive_application_secrets(&full_hash).unwrap();

        // Derive exporter master secret
        let exporter_secret = ks.derive_exporter_secret(&full_hash).unwrap();

        // Test DTLS-SRTP export with empty context
        let dtls_srtp_label = b"EXTRACTOR-dtls_srtp";
        let exported = ks
            .export_keying_material(
                &exporter_secret,
                dtls_srtp_label,
                &[], // Empty context per RFC 5764
                60,  // SRTP_AEAD_AES_128_GCM keying material length
                provider.hash_provider,
            )
            .unwrap();

        assert_eq!(
            exported.len(),
            60,
            "Exported keying material should be 60 bytes"
        );
    }

    #[test]
    fn test_export_keying_material_with_context() {
        let provider = get_provider();
        let mut ks = KeySchedule::new(provider.hkdf_provider, HashAlgorithm::SHA256).unwrap();

        // Simulate handshake
        let ecdhe_secret = [0x11u8; 32];
        let ch_sh_hash = [0x22u8; 32];
        let full_hash = [0x33u8; 32];

        ks.derive_handshake_secrets(&ecdhe_secret, &ch_sh_hash)
            .unwrap();
        ks.derive_application_secrets(&full_hash).unwrap();

        let exporter_secret = ks.derive_exporter_secret(&full_hash).unwrap();

        // Test with non-empty context
        let label = b"test_label";
        let context = b"some context";
        let exported_with_ctx = ks
            .export_keying_material(&exporter_secret, label, context, 32, provider.hash_provider)
            .unwrap();

        // Test with empty context
        let exported_no_ctx = ks
            .export_keying_material(&exporter_secret, label, &[], 32, provider.hash_provider)
            .unwrap();

        // Results should differ based on context
        assert_eq!(exported_with_ctx.len(), 32);
        assert_eq!(exported_no_ctx.len(), 32);
        assert_ne!(
            &*exported_with_ctx, &*exported_no_ctx,
            "Different contexts should produce different keying material"
        );
    }
}
