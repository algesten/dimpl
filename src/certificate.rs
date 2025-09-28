//! Certificate generation and formatting utilities exposed via the public `certificate` module.
//!
//! This module provides helpers to generate self-signed certificates suitable for DTLS,
//! compute fingerprints, and format them for display.

use sha2::{Digest, Sha256};
use std::fmt;

// RustCrypto-based imports for key generation and X.509 building
use der::Encode;
use elliptic_curve::rand_core::OsRng;
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use p256::SecretKey as P256SecretKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey};
use std::str::FromStr;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

/// Certificate utility error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// Invalid certificate format
    InvalidFormat,
    /// Fingerprint verification failed
    FingerprintMismatch,
    /// Certificate generation failed
    GenerationFailed,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateError::InvalidFormat => write!(f, "Invalid certificate format"),
            CertificateError::FingerprintMismatch => write!(f, "Fingerprint mismatch"),
            CertificateError::GenerationFailed => write!(f, "Certificate generation failed"),
        }
    }
}

impl std::error::Error for CertificateError {}

/// Certificate and private key pair
#[derive(Clone)]
pub struct DtlsCertificate {
    /// Certificate in DER format
    pub certificate: Vec<u8>,
    /// Private key in DER format
    pub private_key: Vec<u8>,
}

/// Generate a self-signed certificate for DTLS
pub fn generate_self_signed_certificate() -> Result<DtlsCertificate, CertificateError> {
    // Generate P-256 ECDSA key pair (pure Rust via RustCrypto)
    let mut rng = OsRng;
    let secret_key = P256SecretKey::random(&mut rng);
    let signing_key: EcdsaSigningKey = EcdsaSigningKey::from(secret_key.clone());

    // Encode private key as PKCS#8 DER
    let key_der = {
        let doc = secret_key
            .to_pkcs8_der()
            .map_err(|_| CertificateError::GenerationFailed)?;
        doc.as_bytes().to_vec()
    };

    // Subject/Issuer names: Organization and CommonName
    let subject =
        Name::from_str("O=DTLS,CN=DTLS Peer").map_err(|_| CertificateError::GenerationFailed)?;
    let issuer = subject.clone();

    // Validity: now to now + 365 days
    let validity = Validity::from_now(std::time::Duration::from_secs(365 * 24 * 60 * 60))
        .map_err(|_| CertificateError::GenerationFailed)?;

    // Public key (SPKI) from p256::PublicKey
    let public_key = secret_key.public_key();
    let spki_doc = public_key
        .to_public_key_der()
        .map_err(|_| CertificateError::GenerationFailed)?;
    let spki = SubjectPublicKeyInfoOwned::try_from(spki_doc.as_bytes())
        .map_err(|_| CertificateError::GenerationFailed)?;

    // Serial number: small fixed non-zero
    let serial = SerialNumber::from(1u64);

    // Build end-entity certificate and sign with ECDSA P-256/SHA-256
    let profile = Profile::Leaf {
        issuer,
        enable_key_agreement: false,
        enable_key_encipherment: false,
    };
    let builder = CertificateBuilder::new(profile, serial, validity, subject, spki, &signing_key)
        .map_err(|_| CertificateError::GenerationFailed)?;
    let cert = builder
        .build::<p256::ecdsa::DerSignature>()
        .map_err(|_| CertificateError::GenerationFailed)?;

    // Encode certificate to DER
    let cert_der = cert
        .to_der()
        .map_err(|_| CertificateError::GenerationFailed)?;

    Ok(DtlsCertificate {
        certificate: cert_der,
        private_key: key_der,
    })
}

/// Calculate a certificate fingerprint using SHA-256
pub fn calculate_fingerprint(cert_der: &[u8]) -> Vec<u8> {
    // Use SHA-256 to calculate the fingerprint
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().to_vec()
}

/// Format a fingerprint as a colon-separated hex string
/// Example: "AF:12:F6:..."
pub fn format_fingerprint(fingerprint: &[u8]) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<String>>()
        .join(":")
}

impl DtlsCertificate {
    /// Returns the certificate fingerprint as raw bytes.
    ///
    /// The fingerprint is computed by hashing the DER-encoded certificate
    /// with SHA-256 and is therefore 32 bytes long.
    pub fn fingerprint(&self) -> Vec<u8> {
        calculate_fingerprint(&self.certificate)
    }

    /// Returns the certificate fingerprint as a human-readable string.
    ///
    /// The string is the SHA-256 fingerprint formatted as uppercase
    /// hex byte pairs separated by colons, for example "AF:12:F6:...".
    pub fn fingerprint_str(&self) -> String {
        format_fingerprint(&self.fingerprint())
    }
}

impl fmt::Debug for DtlsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DtlsCertificate")
            .field("certificate", &self.certificate.len())
            .field("private_key", &self.private_key.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_signed_certificate() {
        // Generate a certificate
        let cert = generate_self_signed_certificate().unwrap();

        // Check certificate format
        assert!(!cert.certificate.is_empty());
        assert!(!cert.private_key.is_empty());

        // Fingerprint should be 32 bytes (SHA-256)
        assert_eq!(cert.fingerprint().len(), 32);
    }

    #[test]
    fn test_fingerprint_formatting() {
        let test_fingerprint = vec![0xAF, 0x12, 0xF6, 0x38, 0x2A];
        let formatted = format_fingerprint(&test_fingerprint);
        assert_eq!(formatted, "AF:12:F6:38:2A");

        // Test with an actual generated certificate
        let cert = generate_self_signed_certificate().unwrap();
        let formatted = format_fingerprint(&cert.fingerprint());

        // Verify the format
        assert_eq!(formatted.len(), 95); // 32 bytes * 3 - 1 = 95 (32 hex pairs with : between them)
        assert!(formatted.contains(':'));

        // Each segment should be 2 hex chars
        for segment in formatted.split(':') {
            assert_eq!(segment.len(), 2);
            // Verify it's valid hex
            assert!(u8::from_str_radix(segment, 16).is_ok());
        }
    }
}
