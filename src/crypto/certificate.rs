// Certificate handling for DTLS 1.2 in WebRTC
// Implements certificate handling for WebRTC's security model with self-signed certificates
// and fingerprint verification

use crate::message::{Asn1Cert, Certificate};
use rand::{rngs::OsRng, RngCore};
use rcgen::{
    Certificate as RcgenCertificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tinyvec::array_vec;

/// Certificate verification error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// Invalid certificate format
    InvalidFormat,
    /// Fingerprint verification failed
    FingerprintMismatch,
    /// Certificate generation failed
    GenerationFailed,
}

/// Properly calculated certificate fingerprint using SHA-256
pub type Fingerprint = Vec<u8>;

/// Certificate store for WebRTC DTLS
pub struct TrustStore {
    /// Client certificate (self-signed)
    client_cert: Option<Vec<u8>>,

    /// Client private key
    client_key: Option<Vec<u8>>,

    /// Trusted remote fingerprints (hostname -> fingerprint)
    trusted_fingerprints: HashMap<String, Fingerprint>,
}

impl TrustStore {
    /// Create a new empty trust store
    pub fn new() -> Self {
        TrustStore {
            client_cert: None,
            client_key: None,
            trusted_fingerprints: HashMap::new(),
        }
    }

    /// Set client certificate and private key
    pub fn set_client_certificate(&mut self, cert_der: &[u8], key_der: &[u8]) {
        self.client_cert = Some(cert_der.to_vec());
        self.client_key = Some(key_der.to_vec());
    }

    /// Check if we have a client certificate available
    pub fn has_client_certificate(&self) -> bool {
        self.client_cert.is_some() && self.client_key.is_some()
    }

    /// Get client certificate as a Certificate message
    pub fn get_client_certificate(&self) -> Option<Certificate> {
        self.client_cert.as_ref().map(|cert_der| {
            // Create a Certificate with a single Asn1Cert
            let cert = Asn1Cert(cert_der.as_slice());
            let mut certs = array_vec![[Asn1Cert; 32] => cert];
            Certificate::new(certs)
        })
    }

    /// Generate a self-signed certificate for the client optimized for WebRTC
    pub fn generate_self_signed_certificate(&mut self) -> Result<Fingerprint, CertificateError> {
        // Create a key pair for the certificate
        let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)
            .map_err(|_| CertificateError::GenerationFailed)?;

        // Set up certificate parameters
        let mut params = CertificateParams::new(vec!["WebRTC DTLS Client".to_string()]);

        // Set up distinguished name
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::OrganizationName, "WebRTC Client".to_string());
        distinguished_name.push(DnType::CommonName, "DTLS Client".to_string());
        params.distinguished_name = distinguished_name;

        // Configure as end entity certificate (not a CA)
        params.is_ca = IsCa::NoCa;

        // Use the generated key pair
        params.key_pair = Some(key_pair);

        // Set validity period (1 year)
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + time::Duration::days(365);
        params.not_before = not_before;
        params.not_after = not_after;

        // Build the certificate
        let cert = RcgenCertificate::from_params(params)
            .map_err(|_| CertificateError::GenerationFailed)?;

        // Get the certificate in DER format
        let cert_der = cert
            .serialize_der()
            .map_err(|_| CertificateError::GenerationFailed)?;

        // Get the private key in DER format
        let key_der = cert.serialize_private_key_der();

        // Store the certificate and key
        self.client_cert = Some(cert_der.clone());
        self.client_key = Some(key_der);

        // Calculate and return the fingerprint
        Ok(calculate_fingerprint(&cert_der))
    }

    /// Add a trusted fingerprint for a remote host
    pub fn add_trusted_fingerprint(&mut self, hostname: &str, fingerprint: Fingerprint) {
        self.trusted_fingerprints
            .insert(hostname.to_string(), fingerprint);
    }

    /// Verify a certificate against stored fingerprints
    pub fn verify_certificate(
        &self,
        certificate_data: &[u8],
        hostname: &str,
    ) -> Result<(), CertificateError> {
        // Calculate fingerprint of the certificate
        let cert_fingerprint = calculate_fingerprint(certificate_data);

        // Verify against the trusted fingerprint for this hostname
        if let Some(trusted) = self.trusted_fingerprints.get(hostname) {
            if &cert_fingerprint == trusted {
                Ok(())
            } else {
                Err(CertificateError::FingerprintMismatch)
            }
        } else {
            // In development/testing, accept any certificate if no fingerprint was specified
            // In production, this should return an error
            Err(CertificateError::FingerprintMismatch)
        }
    }
}

/// Calculate a certificate fingerprint using SHA-256
pub fn calculate_fingerprint(cert_der: &[u8]) -> Fingerprint {
    // Use SHA-256 to calculate the fingerprint
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().to_vec()
}

/// Format a fingerprint as a colon-separated hex string (standard WebRTC format)
/// Example: "AF:12:F6:..."
pub fn format_fingerprint(fingerprint: &[u8]) -> String {
    fingerprint
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<String>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_verification() {
        let mut trust_store = TrustStore::new();

        // Create a test certificate
        let cert = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let fingerprint = calculate_fingerprint(&cert);

        // Register the fingerprint
        trust_store.add_trusted_fingerprint("example.com", fingerprint.clone());

        // Verification should succeed with matching fingerprint
        assert!(trust_store.verify_certificate(&cert, "example.com").is_ok());

        // Verification should fail with different certificate
        let wrong_cert = vec![0x06, 0x07, 0x08, 0x09, 0x0A];
        assert!(trust_store
            .verify_certificate(&wrong_cert, "example.com")
            .is_err());
    }

    #[test]
    fn test_self_signed_certificate() {
        let mut trust_store = TrustStore::new();

        // Generate a certificate
        let fingerprint = trust_store.generate_self_signed_certificate().unwrap();

        // Should have client certificate
        assert!(trust_store.has_client_certificate());

        // Should be able to get certificate as Certificate message
        assert!(trust_store.get_client_certificate().is_some());

        // Fingerprint should be 32 bytes (SHA-256)
        assert_eq!(fingerprint.len(), 32);
    }

    #[test]
    fn test_fingerprint_formatting() {
        let test_fingerprint = vec![0xAF, 0x12, 0xF6, 0x38, 0x2A];
        let formatted = format_fingerprint(&test_fingerprint);
        assert_eq!(formatted, "AF:12:F6:38:2A");

        // Test with an actual generated certificate
        let mut trust_store = TrustStore::new();
        let fingerprint = trust_store.generate_self_signed_certificate().unwrap();
        let formatted = format_fingerprint(&fingerprint);

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
