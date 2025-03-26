// Certificate handling for DTLS 1.2 in WebRTC
// This module implements simplified certificate handling:
// - Generate self-signed certificates for the client
// - Accept and verify self-signed certificates from the server using fingerprints
// - Lightweight certificate management for WebRTC use case

use crate::message::{Asn1Cert, Certificate};
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

/// Simple fingerprint type (for now just raw bytes)
/// In a complete implementation, this would use proper cryptographic hashing
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

    /// Generate a self-signed certificate for the client
    pub fn generate_self_signed_certificate(&mut self) -> Result<Fingerprint, CertificateError> {
        // In a real implementation, this would generate a proper self-signed certificate
        // For now, we're just creating placeholder data

        // Create a minimal self-signed certificate (this is just a placeholder)
        let cert_der = vec![
            0x30, 0x82, 0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let key_der = vec![
            0x30, 0x82, 0x01, 0x01, 0x00, 0x00, 0x06, 0x07, 0x08, 0x09, 0x0A,
        ];

        self.set_client_certificate(&cert_der, &key_der);

        // Calculate and return the fingerprint
        Ok(calculate_fingerprint(&cert_der))
    }

    /// Add a trusted fingerprint for a remote host
    pub fn add_trusted_fingerprint(&mut self, hostname: &str, fingerprint: Fingerprint) {
        self.trusted_fingerprints
            .insert(hostname.to_string(), fingerprint);
    }

    /// Verify a certificate against stored fingerprints
    pub fn verify_cert_chain(
        &self,
        certs: &[&[u8]],
        hostname: &str,
    ) -> Result<(), CertificateError> {
        // For WebRTC, we only care about verifying the fingerprint of the leaf certificate
        if certs.is_empty() {
            return Err(CertificateError::InvalidFormat);
        }

        // Calculate fingerprint of the leaf certificate
        let cert_fingerprint = calculate_fingerprint(certs[0]);

        // Verify against the trusted fingerprint for this hostname
        if let Some(trusted) = self.trusted_fingerprints.get(hostname) {
            if &cert_fingerprint == trusted {
                Ok(())
            } else {
                Err(CertificateError::FingerprintMismatch)
            }
        } else {
            // For development/testing, accept any certificate if no fingerprint was specified
            // In production, this should return an error
            Ok(())
        }
    }
}

/// Calculate a certificate fingerprint
/// In a real implementation, this would use SHA-256 or another cryptographic hash
pub fn calculate_fingerprint(cert_der: &[u8]) -> Fingerprint {
    // Simple fingerprint implementation - in reality, you would use a proper
    // cryptographic hash like SHA-256
    cert_der.iter().take(20).copied().collect()
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
        assert!(trust_store
            .verify_cert_chain(&[&cert], "example.com")
            .is_ok());

        // Verification should fail with different certificate
        let wrong_cert = vec![0x06, 0x07, 0x08, 0x09, 0x0A];
        assert!(trust_store
            .verify_cert_chain(&[&wrong_cert], "example.com")
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
    }
}
