use crate::message::CipherSuite;

/// DTLS configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Max amount of incoming packets to buffer before rejecting more input.
    pub max_queue_rx: usize,

    /// Max amount of outgoing packets to buffer.
    pub max_queue_tx: usize,

    /// The allowed cipher suites.
    pub cipher_suites: Vec<CipherSuite>,

    /// For a server, require a client certificate.
    ///
    /// This will cause the server to send a CertificateRequest message.
    /// Makes the server fail if the client does not send a certificate.
    pub require_client_certificate: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_queue_rx: 30,
            max_queue_tx: 10,
            cipher_suites: CipherSuite::all().to_vec(),
            require_client_certificate: true,
        }
    }
}
