use std::time::Duration;

use crate::message::CipherSuite;

/// DTLS configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Max transmission unit.
    ///
    /// The largest size UDP packets we will produce.
    ///
    /// Defaults to 1150
    pub mtu: usize,

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

    /// Time of first retry.
    ///
    /// * Every flight restarts with this value.
    /// * Doubled for every retry with a ±25% jitter.
    ///
    /// Defaults to 1 second.
    pub flight_start_rto: Duration,

    /// Max number of retries per flight.
    ///
    /// The default retry timeouts are: 1s, 2s, 4s, 8s, 16s.
    ///
    /// Defaults to 5.
    pub flight_retries: usize,

    /// Timeout for the entire handshake, regardless of flights
    ///
    /// Defaults to 40s.
    pub handshake_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mtu: 1150,
            max_queue_rx: 30,
            max_queue_tx: 10,
            cipher_suites: CipherSuite::all().to_vec(),
            require_client_certificate: true,
            flight_start_rto: Duration::from_secs(1),
            flight_retries: 4,
            handshake_timeout: Duration::from_secs(40),
        }
    }
}
