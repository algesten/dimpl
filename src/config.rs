use std::time::Duration;

use crate::crypto::CryptoProvider;
use crate::Error;

#[cfg(feature = "aws-lc-rs")]
use crate::crypto::aws_lc_rs;

#[cfg(feature = "rust-crypto")]
use crate::crypto::rust_crypto;

/// DTLS protocol version to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DtlsVersion {
    /// DTLS 1.2 (RFC 6347)
    #[default]
    Dtls12,
    /// DTLS 1.3 (RFC 9147)
    Dtls13,
}

/// DTLS configuration
#[derive(Clone)]
pub struct Config {
    dtls_version: DtlsVersion,
    mtu: usize,
    max_queue_rx: usize,
    max_queue_tx: usize,
    require_client_certificate: bool,
    flight_start_rto: Duration,
    flight_retries: usize,
    handshake_timeout: Duration,
    crypto_provider: CryptoProvider,
    /// AEAD encryption limit (for DTLS 1.3 KeyUpdate triggering)
    aead_encryption_limit: u64,
    /// AEAD decryption failure limit (for DTLS 1.3)
    aead_decryption_failure_limit: u64,
}

impl Config {
    /// Create a new configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder {
            dtls_version: DtlsVersion::default(),
            mtu: 1150,
            max_queue_rx: 30,
            max_queue_tx: 10,
            require_client_certificate: true,
            flight_start_rto: Duration::from_millis(400),
            flight_retries: 4,
            handshake_timeout: Duration::from_secs(40),
            crypto_provider: None,
            aead_encryption_limit: DEFAULT_AEAD_ENCRYPTION_LIMIT,
            aead_decryption_failure_limit: DEFAULT_AEAD_DECRYPTION_FAILURE_LIMIT,
        }
    }

    /// DTLS protocol version.
    #[inline(always)]
    pub fn dtls_version(&self) -> DtlsVersion {
        self.dtls_version
    }

    /// Max transmission unit.
    ///
    /// The largest size UDP packets we will produce.
    #[inline(always)]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Max amount of incoming packets to buffer before rejecting more input.
    #[inline(always)]
    pub fn max_queue_rx(&self) -> usize {
        self.max_queue_rx
    }

    /// Max amount of outgoing packets to buffer.
    #[inline(always)]
    pub fn max_queue_tx(&self) -> usize {
        self.max_queue_tx
    }

    /// For a server, require a client certificate.
    ///
    /// This will cause the server to send a CertificateRequest message.
    /// Makes the server fail if the client does not send a certificate.
    #[inline(always)]
    pub fn require_client_certificate(&self) -> bool {
        self.require_client_certificate
    }

    /// Time of first retry.
    ///
    /// Every flight restarts with this value.
    /// Doubled for every retry with a ±25% jitter.
    #[inline(always)]
    pub fn flight_start_rto(&self) -> Duration {
        self.flight_start_rto
    }

    /// Max number of retries per flight.
    #[inline(always)]
    pub fn flight_retries(&self) -> usize {
        self.flight_retries
    }

    /// Timeout for the entire handshake, regardless of flights.
    #[inline(always)]
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Cryptographic provider.
    ///
    /// Provides all cryptographic operations (ciphers, key exchange, signing, etc.).
    #[inline(always)]
    pub fn crypto_provider(&self) -> &CryptoProvider {
        &self.crypto_provider
    }

    /// AEAD encryption limit for DTLS 1.3.
    ///
    /// When this many records have been encrypted with the same key,
    /// a KeyUpdate will be triggered. Default is 2^23 (~8.4 million).
    #[inline(always)]
    pub fn aead_encryption_limit(&self) -> u64 {
        self.aead_encryption_limit
    }

    /// AEAD decryption failure limit for DTLS 1.3.
    ///
    /// If this many decryption failures occur, the connection must be terminated.
    /// Default is 2^35.
    #[inline(always)]
    pub fn aead_decryption_failure_limit(&self) -> u64 {
        self.aead_decryption_failure_limit
    }
}

/// Default AEAD encryption limit: 2^23 (safety margin below RFC's 2^24.5)
pub const DEFAULT_AEAD_ENCRYPTION_LIMIT: u64 = 1 << 23;
/// Default AEAD decryption failure limit: 2^35 (safety margin below RFC's 2^36)
pub const DEFAULT_AEAD_DECRYPTION_FAILURE_LIMIT: u64 = 1 << 35;

/// Builder for DTLS configuration.
pub struct ConfigBuilder {
    dtls_version: DtlsVersion,
    mtu: usize,
    max_queue_rx: usize,
    max_queue_tx: usize,
    require_client_certificate: bool,
    flight_start_rto: Duration,
    flight_retries: usize,
    handshake_timeout: Duration,
    crypto_provider: Option<CryptoProvider>,
    aead_encryption_limit: u64,
    aead_decryption_failure_limit: u64,
}

impl ConfigBuilder {
    /// Set the max transmission unit (MTU).
    ///
    /// The largest size UDP packets we will produce.
    /// Defaults to 1150.
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the max amount of incoming packets to buffer before rejecting more input.
    ///
    /// Defaults to 30.
    pub fn max_queue_rx(mut self, max_queue_rx: usize) -> Self {
        self.max_queue_rx = max_queue_rx;
        self
    }

    /// Set the max amount of outgoing packets to buffer.
    ///
    /// Defaults to 10.
    pub fn max_queue_tx(mut self, max_queue_tx: usize) -> Self {
        self.max_queue_tx = max_queue_tx;
        self
    }

    /// Set whether to require a client certificate (for servers).
    ///
    /// This will cause the server to send a CertificateRequest message.
    /// Makes the server fail if the client does not send a certificate.
    /// Defaults to true.
    pub fn require_client_certificate(mut self, require: bool) -> Self {
        self.require_client_certificate = require;
        self
    }

    /// Set the time of first retry.
    ///
    /// Every flight restarts with this value.
    /// Doubled for every retry with a ±25% jitter.
    /// Defaults to 400ms (RFC 9147 recommended for WebRTC/DTLS-SRTP).
    pub fn flight_start_rto(mut self, rto: Duration) -> Self {
        self.flight_start_rto = rto;
        self
    }

    /// Set the max number of retries per flight.
    ///
    /// Defaults to 4.
    pub fn flight_retries(mut self, retries: usize) -> Self {
        self.flight_retries = retries;
        self
    }

    /// Set the timeout for the entire handshake, regardless of flights.
    ///
    /// Defaults to 40 seconds.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set a custom crypto provider.
    ///
    /// If not set, the default aws-lc-rs provider will be used, if the feature
    /// flag `aws-lc-rs` is enabled.
    pub fn with_crypto_provider(mut self, provider: CryptoProvider) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// Set the DTLS protocol version.
    ///
    /// Defaults to DTLS 1.2.
    pub fn dtls_version(mut self, version: DtlsVersion) -> Self {
        self.dtls_version = version;
        self
    }

    /// Set the AEAD encryption limit for DTLS 1.3.
    ///
    /// When this many records have been encrypted with the same key,
    /// a KeyUpdate will be triggered. Useful for testing KeyUpdate with
    /// a low value like 10.
    ///
    /// Defaults to 2^23 (~8.4 million records).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn aead_encryption_limit(mut self, limit: u64) -> Self {
        self.aead_encryption_limit = limit;
        self
    }

    /// Set the AEAD decryption failure limit for DTLS 1.3.
    ///
    /// If this many decryption failures occur, the connection must be terminated.
    /// Useful for testing with a low value.
    ///
    /// Defaults to 2^35.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn aead_decryption_failure_limit(mut self, limit: u64) -> Self {
        self.aead_decryption_failure_limit = limit;
        self
    }

    /// Build the configuration.
    ///
    /// This validates the crypto provider before returning the configuration.
    /// Returns `Error::ConfigError` if the provider is invalid.
    ///
    /// The crypto provider is selected in the following priority order:
    /// 1. Explicit provider set via `with_crypto_provider()`
    /// 2. Default provider installed via `CryptoProvider::install_default()`
    /// 3. AWS-LC provider (if `aws-lc-rs` feature is enabled)
    /// 4. RustCrypto provider (if `rust-crypto` feature is enabled)
    /// 5. Panic if no provider is available
    pub fn build(self) -> Result<Config, Error> {
        let crypto_provider = self
            .crypto_provider
            .or_else(|| CryptoProvider::get_default().cloned());

        #[cfg(feature = "aws-lc-rs")]
        let crypto_provider = crypto_provider.or_else(|| Some(aws_lc_rs::default_provider()));

        #[cfg(feature = "rust-crypto")]
        let crypto_provider = crypto_provider.or_else(|| Some(rust_crypto::default_provider()));

        let crypto_provider = crypto_provider.expect(
            "No crypto provider available. Either set one explicitly via \
             with_crypto_provider(), install a default via CryptoProvider::install_default(), \
             or enable the 'aws-lc-rs' or 'rust-crypto' feature.",
        );

        // Always validate the crypto provider
        crypto_provider.validate()?;

        Ok(Config {
            dtls_version: self.dtls_version,
            mtu: self.mtu,
            max_queue_rx: self.max_queue_rx,
            max_queue_tx: self.max_queue_tx,
            require_client_certificate: self.require_client_certificate,
            flight_start_rto: self.flight_start_rto,
            flight_retries: self.flight_retries,
            handshake_timeout: self.handshake_timeout,
            crypto_provider,
            aead_encryption_limit: self.aead_encryption_limit,
            aead_decryption_failure_limit: self.aead_decryption_failure_limit,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::builder()
            .build()
            .expect("Default config should always validate")
    }
}
