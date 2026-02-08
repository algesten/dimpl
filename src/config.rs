use std::time::Duration;

use crate::crypto::CryptoProvider;
use crate::Error;

#[cfg(feature = "aws-lc-rs")]
use crate::crypto::aws_lc_rs;

#[cfg(feature = "rust-crypto")]
use crate::crypto::rust_crypto;

/// DTLS configuration shared by all connections.
///
/// Build with [`Config::builder()`] or use [`Config::default()`].
#[derive(Clone)]
pub struct Config {
    mtu: usize,
    max_queue_rx: usize,
    max_queue_tx: usize,
    require_client_certificate: bool,
    use_server_cookie: bool,
    flight_start_rto: Duration,
    flight_retries: usize,
    handshake_timeout: Duration,
    crypto_provider: CryptoProvider,
    rng_seed: Option<u64>,
    aead_encryption_limit: u64,
}

impl Config {
    /// Create a new configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder {
            mtu: 1150,
            max_queue_rx: 30,
            max_queue_tx: 10,
            require_client_certificate: true,
            use_server_cookie: true,
            flight_start_rto: Duration::from_secs(1),
            flight_retries: 4,
            handshake_timeout: Duration::from_secs(40),
            crypto_provider: None,
            rng_seed: None,
            aead_encryption_limit: 1 << 23,
        }
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

    /// Whether the server sends a cookie exchange before the handshake.
    ///
    /// When true (the default), the server requires a stateless cookie
    /// roundtrip for DoS protection: HelloVerifyRequest in DTLS 1.2,
    /// HelloRetryRequest with a cookie in DTLS 1.3.
    ///
    /// When false, the server proceeds directly to ServerHello without
    /// a cookie exchange.
    #[inline(always)]
    pub fn use_server_cookie(&self) -> bool {
        self.use_server_cookie
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

    /// Optional seed for deterministic random number generation.
    ///
    /// When set, most non-cryptographic randomness (backoff jitter, TLS random bytes,
    /// AEAD nonces, cookie secrets) will be deterministic based on this seed.
    /// This is useful for testing and reproducibility.
    ///
    /// Note: Cryptographic operations (key exchange, signatures) always use
    /// secure system randomness regardless of this setting.
    #[inline(always)]
    pub fn rng_seed(&self) -> Option<u64> {
        self.rng_seed
    }

    /// Maximum number of AEAD encryptions before triggering a KeyUpdate.
    ///
    /// When the number of application-epoch ciphertext records reaches this
    /// limit, the endpoint automatically initiates a KeyUpdate to rotate keys.
    /// Defaults to 2^23 (8,388,608).
    #[inline(always)]
    pub fn aead_encryption_limit(&self) -> u64 {
        self.aead_encryption_limit
    }
}

/// Builder for [`Config`]. See each setter for defaults.
pub struct ConfigBuilder {
    mtu: usize,
    max_queue_rx: usize,
    max_queue_tx: usize,
    require_client_certificate: bool,
    use_server_cookie: bool,
    flight_start_rto: Duration,
    flight_retries: usize,
    handshake_timeout: Duration,
    crypto_provider: Option<CryptoProvider>,
    rng_seed: Option<u64>,
    aead_encryption_limit: u64,
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

    /// Set whether the server sends a cookie exchange before the handshake.
    ///
    /// When true (the default), the server requires a stateless cookie
    /// roundtrip for DoS protection: HelloVerifyRequest in DTLS 1.2,
    /// HelloRetryRequest with a cookie in DTLS 1.3.
    ///
    /// When false, the server proceeds directly to ServerHello without
    /// a cookie exchange.
    pub fn use_server_cookie(mut self, use_cookie: bool) -> Self {
        self.use_server_cookie = use_cookie;
        self
    }

    /// Set the time of first retry.
    ///
    /// Every flight restarts with this value.
    /// Doubled for every retry with a ±25% jitter.
    /// Defaults to 1 second.
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

    /// Set a seed for deterministic random number generation.
    ///
    /// When set, most non-cryptographic randomness (backoff jitter, TLS random bytes,
    /// AEAD nonces, cookie secrets) will be deterministic based on this seed.
    ///
    /// This is useful for testing and reproducibility.
    ///
    /// Note: Cryptographic operations (key exchange, signatures) always use
    /// secure system randomness regardless of this setting.
    pub fn dangerously_set_rng_seed(mut self, seed: u64) -> Self {
        self.rng_seed = Some(seed);
        self
    }

    /// Set the maximum number of AEAD encryptions before triggering a KeyUpdate.
    ///
    /// Defaults to 2^23 (8,388,608).
    pub fn aead_encryption_limit(mut self, limit: u64) -> Self {
        self.aead_encryption_limit = limit;
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
            mtu: self.mtu,
            max_queue_rx: self.max_queue_rx,
            max_queue_tx: self.max_queue_tx,
            require_client_certificate: self.require_client_certificate,
            use_server_cookie: self.use_server_cookie,
            flight_start_rto: self.flight_start_rto,
            flight_retries: self.flight_retries,
            handshake_timeout: self.handshake_timeout,
            crypto_provider,
            rng_seed: self.rng_seed,
            aead_encryption_limit: self.aead_encryption_limit,
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
