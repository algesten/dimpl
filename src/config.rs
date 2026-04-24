use std::fmt;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use crate::Error;
use crate::crypto::{CryptoProvider, SupportedDtls12CipherSuite};
use crate::crypto::{SupportedDtls13CipherSuite, SupportedKxGroup};
use crate::dtls12::message::Dtls12CipherSuite;
use crate::types::{Dtls13CipherSuite, NamedGroup};

/// Callback for resolving PSK identities to shared secrets.
///
/// Implement this trait and provide it via [`ConfigBuilder::with_psk_client`]
/// or [`ConfigBuilder::with_psk_server`] to enable PSK cipher suites.
pub trait PskResolver: Send + Sync + UnwindSafe + RefUnwindSafe {
    /// Look up a pre-shared key by the peer's identity.
    ///
    /// Returns the shared secret bytes, or `None` if the identity is unknown.
    fn resolve(&self, identity: &[u8]) -> Option<Vec<u8>>;
}

/// PSK configuration for a DTLS endpoint.
///
/// Use [`Psk::Client`] for endpoints that initiate PSK handshakes (send identity),
/// and [`Psk::Server`] for endpoints that resolve incoming identities.
///
/// `#[non_exhaustive]` so new variants (e.g. DTLS 1.3 external PSKs) or new
/// fields can be added without a major version bump.
#[derive(Clone)]
#[non_exhaustive]
pub enum Psk {
    /// Client-side PSK: sends `identity` during handshake, uses `resolver`
    /// to look up the shared secret.
    #[non_exhaustive]
    Client {
        /// The identity to send to the server.
        identity: Vec<u8>,
        /// Resolver for looking up shared secrets.
        resolver: Arc<dyn PskResolver>,
    },
    /// Server-side PSK: optionally sends a `hint` to help the client choose
    /// an identity, uses `resolver` to look up secrets by client identity.
    #[non_exhaustive]
    Server {
        /// Optional hint sent to the client in ServerKeyExchange.
        hint: Option<Vec<u8>>,
        /// Resolver for looking up shared secrets.
        resolver: Arc<dyn PskResolver>,
    },
}

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
    dtls12_cipher_suites: Option<Vec<Dtls12CipherSuite>>,
    dtls13_cipher_suites: Option<Vec<Dtls13CipherSuite>>,
    kx_groups: Option<Vec<NamedGroup>>,
    psk: Option<Psk>,
    connection_id: Option<Vec<u8>>,
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
            dtls12_cipher_suites: None,
            dtls13_cipher_suites: None,
            kx_groups: None,
            psk: None,
            connection_id: None,
        }
    }

    /// Max transmission unit (coalescing target for outbound datagrams).
    ///
    /// The implementation packs multiple DTLS records into a single
    /// outbound datagram up to this size, and sizes encrypted handshake
    /// fragments so each handshake record fits. Application-data writes
    /// that exceed one record's plaintext capacity
    /// (`DTLS12_MAX_PLAINTEXT_LEN = 2^14` bytes) are rejected with
    /// [`Error::Oversized`]. Handshake fragmentation returns
    /// [`Error::MtuTooSmall`] when the configured MTU cannot fit even a
    /// single record of the required overhead (record header, negotiated
    /// CID bytes, AEAD, handshake header).
    ///
    /// This is **not** a hard ceiling on every individual record: a
    /// single outbound application-data record may exceed MTU when the
    /// plaintext plus DTLS + AEAD + CID overhead is larger than MTU,
    /// because `DTLS12_MAX_PLAINTEXT_LEN` (2^14) may be bigger than a
    /// caller-chosen MTU. Set MTU above `DTLS12_MAX_PLAINTEXT_LEN +
    /// record overhead` if strict per-datagram sizing matters, or
    /// fragment application data caller-side.
    ///
    /// [`Error::Oversized`]: crate::Error::Oversized
    /// [`Error::MtuTooSmall`]: crate::Error::MtuTooSmall
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
    ///
    /// Applies only to certificate-authenticated cipher suites. For RFC 4279
    /// PSK suites the client never sends a certificate, so this flag has no
    /// effect on a negotiated PSK handshake.
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

    /// PSK configuration, if any.
    pub fn psk(&self) -> Option<&Psk> {
        self.psk.as_ref()
    }

    /// PSK identity for the client to send during handshake.
    pub fn psk_identity(&self) -> Option<&[u8]> {
        match &self.psk {
            Some(Psk::Client { identity, .. }) => Some(identity),
            _ => None,
        }
    }

    /// PSK identity hint for the server to send during handshake.
    pub fn psk_identity_hint(&self) -> Option<&[u8]> {
        match &self.psk {
            Some(Psk::Server { hint, .. }) => hint.as_deref(),
            _ => None,
        }
    }

    /// PSK resolver for looking up shared secrets by identity.
    pub fn psk_resolver(&self) -> Option<&dyn PskResolver> {
        match &self.psk {
            Some(Psk::Client { resolver, .. } | Psk::Server { resolver, .. }) => {
                Some(resolver.as_ref())
            }
            None => None,
        }
    }

    /// Connection ID to advertise to the peer (RFC 9146, DTLS 1.2 only).
    ///
    /// When set on a DTLS 1.2 or DTLS 1.2 PSK association, the endpoint
    /// offers CID negotiation during the handshake and the peer includes
    /// this CID in encrypted records it sends to us, allowing
    /// demultiplexing by CID instead of the UDP 5-tuple.
    ///
    /// **Version scope.** The current CID implementation is RFC 9146
    /// (DTLS 1.2). RFC 9147 §9 defines a separate DTLS 1.3 CID
    /// mechanism (`NewConnectionId` / `RequestConnectionId`
    /// post-handshake messages, unified-header CID bit) which dimpl does
    /// not implement. A `with_connection_id` value configured on a
    /// [`Dtls::new_13`] association is silently ignored: no CID
    /// negotiation, no `Output::ConnectionId` event, no `tls12_cid`
    /// records on the wire. Use `with_connection_id` on the explicit
    /// DTLS 1.2 / DTLS 1.2 PSK constructors (`Dtls::new_12`,
    /// `Dtls::new_12_psk`); on `Dtls::new_auto` the config only takes
    /// effect if the auto-sense path resolves to DTLS 1.2.
    ///
    /// An empty slice is valid — per RFC 9146 §3 it negotiates the
    /// extension but leaves that direction on legacy RFC 6347 framing.
    ///
    /// [`Dtls::new_13`]: crate::Dtls::new_13
    pub fn connection_id(&self) -> Option<&[u8]> {
        self.connection_id.as_deref()
    }

    /// Allowed DTLS 1.2 cipher suites, filtered by the config's allow-list.
    ///
    /// Returns all provider-supported DTLS 1.2 cipher suites when no filter
    /// is set. When a filter is set via the builder's `dtls12_cipher_suites`
    /// method, only suites in both the provider and the filter are returned.
    ///
    /// PSK cipher suites are excluded when no [`PskResolver`] is configured,
    /// preventing a certificate-mode endpoint from negotiating a PSK suite
    /// and inadvertently skipping certificate authentication.
    pub fn dtls12_cipher_suites(
        &self,
    ) -> impl Iterator<Item = &'static dyn SupportedDtls12CipherSuite> + '_ {
        let filter = self.dtls12_cipher_suites.as_ref();
        let has_psk = self.psk.is_some();
        self.crypto_provider
            .supported_cipher_suites()
            .filter(move |cs| match filter {
                Some(list) => list.contains(&cs.suite()),
                None => true,
            })
            .filter(move |cs| has_psk || !cs.suite().is_psk())
    }

    /// Allowed DTLS 1.3 cipher suites, filtered by the config's allow-list.
    ///
    /// Returns all provider DTLS 1.3 cipher suites when no filter is set.
    /// When a filter is set via the builder's `dtls13_cipher_suites` method,
    /// only suites in both the provider and the filter are returned.
    pub fn dtls13_cipher_suites(
        &self,
    ) -> impl Iterator<Item = &'static dyn SupportedDtls13CipherSuite> + '_ {
        let filter = self.dtls13_cipher_suites.as_ref();
        self.crypto_provider
            .dtls13_cipher_suites
            .iter()
            .copied()
            .filter(move |cs| match filter {
                Some(list) => list.contains(&cs.suite()),
                None => true,
            })
    }

    /// Allowed key exchange groups, filtered by the config's allow-list.
    ///
    /// Returns all provider-supported key exchange groups when no filter
    /// is set. When a filter is set via the builder's `kx_groups` method,
    /// only groups in both the provider and the filter are returned.
    pub fn kx_groups(&self) -> impl Iterator<Item = &'static dyn SupportedKxGroup> + '_ {
        let filter = self.kx_groups.as_ref();
        self.crypto_provider
            .supported_kx_groups()
            .filter(move |kx| match filter {
                Some(list) => list.contains(&kx.name()),
                None => true,
            })
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
    dtls12_cipher_suites: Option<Vec<Dtls12CipherSuite>>,
    dtls13_cipher_suites: Option<Vec<Dtls13CipherSuite>>,
    kx_groups: Option<Vec<NamedGroup>>,
    psk: Option<Psk>,
    connection_id: Option<Vec<u8>>,
}

impl ConfigBuilder {
    /// Set the max transmission unit (MTU).
    ///
    /// This is a **coalescing target** for outbound datagrams, not a hard
    /// per-record ceiling — see [`Config::mtu`] for the full contract.
    /// Handshake fragmentation honors this bound (returning
    /// [`Error::MtuTooSmall`] if record overhead exceeds it), but a single
    /// application-data record whose plaintext + CID + AEAD overhead
    /// exceeds MTU will still be emitted; the only hard cap on
    /// application data is [`Error::Oversized`] at
    /// `DTLS12_MAX_PLAINTEXT_LEN = 2^14`.
    ///
    /// Defaults to 1150.
    ///
    /// [`Config::mtu`]: crate::Config::mtu
    /// [`Error::MtuTooSmall`]: crate::Error::MtuTooSmall
    /// [`Error::Oversized`]: crate::Error::Oversized
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
    ///
    /// Applies only to certificate-authenticated cipher suites. For RFC 4279
    /// PSK suites the client never sends a certificate, so this flag has no
    /// effect on a negotiated PSK handshake; no opt-out is required when
    /// combining this builder with [`with_psk_server`](Self::with_psk_server).
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

    /// Restrict which DTLS 1.2 cipher suites are offered and accepted.
    ///
    /// Only cipher suites present in both this list and the provider will
    /// be used. Passing an empty slice disables DTLS 1.2 (as long as
    /// DTLS 1.3 suites remain).
    ///
    /// By default all provider-supported DTLS 1.2 cipher suites are used.
    pub fn dtls12_cipher_suites(mut self, suites: &[Dtls12CipherSuite]) -> Self {
        self.dtls12_cipher_suites = Some(suites.to_vec());
        self
    }

    /// Restrict which DTLS 1.3 cipher suites are offered and accepted.
    ///
    /// Only cipher suites present in both this list and the provider will
    /// be used. Passing an empty slice disables DTLS 1.3 (as long as
    /// DTLS 1.2 suites remain).
    ///
    /// By default all provider DTLS 1.3 cipher suites are used.
    pub fn dtls13_cipher_suites(mut self, suites: &[Dtls13CipherSuite]) -> Self {
        self.dtls13_cipher_suites = Some(suites.to_vec());
        self
    }

    /// Restrict which key exchange groups are offered and accepted.
    ///
    /// Only groups present in both this list and the provider will be
    /// used. Order determines preference (first = most preferred).
    ///
    /// By default all provider-supported key exchange groups are used.
    pub fn kx_groups(mut self, groups: &[NamedGroup]) -> Self {
        self.kx_groups = Some(groups.to_vec());
        self
    }

    /// Configure PSK for a client endpoint.
    ///
    /// The `identity` is sent to the server during the handshake.
    /// The `resolver` looks up the shared secret by identity.
    pub fn with_psk_client(mut self, identity: Vec<u8>, resolver: Arc<dyn PskResolver>) -> Self {
        self.psk = Some(Psk::Client { identity, resolver });
        self
    }

    /// Configure PSK for a server endpoint.
    ///
    /// The optional `hint` is sent to the client in ServerKeyExchange.
    /// The `resolver` looks up the shared secret by client identity.
    pub fn with_psk_server(
        mut self,
        hint: Option<Vec<u8>>,
        resolver: Arc<dyn PskResolver>,
    ) -> Self {
        self.psk = Some(Psk::Server { hint, resolver });
        self
    }

    /// Set the Connection ID (CID) to advertise to the peer (RFC 9146).
    ///
    /// The peer includes this CID in encrypted records it sends to us, so
    /// roaming peers stay addressable across 5-tuple changes. CID must be
    /// at most 255 bytes.
    ///
    /// Per RFC 9146 §3, an **empty** CID (`Vec::new()`) negotiates the
    /// extension but leaves this direction on legacy RFC 6347 framing; a
    /// non-empty value engages `tls12_cid` framing for records sent to us.
    /// The per-direction choice is independent: the peer may choose the
    /// opposite framing for records we send to it.
    ///
    /// `Output::ConnectionId` fires once on successful negotiation in
    /// **either** case — including the zero-length case, where the
    /// emitted slice is empty (`&[]`). Empty means "the peer will send
    /// us records with legacy (non-`tls12_cid`) framing", so the emitted
    /// bytes are not a valid routing key for that direction; do not use
    /// them as a load-balancer key, since every empty-CID association
    /// would route to the same bucket.
    ///
    /// When negotiation completes, the state machine emits
    /// [`Output::ConnectionId`][output_cid] once. Poll for it in the
    /// standard event loop:
    ///
    /// ```
    /// # #[cfg(feature = "rcgen")]
    /// # {
    /// use std::sync::Arc;
    /// use std::time::Instant;
    ///
    /// use dimpl::{certificate, Config, Dtls, Output};
    ///
    /// let config = Config::builder()
    ///     .with_connection_id(b"my-cid".to_vec())
    ///     .build()
    ///     .unwrap();
    /// let cert = certificate::generate_self_signed_certificate().unwrap();
    /// let mut dtls = Dtls::new_12(Arc::new(config), cert, Instant::now());
    /// dtls.set_active(true); // client role
    ///
    /// // Standard poll-to-Timeout loop: the caller's buffer must be large
    /// // enough for the CID bytes; if not, `poll_output` defers and re-emits
    /// // the event on the next call.
    /// let mut buf = vec![0u8; 2048];
    /// loop {
    ///     match dtls.poll_output(&mut buf) {
    ///         Output::Packet(_p) => { /* send on UDP socket */ }
    ///         Output::ConnectionId(cid) => {
    ///             // Peer will place these bytes in the CID field of its
    ///             // encrypted records. Use them to route incoming
    ///             // datagrams to this session — see "Peer address
    ///             // updates" below for the safe integration pattern.
    ///             let _ = cid;
    ///         }
    ///         Output::Timeout(_) => break,
    ///         _ => {}
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// ## Peer address updates (RFC 9146 §6)
    ///
    /// `Output::ConnectionId` is a **routing hint, not authorization to
    /// change the send address.** dimpl is Sans-IO and never observes
    /// the source address of incoming datagrams, so it cannot enforce
    /// the RFC 9146 §6 conditions for replacing the peer address. Those
    /// are the caller's responsibility:
    ///
    /// 1. **Lookup, then authenticate.** A visible CID match in an
    ///    incoming datagram only routes the bytes to a candidate
    ///    association. `Dtls::handle_packet` returning `Ok(())` is **not**
    ///    an authentication signal: per RFC 6347 §4.1.2.7 / RFC 9146 §6,
    ///    invalid records (tampered CID, failed AEAD, truncated header,
    ///    replay, bogus inner type) are silently discarded and still
    ///    surface as `Ok(())` from `handle_packet`. Before authorizing
    ///    an address update the caller must observe an
    ///    authentication-positive signal such as new `ApplicationData`,
    ///    handshake-state progression, or a successful keying-material
    ///    export — not `Ok(())` alone.
    /// 2. **Newer than newest.** Per RFC 9146 §6, an authenticated CID
    ///    record may update the peer address only if its (epoch,
    ///    sequence_number) is strictly greater than the newest
    ///    authenticated record received so far. Stale CID records seen
    ///    from a different source do not authorize an update.
    /// 3. **Reachability strategy.** Apply your own address-validation
    ///    policy (e.g. a probe round-trip) before committing the new
    ///    address for outbound traffic, especially for unattended IoT
    ///    deployments.
    ///
    /// Concrete pattern: sample
    /// [`Dtls::newest_authenticated_record`] *before* `handle_packet`,
    /// deliver the datagram, poll to `Timeout`, and re-sample the
    /// accessor. A strictly-increased `(epoch, sequence_number)` plus
    /// an authentication-positive output (`ApplicationData`, handshake
    /// progression, or `KeyingMaterial`) proves an authenticated fresh
    /// record landed — only *then* consider the address-update policy.
    /// Treat `Output::ConnectionId` purely as "what bytes to look at
    /// when routing" and never as "where to send next."
    ///
    /// [`Dtls::handle_packet`]: crate::Dtls::handle_packet
    /// [`Dtls::newest_authenticated_record`]: crate::Dtls::newest_authenticated_record
    ///
    /// ## Privacy (RFC 9146 §8)
    ///
    /// CIDs are observable on the wire and are not rotated within a session.
    /// Reusing the same CID across unrelated associations — or using a
    /// predictable scheme (counter, timestamp, MAC address) — lets a passive
    /// observer link traffic across paths and time. Prefer a freshly
    /// generated, unpredictable CID per association (e.g. 8 random bytes
    /// from a CSPRNG). The peer's CID advertised back in
    /// [`Output::ConnectionId`][output_cid] should be treated as opaque.
    ///
    /// ## Alerts are the caller's responsibility
    ///
    /// dimpl is Sans-IO: it does not emit TLS alerts on the wire. Rejection
    /// errors from CID-extension handling surface as [`Error::SecurityError`]
    /// with an RFC-mandated description code the caller is expected to
    /// translate into a fatal alert:
    ///
    /// - Unsolicited `connection_id` in ServerHello → `unsupported_extension(110)`
    ///   (RFC 5246 §7.4.1.4, RFC 9146 §3)
    /// - Malformed `connection_id` extension body → `decode_error(50)`
    ///   (RFC 5246 §7.2.2)
    ///
    /// [output_cid]: crate::Output::ConnectionId
    /// [`Error::SecurityError`]: crate::Error::SecurityError
    pub fn with_connection_id(mut self, cid: Vec<u8>) -> Self {
        self.connection_id = Some(cid);
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

        // Validate MTU: must be large enough for DTLS record + handshake headers
        if self.mtu < 64 {
            return Err(Error::ConfigError(format!(
                "MTU {} is too small (minimum 64)",
                self.mtu
            )));
        }

        // Validate connection_id: must be at most DTLS12_CID_MAX_LEN bytes.
        //
        // This is the single source of truth for the CID length invariant
        // relied on throughout the DTLS 1.2 CID path:
        //
        // - `crypto::dtls_aead::DTLS12_CID_AAD_MAX` (23 + DTLS12_CID_MAX_LEN)
        //   sizes the AAD ArrayVec so the `try_extend_from_slice(cid)` unwraps
        //   in `Aad::new_dtls12_cid` cannot panic.
        // - `dtls12::incoming::Record::decrypt_record`'s `ArrayVec<u8, 255>`
        //   wire-CID buffer and its `try_extend_from_slice(...).expect(...)`
        //   rely on it (RFC 9146 §5.3 on-wire auth).
        // - `dtls12::message::extensions::ConnectionIdExtension::{new, parse}`
        //   uses the same 255-byte backing store (matches the u8 length byte
        //   on the wire).
        // - `Client::into_output` / `Server::into_output`'s poll-buffer handling
        //   assumes the caller's buffer can fit up to DTLS12_CID_MAX_LEN bytes
        //   of CID.
        //
        // If this ceiling ever changes, audit every site listed above.
        if let Some(ref cid) = self.connection_id {
            if cid.len() > crate::crypto::DTLS12_CID_MAX_LEN {
                return Err(Error::ConfigError(format!(
                    "Connection ID length {} exceeds maximum {}",
                    cid.len(),
                    crate::crypto::DTLS12_CID_MAX_LEN
                )));
            }
        }

        // Round-5 review #3: `connection_id` is RFC 9146 (DTLS 1.2). If
        // the caller sets a CID but the cipher-suite filter drops every
        // DTLS 1.2 suite, the ClientHello would advertise CID on a
        // handshake that can only succeed as DTLS 1.3, where dimpl does
        // not implement RFC 9147 CID. Reject the combination at config
        // build time so the mismatch is caught before the handshake.
        if self.connection_id.is_some() {
            let has_dtls12 = {
                let mut all = crypto_provider.supported_cipher_suites();
                match &self.dtls12_cipher_suites {
                    Some(list) => all.any(|cs| list.contains(&cs.suite())),
                    None => all.next().is_some(),
                }
            };
            if !has_dtls12 {
                return Err(Error::ConfigError(
                    "Connection ID is configured (RFC 9146, DTLS 1.2) but no \
                     DTLS 1.2 cipher suite survives the filter. Either include \
                     a DTLS 1.2 suite in `dtls12_cipher_suites` or drop \
                     `with_connection_id`."
                        .to_string(),
                ));
            }
        }

        // Validate aead_encryption_limit: must be at least 1
        if self.aead_encryption_limit == 0 {
            return Err(Error::ConfigError(
                "aead_encryption_limit must be at least 1".to_string(),
            ));
        }

        // Validate cipher suite filters: at least one version must have suites.
        // Mirror Config::dtls12_cipher_suites() by dropping PSK suites when no PSK
        // is configured, so a PSK-only filter without a PSK resolver fails fast.
        let has_psk = self.psk.is_some();
        let dtls12_suites: Vec<_> = {
            let all = crypto_provider.supported_cipher_suites();
            match &self.dtls12_cipher_suites {
                Some(list) => all
                    .filter(|cs| list.contains(&cs.suite()))
                    .filter(|cs| has_psk || !cs.suite().is_psk())
                    .collect(),
                None => all.filter(|cs| has_psk || !cs.suite().is_psk()).collect(),
            }
        };
        let dtls12_count = dtls12_suites.len();
        let dtls13_count = {
            let all = crypto_provider.dtls13_cipher_suites.iter();
            match &self.dtls13_cipher_suites {
                Some(list) => all.filter(|cs| list.contains(&cs.suite())).count(),
                None => all.count(),
            }
        };
        if dtls12_count + dtls13_count == 0 {
            return Err(Error::ConfigError(
                "No cipher suites remain after filtering. \
                 At least one DTLS 1.2 or DTLS 1.3 cipher suite must be available."
                    .to_string(),
            ));
        }

        // When PSK is configured, at least one negotiable DTLS 1.2 suite must be
        // a PSK suite. The only PSK suite we implement today is DTLS 1.2 (0xC0A8),
        // so a surviving DTLS 1.3 suite is not a fallback: Dtls::new_12_psk only
        // speaks DTLS 1.2, and under AuthMode::Psk every non-PSK suite is rejected
        // by CryptoContext::is_cipher_suite_compatible.
        if has_psk && !dtls12_suites.iter().any(|cs| cs.suite().is_psk()) {
            return Err(Error::ConfigError(
                "PSK is configured but no PSK cipher suite remains after filtering \
                 DTLS 1.2 suites. Include at least one PSK suite in \
                 dtls12_cipher_suites."
                    .to_string(),
            ));
        }

        // Skip DTLS 1.2 kx-group validation only when the surviving DTLS 1.2
        // suites are exclusively PSK — those don't negotiate an ECDHE group.
        // Any cert-based DTLS 1.2 suite left in the filter still needs a
        // compatible key exchange group, even when PSK is also configured.
        let has_non_psk_dtls12 = dtls12_suites.iter().any(|cs| !cs.suite().is_psk());

        // Validate kx_groups filter: each enabled version needs compatible groups
        // (PSK-only DTLS 1.2 configs don't need key exchange groups)
        let filtered_kx = |kx: &&'static dyn SupportedKxGroup| -> bool {
            match &self.kx_groups {
                Some(list) => list.contains(&kx.name()),
                None => true,
            }
        };
        if has_non_psk_dtls12 {
            let dtls12_kx_count = crypto_provider
                .supported_kx_groups()
                .filter(|kx| filtered_kx(kx))
                .count();
            if dtls12_kx_count == 0 {
                return Err(Error::ConfigError(
                    "DTLS 1.2 cipher suites are enabled but no compatible key exchange \
                     groups remain after filtering."
                        .to_string(),
                ));
            }
        }
        if dtls13_count > 0 {
            let kx_count = crypto_provider
                .supported_kx_groups()
                .filter(|kx| filtered_kx(kx))
                .count();
            if kx_count == 0 {
                return Err(Error::ConfigError(
                    "DTLS 1.3 cipher suites are enabled but no key exchange groups \
                     remain after filtering."
                        .to_string(),
                ));
            }
        }

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
            dtls12_cipher_suites: self.dtls12_cipher_suites,
            dtls13_cipher_suites: self.dtls13_cipher_suites,
            kx_groups: self.kx_groups,
            psk: self.psk,
            connection_id: self.connection_id,
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

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Psk::Client { identity, .. } => f
                .debug_struct("Psk::Client")
                .field("identity", &identity)
                .field("resolver", &"...")
                .finish(),
            Psk::Server { hint, .. } => f
                .debug_struct("Psk::Server")
                .field("hint", &hint)
                .field("resolver", &"...")
                .finish(),
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("mtu", &self.mtu)
            .field("max_queue_rx", &self.max_queue_rx)
            .field("max_queue_tx", &self.max_queue_tx)
            .field(
                "require_client_certificate",
                &self.require_client_certificate,
            )
            .field("use_server_cookie", &self.use_server_cookie)
            .field("flight_start_rto", &self.flight_start_rto)
            .field("flight_retries", &self.flight_retries)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("crypto_provider", &self.crypto_provider)
            .field("rng_seed", &self.rng_seed)
            .field("aead_encryption_limit", &self.aead_encryption_limit)
            .field("dtls12_cipher_suites", &self.dtls12_cipher_suites)
            .field("dtls13_cipher_suites", &self.dtls13_cipher_suites)
            .field("kx_groups", &self.kx_groups)
            .field("psk", &self.psk)
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

impl fmt::Debug for ConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigBuilder")
            .field("mtu", &self.mtu)
            .field("max_queue_rx", &self.max_queue_rx)
            .field("max_queue_tx", &self.max_queue_tx)
            .field(
                "require_client_certificate",
                &self.require_client_certificate,
            )
            .field("use_server_cookie", &self.use_server_cookie)
            .field("flight_start_rto", &self.flight_start_rto)
            .field("flight_retries", &self.flight_retries)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("crypto_provider", &self.crypto_provider)
            .field("rng_seed", &self.rng_seed)
            .field("aead_encryption_limit", &self.aead_encryption_limit)
            .field("dtls12_cipher_suites", &self.dtls12_cipher_suites)
            .field("dtls13_cipher_suites", &self.dtls13_cipher_suites)
            .field("kx_groups", &self.kx_groups)
            .field("psk", &self.psk)
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_mtu() {
        match Config::builder().mtu(0).build() {
            Err(Error::ConfigError(msg)) => {
                assert!(msg.contains("MTU"), "error should mention MTU: {msg}")
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for MTU=0"),
        }
    }

    #[test]
    fn rejects_small_mtu() {
        match Config::builder().mtu(32).build() {
            Err(Error::ConfigError(msg)) => {
                assert!(msg.contains("MTU"), "error should mention MTU: {msg}")
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for MTU=32"),
        }
    }

    #[test]
    fn accepts_minimum_mtu() {
        Config::builder()
            .mtu(64)
            .build()
            .expect("MTU 64 should be accepted");
    }

    #[test]
    fn rejects_zero_aead_limit() {
        match Config::builder().aead_encryption_limit(0).build() {
            Err(Error::ConfigError(msg)) => assert!(
                msg.contains("aead_encryption_limit"),
                "error should mention aead_encryption_limit: {msg}"
            ),
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for aead_encryption_limit=0"),
        }
    }

    #[test]
    fn accepts_minimum_aead_limit() {
        Config::builder()
            .aead_encryption_limit(1)
            .build()
            .expect("aead_encryption_limit 1 should be accepted");
    }

    #[test]
    fn filter_dtls12_cipher_suite() {
        let config = Config::builder()
            .dtls12_cipher_suites(&[Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256])
            .build()
            .expect("should accept single DTLS 1.2 suite");
        let suites: Vec<_> = config.dtls12_cipher_suites().map(|cs| cs.suite()).collect();
        assert_eq!(suites, &[Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256]);
    }

    #[test]
    fn filter_dtls13_cipher_suite() {
        let config = Config::builder()
            .dtls13_cipher_suites(&[Dtls13CipherSuite::AES_256_GCM_SHA384])
            .build()
            .expect("should accept single DTLS 1.3 suite");
        let suites: Vec<_> = config.dtls13_cipher_suites().map(|cs| cs.suite()).collect();
        assert_eq!(suites, &[Dtls13CipherSuite::AES_256_GCM_SHA384]);
    }

    #[test]
    fn filter_kx_groups() {
        let config = Config::builder()
            .kx_groups(&[NamedGroup::Secp256r1])
            .build()
            .expect("should accept single kx group");
        let groups: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
        assert_eq!(groups, &[NamedGroup::Secp256r1]);
    }

    #[test]
    fn empty_dtls12_filter_disables_version() {
        let config = Config::builder()
            .dtls12_cipher_suites(&[])
            .build()
            .expect("should accept empty DTLS 1.2 when 1.3 has suites");
        assert_eq!(config.dtls12_cipher_suites().count(), 0);
        assert!(config.dtls13_cipher_suites().count() > 0);
    }

    #[test]
    fn empty_dtls13_filter_disables_version() {
        let config = Config::builder()
            .dtls13_cipher_suites(&[])
            .build()
            .expect("should accept empty DTLS 1.3 when 1.2 has suites");
        assert!(config.dtls12_cipher_suites().count() > 0);
        assert_eq!(config.dtls13_cipher_suites().count(), 0);
    }

    #[test]
    fn both_empty_filters_rejected() {
        match Config::builder()
            .dtls12_cipher_suites(&[])
            .dtls13_cipher_suites(&[])
            .build()
        {
            Err(Error::ConfigError(msg)) => {
                assert!(
                    msg.contains("No cipher suites"),
                    "error should mention cipher suites: {msg}"
                )
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error when both versions are empty"),
        }
    }

    #[test]
    fn empty_kx_groups_filter_rejected() {
        match Config::builder().kx_groups(&[]).build() {
            Err(Error::ConfigError(msg)) => {
                assert!(
                    msg.contains("key exchange"),
                    "error should mention key exchange: {msg}"
                )
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for empty kx groups"),
        }
    }

    #[test]
    fn x25519_only_accepted_for_dtls12() {
        // X25519 is supported for DTLS 1.2 and should be accepted.
        let config = Config::builder()
            .dtls13_cipher_suites(&[])
            .kx_groups(&[NamedGroup::X25519])
            .build()
            .expect("X25519-only should be accepted for DTLS 1.2");
        let groups: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
        assert_eq!(groups, &[NamedGroup::X25519]);
    }

    #[test]
    fn x25519_only_accepted_for_dtls13_only() {
        // X25519-only is fine when DTLS 1.2 is disabled.
        let config = Config::builder()
            .dtls12_cipher_suites(&[])
            .kx_groups(&[NamedGroup::X25519])
            .build()
            .expect("X25519-only should be accepted for DTLS 1.3-only config");
        let groups: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
        assert_eq!(groups, &[NamedGroup::X25519]);
    }

    #[test]
    fn kx_groups_match_provider_when_unfiltered() {
        let config = Config::default();
        let from_config: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
        let from_provider: Vec<_> = config
            .crypto_provider()
            .supported_kx_groups()
            .map(|g| g.name())
            .collect();
        assert_eq!(from_config, from_provider);
    }

    #[test]
    fn no_filter_returns_all() {
        let config = Config::default();
        // Default provider should have at least 2 DTLS 1.2 and 2 DTLS 1.3 suites
        // (PSK suites are excluded without a resolver, so only non-PSK count)
        assert!(config.dtls12_cipher_suites().count() >= 2);
        assert!(config.dtls13_cipher_suites().count() >= 2);
        assert!(config.kx_groups().count() >= 2);
    }

    #[test]
    fn psk_suites_excluded_without_resolver() {
        let config = Config::default();
        assert!(
            config.dtls12_cipher_suites().all(|cs| !cs.suite().is_psk()),
            "PSK suites should be excluded when no PskResolver is configured"
        );
    }

    #[test]
    fn psk_suites_included_with_resolver() {
        struct DummyResolver;
        impl PskResolver for DummyResolver {
            fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
                None
            }
        }

        let config = Config::builder()
            .with_psk_server(None, Arc::new(DummyResolver))
            .build()
            .expect("config with PSK resolver should build");
        assert!(
            config.dtls12_cipher_suites().any(|cs| cs.suite().is_psk()),
            "PSK suites should be included when a PskResolver is configured"
        );
    }

    #[test]
    fn psk_config_with_only_non_psk_dtls12_filter_rejected() {
        struct DummyResolver;
        impl PskResolver for DummyResolver {
            fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
                Some(b"key".to_vec())
            }
        }

        // PSK config but the user filtered DTLS 1.2 down to a cert-only suite
        // and disabled DTLS 1.3. AuthMode::Psk would reject every surviving
        // suite at runtime, so build() should fail fast here.
        let result = Config::builder()
            .with_psk_client(b"identity".to_vec(), Arc::new(DummyResolver))
            .dtls12_cipher_suites(&[Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256])
            .dtls13_cipher_suites(&[])
            .build();
        match result {
            Err(Error::ConfigError(msg)) => {
                assert!(msg.contains("PSK"), "error should mention PSK: {msg}")
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!("expected error for PSK config with only non-PSK suites"),
        }
    }

    #[test]
    fn psk_with_dtls13_but_no_psk_dtls12_suite_rejected() {
        struct DummyResolver;
        impl PskResolver for DummyResolver {
            fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
                Some(b"key".to_vec())
            }
        }

        // PSK configured, DTLS 1.2 filtered to cert-only, DTLS 1.3 left enabled.
        // The surviving DTLS 1.3 suite is not a fallback for Dtls::new_12_psk,
        // so build() must reject this config instead of producing one that can
        // never complete a PSK handshake.
        let result = Config::builder()
            .with_psk_client(b"identity".to_vec(), Arc::new(DummyResolver))
            .dtls12_cipher_suites(&[Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256])
            .build();
        match result {
            Err(Error::ConfigError(msg)) => {
                assert!(msg.contains("PSK"), "error should mention PSK: {msg}")
            }
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!(
                "expected error for PSK config with only non-PSK DTLS 1.2 suites, \
                 even when DTLS 1.3 is enabled"
            ),
        }
    }

    #[test]
    fn psk_with_cert_dtls12_and_empty_kx_groups_rejected() {
        struct DummyResolver;
        impl PskResolver for DummyResolver {
            fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
                Some(b"key".to_vec())
            }
        }

        // Mixed config: PSK is set, but a cert-based DTLS 1.2 suite is also in
        // the filter alongside a PSK suite. That cert suite still needs an
        // ECDHE group, so kx_groups(&[]) must fail build — the fact that PSK
        // is also configured does not excuse the missing groups.
        let result = Config::builder()
            .with_psk_server(None, Arc::new(DummyResolver))
            .dtls12_cipher_suites(&[
                Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
                Dtls12CipherSuite::PSK_AES128_CCM_8,
            ])
            .dtls13_cipher_suites(&[])
            .kx_groups(&[])
            .build();
        match result {
            Err(Error::ConfigError(msg)) => assert!(
                msg.contains("key exchange"),
                "error should mention key exchange groups: {msg}"
            ),
            Err(other) => panic!("expected ConfigError, got: {other:?}"),
            Ok(_) => panic!(
                "expected error when a cert-based DTLS 1.2 suite is enabled \
                 without any kx groups, even alongside PSK"
            ),
        }
    }

    #[test]
    fn psk_client_with_empty_kx_groups_builds() {
        struct DummyResolver;
        impl PskResolver for DummyResolver {
            fn resolve(&self, _identity: &[u8]) -> Option<Vec<u8>> {
                Some(b"key".to_vec())
            }
        }

        // PSK suites don't need ECDHE groups. A truly PSK-only endpoint (with
        // the DTLS 1.2 filter narrowed to PSK suites and DTLS 1.3 disabled)
        // should be able to opt out of kx_groups entirely.
        Config::builder()
            .with_psk_client(b"identity".to_vec(), Arc::new(DummyResolver))
            .dtls12_cipher_suites(&[Dtls12CipherSuite::PSK_AES128_CCM_8])
            .dtls13_cipher_suites(&[])
            .kx_groups(&[])
            .build()
            .expect("PSK-only client with empty kx_groups should build");
    }

    #[test]
    fn filter_with_explicit_provider() {
        #[cfg(feature = "aws-lc-rs")]
        {
            let config = Config::builder()
                .with_crypto_provider(aws_lc_rs::default_provider())
                .dtls12_cipher_suites(&[Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384])
                .dtls13_cipher_suites(&[Dtls13CipherSuite::AES_128_GCM_SHA256])
                .kx_groups(&[NamedGroup::X25519, NamedGroup::Secp256r1])
                .build()
                .expect("should accept filtered config with explicit provider");
            let suites12: Vec<_> = config.dtls12_cipher_suites().map(|cs| cs.suite()).collect();
            assert_eq!(
                suites12,
                &[Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384]
            );
            let suites13: Vec<_> = config.dtls13_cipher_suites().map(|cs| cs.suite()).collect();
            assert_eq!(suites13, &[Dtls13CipherSuite::AES_128_GCM_SHA256]);
            let groups: Vec<_> = config.kx_groups().map(|g| g.name()).collect();
            assert_eq!(groups, &[NamedGroup::X25519, NamedGroup::Secp256r1]);
        }
    }
}
