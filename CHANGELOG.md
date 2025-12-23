# Unreleased

# 0.2.1

  * Fix DTLS protocol version in HelloVerifyRequest #36
  * Handle multiple Handshake in one Record #36
  * dimpl is not compatible with aws-lc-rs < 1.14 #35

# 0.2.0

  * Add fuzz testing to #32
  * Re-export Aad and Nonce that was missing #30
  * Add CodeQL analysis workflow configuration #27
  * Constant time equality #26
  * Pluggable CryptoProvider #16
    * aws-lc-rs backend (default)
    * rust-crypto backend (pure Rust)

# 0.1.5

  * Optimize parse speed using Box #14
  * Replace self_cell with indexes #14
  * Fix bug not retuning pooled Buf #14
  * Replace tinyvec with arrayvec #14
  * Remove zeroize - for now #13

# 0.1.4

  * Replace RustCrypto with aws-lc-rs #12
  * Fix SRTP key to include client_random and server_random #11
  * Make generated certs compatible with Firefox #11

# 0.1.3

  * Fixes to extension parsing #10
  * Better connection/flight timers #9
  * Remove rcgen/ring dependency #8

# 0.1.2

  * Bump MSRV to 1.81.0 #7
  * Bump rand to 0.9.x #7

# 0.1.1

  * Remove Diffie-Hellman (since no RSA) #6
  * Add github actions as CI #5
  * Fix bad MTU packing causing flaky tests #4
  * Remove ciphers using RSA #3

# 0.1.0
  * First published version
