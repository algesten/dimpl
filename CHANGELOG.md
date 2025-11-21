# Unreleased

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
