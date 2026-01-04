//! Cookie extension (RFC 8446 Section 4.2.2)
//!
//! In TLS/DTLS 1.3, the cookie extension is used with HelloRetryRequest to
//! allow the server to force the client to prove reachability (similar to
//! DTLS 1.2's HelloVerifyRequest, but integrated into the TLS 1.3 handshake).
//!
//! The cookie is opaque to the client - it just echoes it back in the retry.
//!
//! NOTE: This module is prepared for DTLS 1.3 but not yet fully integrated
//! into the main extension parsing paths.

use crate::buffer::Buf;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;
use std::ops::Range;

/// Cookie extension data.
///
/// In HelloRetryRequest: server sends a cookie to the client.
/// In ClientHello (retry): client echoes the cookie back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieExtension {
    /// Range into the source buffer containing the cookie bytes.
    pub cookie_range: Range<usize>,
}

impl CookieExtension {
    /// Get the cookie bytes from a buffer.
    pub fn cookie<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.cookie_range.clone()]
    }

    /// Parse the extension data.
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Self> {
        let (input, cookie_len) = be_u16(input)?;
        let (input, _cookie_bytes) = take(cookie_len)(input)?;

        // Calculate range: cookie data starts after the 2-byte length
        let cookie_start = base_offset + 2;
        let cookie_range = cookie_start..(cookie_start + cookie_len as usize);

        Ok((input, Self { cookie_range }))
    }

    /// Create and serialize a cookie directly from bytes.
    pub fn serialize_from_bytes(cookie: &[u8], output: &mut Buf) {
        output.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        output.extend_from_slice(cookie);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_roundtrip() {
        let cookie_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let mut output = Buf::new();
        CookieExtension::serialize_from_bytes(&cookie_data, &mut output);

        // Expected: 2 bytes length + 8 bytes cookie
        assert_eq!(output.len(), 10);
        assert_eq!(&output[0..2], &[0x00, 0x08]); // length
        assert_eq!(&output[2..10], &cookie_data);

        let (rest, parsed) = CookieExtension::parse(&output, 0).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.cookie(&output), &cookie_data);
    }

    #[test]
    fn test_cookie_serialize_from_bytes() {
        let cookie_data = [0xAA, 0xBB, 0xCC, 0xDD];

        let mut output = Buf::new();
        CookieExtension::serialize_from_bytes(&cookie_data, &mut output);

        assert_eq!(output.len(), 6);
        assert_eq!(&output[0..2], &[0x00, 0x04]); // length
        assert_eq!(&output[2..6], &cookie_data);
    }

    #[test]
    fn test_empty_cookie() {
        let mut output = Buf::new();
        CookieExtension::serialize_from_bytes(&[], &mut output);

        assert_eq!(output.len(), 2);
        assert_eq!(&output[0..2], &[0x00, 0x00]); // length = 0
    }
}
