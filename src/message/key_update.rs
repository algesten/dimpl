//! DTLS 1.3 KeyUpdate message (RFC 8446 Section 4.6.3)
//!
//! The KeyUpdate handshake message is used to indicate that the sender
//! is updating its sending cryptographic keys.
//!
//! Format:
//! ```text
//! enum {
//!     update_not_requested(0),
//!     update_requested(1),
//!     (255)
//! } KeyUpdateRequest;
//!
//! struct {
//!     KeyUpdateRequest request_update;
//! } KeyUpdate;
//! ```

use crate::buffer::Buf;
use nom::number::complete::be_u8;
use nom::IResult;

/// KeyUpdate request type (RFC 8446 Section 4.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyUpdateRequest {
    /// Sender is updating keys but does not request peer to update.
    UpdateNotRequested = 0,
    /// Sender is updating keys and requests peer to also update.
    UpdateRequested = 1,
}

impl KeyUpdateRequest {
    #[allow(dead_code)]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(KeyUpdateRequest::UpdateNotRequested),
            1 => Some(KeyUpdateRequest::UpdateRequested),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// DTLS 1.3 KeyUpdate message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUpdate {
    pub request_update: KeyUpdateRequest,
}

#[allow(dead_code)]
impl KeyUpdate {
    pub const WIRE_SIZE: usize = 1;

    pub fn new(request_update: KeyUpdateRequest) -> Self {
        Self { request_update }
    }

    /// Create a KeyUpdate requesting the peer to also update.
    pub fn request_update() -> Self {
        Self {
            request_update: KeyUpdateRequest::UpdateRequested,
        }
    }

    /// Create a KeyUpdate not requesting peer update (response to received KeyUpdate).
    pub fn update_not_requested() -> Self {
        Self {
            request_update: KeyUpdateRequest::UpdateNotRequested,
        }
    }

    /// Parse a KeyUpdate message.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, value) = be_u8(input)?;
        let request_update = KeyUpdateRequest::from_u8(value).ok_or_else(|| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((input, Self { request_update }))
    }

    /// Serialize the KeyUpdate message.
    pub fn serialize(&self, output: &mut Buf) {
        output.push(self.request_update.as_u8());
    }

    /// Returns true if this KeyUpdate requests the peer to also update.
    pub fn is_update_requested(&self) -> bool {
        self.request_update == KeyUpdateRequest::UpdateRequested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_update_roundtrip() {
        let ku = KeyUpdate::request_update();
        let mut buf = Buf::new();
        ku.serialize(&mut buf);

        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 1);

        let (rest, parsed) = KeyUpdate::parse(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, ku);
        assert!(parsed.is_update_requested());
    }

    #[test]
    fn test_key_update_not_requested() {
        let ku = KeyUpdate::update_not_requested();
        let mut buf = Buf::new();
        ku.serialize(&mut buf);

        assert_eq!(buf[0], 0);

        let (_, parsed) = KeyUpdate::parse(&buf).unwrap();
        assert!(!parsed.is_update_requested());
    }

    #[test]
    fn test_invalid_key_update_request() {
        let buf = [2u8]; // Invalid value
        assert!(KeyUpdate::parse(&buf).is_err());
    }
}
