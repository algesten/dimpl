use super::error::ParseError;
use super::id::Cookie;
use super::ProtocolVersion;

#[derive(Debug)]
pub struct HelloVerifyRequest {
    pub server_version: ProtocolVersion,
    pub cookie: Cookie,
}

impl HelloVerifyRequest {
    pub fn new(server_version: ProtocolVersion, cookie: Cookie) -> Self {
        HelloVerifyRequest {
            server_version,
            cookie,
        }
    }

    pub fn parse(data: &[u8]) -> Result<HelloVerifyRequest, ParseError<ErrorKind>> {
        let mut position = 0;

        if data.len() < 2 {
            return Err(ParseError::new(ErrorKind::ServerVersionNotEnough, position));
        }
        let server_version =
            ProtocolVersion::from_u16(u16::from_be_bytes([data[position], data[position + 1]]));
        position += 2;

        if data.len() < position + 1 {
            return Err(ParseError::new(ErrorKind::CookieLength, position));
        }
        let cookie_len = data[position] as usize;
        position += 1;

        if data.len() < position + cookie_len {
            return Err(ParseError::new(ErrorKind::CookieNotEnough, position));
        }
        let cookie = Cookie::try_new(&data[position..position + cookie_len]).unwrap();

        Ok(HelloVerifyRequest {
            server_version,
            cookie,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.server_version.to_u16().to_be_bytes());
        out.push(self.cookie.len() as u8);
        out.extend_from_slice(&self.cookie);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    ServerVersionNotEnough,
    CookieLength,
    CookieNotEnough,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = &[
        0xFE, 0xFD, // ProtocolVersion::V1_2
        0x09, // Cookie length
        0x63, 0x6F, 0x6F, 0x6B, 0x69, 0x65, 0x34, 0x35, 0x36, // Cookie
    ];

    #[test]
    fn roundtrip() {
        let original =
            HelloVerifyRequest::new(ProtocolVersion::V1_2, "cookie456".try_into().unwrap());

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = HelloVerifyRequest::parse(&serialized).unwrap();

        assert_eq!(parsed.server_version, original.server_version);
        assert_eq!(parsed.cookie, original.cookie);
    }

    #[test]
    fn parse_server_version_too_short() {
        let error = HelloVerifyRequest::parse(&MESSAGE[..1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ServerVersionNotEnough);
    }

    #[test]
    fn parse_cookie_length() {
        let error = HelloVerifyRequest::parse(&MESSAGE[..2]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CookieLength);
    }

    #[test]
    fn parse_cookie_not_enough() {
        let error = HelloVerifyRequest::parse(&MESSAGE[..3]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CookieNotEnough);
    }
}
