use super::error::ParseError;
use super::id::PreMasterSecretRandom;
use super::ProtocolVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreMasterSecret {
    pub client_version: ProtocolVersion,
    pub random: PreMasterSecretRandom,
}

impl PreMasterSecret {
    pub fn new(client_version: ProtocolVersion, random: PreMasterSecretRandom) -> Self {
        PreMasterSecret {
            client_version,
            random,
        }
    }

    pub fn parse(data: &[u8]) -> Result<PreMasterSecret, ParseError<ErrorKind>> {
        if data.len() < 2 {
            return Err(ParseError::new(ErrorKind::VersionNotEnough, 0));
        }
        let client_version = ProtocolVersion::from_u16(u16::from_be_bytes([data[0], data[1]]));
        let random = PreMasterSecretRandom::new(&data[2..])
            .map_err(|_| ParseError::new(ErrorKind::RandomLengthIncorrect, 2))?;
        Ok(PreMasterSecret {
            client_version,
            random,
        })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.client_version.to_u16().to_be_bytes());
        out.extend_from_slice(&self.random);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    VersionNotEnough,
    RandomLengthIncorrect,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::id::PreMasterSecretRandom;
    use crate::message::ProtocolVersion;

    const MESSAGE: &[u8] = &[
        0xFE, 0xFD, // Version (DTLS 1.2)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Random(46)
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
    ];

    #[test]
    fn roundtrip() {
        let original = PreMasterSecret::new(
            ProtocolVersion::V1_2,
            PreMasterSecretRandom::new(&MESSAGE[2..]).unwrap(),
        );

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = PreMasterSecret::parse(&serialized).unwrap();

        assert_eq!(parsed.client_version, original.client_version);
        assert_eq!(parsed.random, original.random);
    }

    #[test]
    fn parse_version_not_enough() {
        let error = PreMasterSecret::parse(&MESSAGE[..1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::VersionNotEnough);
    }

    #[test]
    fn parse_random_length_incorrect() {
        let error = PreMasterSecret::parse(&MESSAGE[..3]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RandomLengthIncorrect);
    }
}
