use crate::buffer::Buf;
use crate::types::ProtocolVersion;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::be_u8;
use nom::IResult;

/// SupportedVersions extension in ClientHello (RFC 8446 Section 4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedVersionsClientHello {
    pub versions: ArrayVec<ProtocolVersion, 3>,
}

impl SupportedVersionsClientHello {
    pub fn parse(input: &[u8]) -> IResult<&[u8], SupportedVersionsClientHello> {
        let (input, list_len) = be_u8(input)?;
        let (input, versions_data) = take(list_len)(input)?;

        let mut versions = ArrayVec::new();
        let mut rest = versions_data;
        while !rest.is_empty() {
            let (r, version) = ProtocolVersion::parse(rest)?;
            versions.push(version);
            rest = r;
        }

        Ok((input, SupportedVersionsClientHello { versions }))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.push((self.versions.len() * 2) as u8);
        for version in &self.versions {
            output.extend_from_slice(&version.as_u16().to_be_bytes());
        }
    }
}

/// SupportedVersions extension in ServerHello (RFC 8446 Section 4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedVersionsServerHello {
    pub selected_version: ProtocolVersion,
}

impl SupportedVersionsServerHello {
    pub fn parse(input: &[u8]) -> IResult<&[u8], SupportedVersionsServerHello> {
        let (input, selected_version) = ProtocolVersion::parse(input)?;
        Ok((input, SupportedVersionsServerHello { selected_version }))
    }

    pub fn serialize(&self, output: &mut Buf) {
        output.extend_from_slice(&self.selected_version.as_u16().to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn client_hello_roundtrip() {
        let message: &[u8] = &[
            0x04, // list length (4 bytes = 2 versions)
            0xFE, 0xFC, // DTLS 1.3
            0xFE, 0xFD, // DTLS 1.2
        ];

        let (rest, parsed) = SupportedVersionsClientHello::parse(message).unwrap();
        assert!(rest.is_empty());

        let mut serialized = Buf::new();
        parsed.serialize(&mut serialized);
        assert_eq!(&*serialized, message);
    }

    #[test]
    fn server_hello_roundtrip() {
        let message: &[u8] = &[
            0xFE, 0xFC, // DTLS 1.3
        ];

        let (rest, parsed) = SupportedVersionsServerHello::parse(message).unwrap();
        assert!(rest.is_empty());

        let mut serialized = Buf::new();
        parsed.serialize(&mut serialized);
        assert_eq!(&*serialized, message);
    }
}
