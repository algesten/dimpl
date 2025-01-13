use nom::{bytes::complete::take, number::complete::be_u16, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    pub extension_type: ExtensionType,
    pub extension_data: &'a [u8],
}

impl<'a> Extension<'a> {
    pub fn new(extension_type: ExtensionType, extension_data: &'a [u8]) -> Self {
        Extension {
            extension_type,
            extension_data,
        }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], Extension<'a>> {
        let (input, extension_type) = ExtensionType::parse(input)?;
        let (input, extension_length) = be_u16(input)?;
        let (input, extension_data) = take(extension_length)(input)?;

        Ok((
            input,
            Extension {
                extension_type,
                extension_data,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.extension_type.as_u16().to_be_bytes());
        output.extend_from_slice(&(self.extension_data.len() as u16).to_be_bytes());
        output.extend_from_slice(self.extension_data);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionType {
    ServerName,
    MaxFragmentLength,
    ClientCertificateUrl,
    TrustedCaKeys,
    TruncatedHmac,
    StatusRequest,
    UserMapping,
    ClientAuthz,
    ServerAuthz,
    CertType,
    SupportedGroups,
    EcPointFormats,
    Srp,
    SignatureAlgorithms,
    UseSrtp,
    Heartbeat,
    ApplicationLayerProtocolNegotiation,
    StatusRequestV2,
    SignedCertificateTimestamp,
    ClientCertificateType,
    ServerCertificateType,
    Padding,
    EncryptThenMac,
    ExtendedMasterSecret,
    TokenBinding,
    CachedInfo,
    SessionTicket,
    PreSharedKey,
    EarlyData,
    SupportedVersions,
    Cookie,
    PskKeyExchangeModes,
    CertificateAuthorities,
    OidFilters,
    PostHandshakeAuth,
    SignatureAlgorithmsCert,
    KeyShare,
    Unknown(u16),
}

impl ExtensionType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0000 => ExtensionType::ServerName,
            0x0001 => ExtensionType::MaxFragmentLength,
            0x0002 => ExtensionType::ClientCertificateUrl,
            0x0003 => ExtensionType::TrustedCaKeys,
            0x0004 => ExtensionType::TruncatedHmac,
            0x0005 => ExtensionType::StatusRequest,
            0x0006 => ExtensionType::UserMapping,
            0x0007 => ExtensionType::ClientAuthz,
            0x0008 => ExtensionType::ServerAuthz,
            0x0009 => ExtensionType::CertType,
            0x000A => ExtensionType::SupportedGroups,
            0x000B => ExtensionType::EcPointFormats,
            0x000C => ExtensionType::Srp,
            0x000D => ExtensionType::SignatureAlgorithms,
            0x000E => ExtensionType::UseSrtp,
            0x000F => ExtensionType::Heartbeat,
            0x0010 => ExtensionType::ApplicationLayerProtocolNegotiation,
            0x0011 => ExtensionType::StatusRequestV2,
            0x0012 => ExtensionType::SignedCertificateTimestamp,
            0x0013 => ExtensionType::ClientCertificateType,
            0x0014 => ExtensionType::ServerCertificateType,
            0x0015 => ExtensionType::Padding,
            0x0016 => ExtensionType::EncryptThenMac,
            0x0017 => ExtensionType::ExtendedMasterSecret,
            0x0018 => ExtensionType::TokenBinding,
            0x0019 => ExtensionType::CachedInfo,
            0x0023 => ExtensionType::SessionTicket,
            0x0029 => ExtensionType::PreSharedKey,
            0x002A => ExtensionType::EarlyData,
            0x002B => ExtensionType::SupportedVersions,
            0x002C => ExtensionType::Cookie,
            0x002D => ExtensionType::PskKeyExchangeModes,
            0x002F => ExtensionType::CertificateAuthorities,
            0x0030 => ExtensionType::OidFilters,
            0x0031 => ExtensionType::PostHandshakeAuth,
            0x0032 => ExtensionType::SignatureAlgorithmsCert,
            0x0033 => ExtensionType::KeyShare,
            _ => ExtensionType::Unknown(value),
        }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            ExtensionType::ServerName => 0x0000,
            ExtensionType::MaxFragmentLength => 0x0001,
            ExtensionType::ClientCertificateUrl => 0x0002,
            ExtensionType::TrustedCaKeys => 0x0003,
            ExtensionType::TruncatedHmac => 0x0004,
            ExtensionType::StatusRequest => 0x0005,
            ExtensionType::UserMapping => 0x0006,
            ExtensionType::ClientAuthz => 0x0007,
            ExtensionType::ServerAuthz => 0x0008,
            ExtensionType::CertType => 0x0009,
            ExtensionType::SupportedGroups => 0x000A,
            ExtensionType::EcPointFormats => 0x000B,
            ExtensionType::Srp => 0x000C,
            ExtensionType::SignatureAlgorithms => 0x000D,
            ExtensionType::UseSrtp => 0x000E,
            ExtensionType::Heartbeat => 0x000F,
            ExtensionType::ApplicationLayerProtocolNegotiation => 0x0010,
            ExtensionType::StatusRequestV2 => 0x0011,
            ExtensionType::SignedCertificateTimestamp => 0x0012,
            ExtensionType::ClientCertificateType => 0x0013,
            ExtensionType::ServerCertificateType => 0x0014,
            ExtensionType::Padding => 0x0015,
            ExtensionType::EncryptThenMac => 0x0016,
            ExtensionType::ExtendedMasterSecret => 0x0017,
            ExtensionType::TokenBinding => 0x0018,
            ExtensionType::CachedInfo => 0x0019,
            ExtensionType::SessionTicket => 0x0023,
            ExtensionType::PreSharedKey => 0x0029,
            ExtensionType::EarlyData => 0x002A,
            ExtensionType::SupportedVersions => 0x002B,
            ExtensionType::Cookie => 0x002C,
            ExtensionType::PskKeyExchangeModes => 0x002D,
            ExtensionType::CertificateAuthorities => 0x002F,
            ExtensionType::OidFilters => 0x0030,
            ExtensionType::PostHandshakeAuth => 0x0031,
            ExtensionType::SignatureAlgorithmsCert => 0x0032,
            ExtensionType::KeyShare => 0x0033,
            ExtensionType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ExtensionType> {
        let (input, value) = be_u16(input)?;
        Ok((input, ExtensionType::from_u16(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = &[
        0x00, 0x0A, // ExtensionType::SupportedGroups
        0x00, 0x08, // Extension length
        0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, // Extension data
    ];

    #[test]
    fn roundtrip() {
        let extension_data = &MESSAGE[4..];
        let extension = Extension::new(ExtensionType::SupportedGroups, extension_data);

        // Serialize and compare to MESSAGE
        let mut serialized = Vec::new();
        extension.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE);

        // Parse and compare with original
        let (rest, parsed) = Extension::parse(&serialized).unwrap();
        assert_eq!(parsed, extension);

        assert!(rest.is_empty());
    }
}
