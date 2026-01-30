use crate::buffer::Buf;
use nom::{bytes::complete::take, number::complete::be_u16, IResult};
use std::ops::Range;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data_range: Range<usize>,
}

impl Extension {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Extension> {
        let original_input = input;
        let (input, extension_type) = ExtensionType::parse(input)?;
        let (input, extension_length) = be_u16(input)?;
        let (input, extension_data_slice) = if extension_length > 0 {
            take(extension_length)(input)?
        } else {
            (input, &input[0..0])
        };

        // Calculate absolute range in root buffer
        let relative_offset =
            extension_data_slice.as_ptr() as usize - original_input.as_ptr() as usize;
        let start = base_offset + relative_offset;
        let end = start + extension_data_slice.len();

        Ok((
            input,
            Extension {
                extension_type,
                extension_data_range: start..end,
            },
        ))
    }

    pub fn extension_data<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.extension_data_range.clone()]
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        let extension_data = self.extension_data(buf);
        output.extend_from_slice(&self.extension_type.as_u16().to_be_bytes());
        output.extend_from_slice(&(extension_data.len() as u16).to_be_bytes());
        if !extension_data.is_empty() {
            output.extend_from_slice(extension_data);
        }
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
    RenegotiationInfo,
    Unknown(u16),
}

impl Default for ExtensionType {
    fn default() -> Self {
        Self::Unknown(0)
    }
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
            0xFF01 => ExtensionType::RenegotiationInfo,
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
            ExtensionType::RenegotiationInfo => 0xFF01,
            ExtensionType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ExtensionType> {
        let (input, value) = be_u16(input)?;
        Ok((input, ExtensionType::from_u16(value)))
    }

    /// Returns true if this extension type is a known/supported variant.
    pub fn is_known(&self) -> bool {
        Self::all().contains(self)
    }

    /// All known extension types that this DTLS 1.3 implementation handles.
    pub fn all() -> &'static [ExtensionType] {
        &[
            ExtensionType::SupportedVersions,
            ExtensionType::SupportedGroups,
            ExtensionType::SignatureAlgorithms,
            ExtensionType::KeyShare,
            ExtensionType::UseSrtp,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0x00, 0x0A, // ExtensionType::SupportedGroups
        0x00, 0x08, // Extension length
        0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, // Extension data
    ];

    #[test]
    fn roundtrip() {
        // Parse the message with base_offset 0
        let (rest, parsed) = Extension::parse(MESSAGE, 0).unwrap();
        assert!(rest.is_empty());

        // Serialize and compare to MESSAGE
        let mut serialized = Buf::new();
        parsed.serialize(MESSAGE, &mut serialized);
        assert_eq!(&*serialized, MESSAGE);
    }
}
