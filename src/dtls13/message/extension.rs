use crate::buffer::Buf;
use nom::{IResult, bytes::complete::take, number::complete::be_u16};
use std::{fmt, ops::Range};

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

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtensionType(u16);

impl Default for ExtensionType {
    fn default() -> Self {
        Self(u16::MAX)
    }
}

impl ExtensionType {
    pub const SERVER_NAME: Self = Self(0x0000);
    pub const MAX_FRAGMENT_LENGTH: Self = Self(0x0001);
    pub const CLIENT_CERTIFICATE_URL: Self = Self(0x0002);
    pub const TRUSTED_CA_KEYS: Self = Self(0x0003);
    pub const TRUNCATED_HMAC: Self = Self(0x0004);
    pub const STATUS_REQUEST: Self = Self(0x0005);
    pub const USER_MAPPING: Self = Self(0x0006);
    pub const CLIENT_AUTHZ: Self = Self(0x0007);
    pub const SERVER_AUTHZ: Self = Self(0x0008);
    pub const CERT_TYPE: Self = Self(0x0009);
    pub const SUPPORTED_GROUPS: Self = Self(0x000A);
    pub const EC_POINT_FORMATS: Self = Self(0x000B);
    pub const SRP: Self = Self(0x000C);
    pub const SIGNATURE_ALGORITHMS: Self = Self(0x000D);
    pub const USE_SRTP: Self = Self(0x000E);
    pub const HEARTBEAT: Self = Self(0x000F);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self = Self(0x0010);
    pub const STATUS_REQUEST_V2: Self = Self(0x0011);
    pub const SIGNED_CERTIFICATE_TIMESTAMP: Self = Self(0x0012);
    pub const CLIENT_CERTIFICATE_TYPE: Self = Self(0x0013);
    pub const SERVER_CERTIFICATE_TYPE: Self = Self(0x0014);
    pub const PADDING: Self = Self(0x0015);
    pub const ENCRYPT_THEN_MAC: Self = Self(0x0016);
    pub const EXTENDED_MASTER_SECRET: Self = Self(0x0017);
    pub const TOKEN_BINDING: Self = Self(0x0018);
    pub const CACHED_INFO: Self = Self(0x0019);
    pub const SESSION_TICKET: Self = Self(0x0023);
    pub const PRE_SHARED_KEY: Self = Self(0x0029);
    pub const EARLY_DATA: Self = Self(0x002A);
    pub const SUPPORTED_VERSIONS: Self = Self(0x002B);
    pub const COOKIE: Self = Self(0x002C);
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(0x002D);
    pub const CERTIFICATE_AUTHORITIES: Self = Self(0x002F);
    pub const OID_FILTERS: Self = Self(0x0030);
    pub const POST_HANDSHAKE_AUTH: Self = Self(0x0031);
    pub const SIGNATURE_ALGORITHMS_CERT: Self = Self(0x0032);
    pub const KEY_SHARE: Self = Self(0x0033);
    pub const RENEGOTIATION_INFO: Self = Self(0xFF01);

    pub const fn from_u16(value: u16) -> Self {
        Self(value)
    }

    pub const fn as_u16(&self) -> u16 {
        self.0
    }

    const fn is_unknown(&self) -> bool {
        !matches!(
            *self,
            Self(0x0000..=0x0019 | 0x0023 | 0x0029..=0x002D | 0x002F..=0x0033 | 0xFF01)
        )
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ExtensionType> {
        let (input, value) = be_u16(input)?;
        Ok((input, ExtensionType::from_u16(value)))
    }

    /// Returns true if this extension type is supported by this implementation.
    pub fn is_supported(&self) -> bool {
        Self::supported().contains(self)
    }

    /// Supported extension types that this DTLS 1.3 implementation handles.
    pub const fn supported() -> &'static [ExtensionType; 6] {
        &[
            ExtensionType::SUPPORTED_VERSIONS,
            ExtensionType::SUPPORTED_GROUPS,
            ExtensionType::SIGNATURE_ALGORITHMS,
            ExtensionType::KEY_SHARE,
            ExtensionType::USE_SRTP,
            ExtensionType::COOKIE,
        ]
    }
}

impl fmt::Debug for ExtensionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unknown() {
            return f.debug_tuple("Unknown").field(&self.0).finish();
        }

        let name = match *self {
            ExtensionType::SERVER_NAME => "ServerName",
            ExtensionType::MAX_FRAGMENT_LENGTH => "MaxFragmentLength",
            ExtensionType::CLIENT_CERTIFICATE_URL => "ClientCertificateUrl",
            ExtensionType::TRUSTED_CA_KEYS => "TrustedCaKeys",
            ExtensionType::TRUNCATED_HMAC => "TruncatedHmac",
            ExtensionType::STATUS_REQUEST => "StatusRequest",
            ExtensionType::USER_MAPPING => "UserMapping",
            ExtensionType::CLIENT_AUTHZ => "ClientAuthz",
            ExtensionType::SERVER_AUTHZ => "ServerAuthz",
            ExtensionType::CERT_TYPE => "CertType",
            ExtensionType::SUPPORTED_GROUPS => "SupportedGroups",
            ExtensionType::EC_POINT_FORMATS => "EcPointFormats",
            ExtensionType::SRP => "Srp",
            ExtensionType::SIGNATURE_ALGORITHMS => "SignatureAlgorithms",
            ExtensionType::USE_SRTP => "UseSrtp",
            ExtensionType::HEARTBEAT => "Heartbeat",
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                "ApplicationLayerProtocolNegotiation"
            }
            ExtensionType::STATUS_REQUEST_V2 => "StatusRequestV2",
            ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP => "SignedCertificateTimestamp",
            ExtensionType::CLIENT_CERTIFICATE_TYPE => "ClientCertificateType",
            ExtensionType::SERVER_CERTIFICATE_TYPE => "ServerCertificateType",
            ExtensionType::PADDING => "Padding",
            ExtensionType::ENCRYPT_THEN_MAC => "EncryptThenMac",
            ExtensionType::EXTENDED_MASTER_SECRET => "ExtendedMasterSecret",
            ExtensionType::TOKEN_BINDING => "TokenBinding",
            ExtensionType::CACHED_INFO => "CachedInfo",
            ExtensionType::SESSION_TICKET => "SessionTicket",
            ExtensionType::PRE_SHARED_KEY => "PreSharedKey",
            ExtensionType::EARLY_DATA => "EarlyData",
            ExtensionType::SUPPORTED_VERSIONS => "SupportedVersions",
            ExtensionType::COOKIE => "Cookie",
            ExtensionType::PSK_KEY_EXCHANGE_MODES => "PskKeyExchangeModes",
            ExtensionType::CERTIFICATE_AUTHORITIES => "CertificateAuthorities",
            ExtensionType::OID_FILTERS => "OidFilters",
            ExtensionType::POST_HANDSHAKE_AUTH => "PostHandshakeAuth",
            ExtensionType::SIGNATURE_ALGORITHMS_CERT => "SignatureAlgorithmsCert",
            ExtensionType::KEY_SHARE => "KeyShare",
            ExtensionType::RENEGOTIATION_INFO => "RenegotiationInfo",
            _ => unreachable!("known DTLS 1.3 extension type missing Debug label"),
        };

        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0x00, 0x0A, // ExtensionType::SUPPORTED_GROUPS
        0x00, 0x08, // Extension length
        0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, // Extension data
    ];

    #[test]
    fn extension_type_newtype_shape() {
        assert_eq!(std::mem::size_of::<ExtensionType>(), 2);
        assert!(ExtensionType::default().is_unknown());
    }

    #[test]
    fn extension_type_wire_roundtrip() {
        for extension_type in ExtensionType::supported() {
            assert_eq!(
                ExtensionType::from_u16(extension_type.as_u16()),
                *extension_type
            );
            assert!(!extension_type.is_unknown());
        }

        let unknown = ExtensionType::from_u16(0xFFFF);
        assert_eq!(unknown.as_u16(), 0xFFFF);
        assert!(unknown.is_unknown());
    }

    #[test]
    fn extension_type_debug_stays_enum_like() {
        assert_eq!(
            format!("{:?}", ExtensionType::SUPPORTED_GROUPS),
            "SupportedGroups"
        );
        assert_eq!(
            format!("{:?}", ExtensionType::from_u16(0xFFFF)),
            "Unknown(65535)"
        );
    }

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
