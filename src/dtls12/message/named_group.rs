use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

/// Elliptic curves for ECDHE key exchange (RFC 4492, RFC 8422).
///
/// Specifies the named group to use for Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
/// key exchange. dimpl supports P-256 (Secp256r1) and P-384 (Secp384r1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    /// sect163k1 (deprecated).
    Sect163k1,
    /// sect163r1 (deprecated).
    Sect163r1,
    /// sect163r2 (deprecated).
    Sect163r2,
    /// sect193r1 (deprecated).
    Sect193r1,
    /// sect193r2 (deprecated).
    Sect193r2,
    /// sect233k1 (deprecated).
    Sect233k1,
    /// sect233r1 (deprecated).
    Sect233r1,
    /// sect239k1 (deprecated).
    Sect239k1,
    /// sect283k1 (deprecated).
    Sect283k1,
    /// sect283r1 (deprecated).
    Sect283r1,
    /// sect409k1 (deprecated).
    Sect409k1,
    /// sect409r1 (deprecated).
    Sect409r1,
    /// sect571k1 (deprecated).
    Sect571k1,
    /// sect571r1 (deprecated).
    Sect571r1,
    /// secp160k1 (deprecated).
    Secp160k1,
    /// secp160r1 (deprecated).
    Secp160r1,
    /// secp160r2 (deprecated).
    Secp160r2,
    /// secp192k1 (deprecated).
    Secp192k1,
    /// secp192r1 (deprecated).
    Secp192r1,
    /// secp224k1.
    Secp224k1,
    /// secp224r1.
    Secp224r1,
    /// secp256k1.
    Secp256k1,
    /// secp256r1 / P-256 (supported by dimpl).
    Secp256r1,
    /// secp384r1 / P-384 (supported by dimpl).
    Secp384r1,
    /// secp521r1 / P-521.
    Secp521r1,
    /// X25519 (Curve25519 for ECDHE).
    X25519,
    /// X448 (Curve448 for ECDHE).
    X448,
    /// Unknown or unsupported group.
    Unknown(u16),
}

impl NamedGroup {
    /// Convert a wire format u16 value to a `NamedCurve`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => NamedGroup::Sect163k1,
            2 => NamedGroup::Sect163r1,
            3 => NamedGroup::Sect163r2,
            4 => NamedGroup::Sect193r1,
            5 => NamedGroup::Sect193r2,
            6 => NamedGroup::Sect233k1,
            7 => NamedGroup::Sect233r1,
            8 => NamedGroup::Sect239k1,
            9 => NamedGroup::Sect283k1,
            10 => NamedGroup::Sect283r1,
            11 => NamedGroup::Sect409k1,
            12 => NamedGroup::Sect409r1,
            13 => NamedGroup::Sect571k1,
            14 => NamedGroup::Sect571r1,
            15 => NamedGroup::Secp160k1,
            16 => NamedGroup::Secp160r1,
            17 => NamedGroup::Secp160r2,
            18 => NamedGroup::Secp192k1,
            19 => NamedGroup::Secp192r1,
            20 => NamedGroup::Secp224k1,
            21 => NamedGroup::Secp224r1,
            22 => NamedGroup::Secp256k1,
            23 => NamedGroup::Secp256r1,
            24 => NamedGroup::Secp384r1,
            25 => NamedGroup::Secp521r1,
            29 => NamedGroup::X25519,
            30 => NamedGroup::X448,
            _ => NamedGroup::Unknown(value),
        }
    }

    /// Convert this `NamedCurve` to its wire format u16 value.
    pub fn as_u16(&self) -> u16 {
        match self {
            NamedGroup::Sect163k1 => 1,
            NamedGroup::Sect163r1 => 2,
            NamedGroup::Sect163r2 => 3,
            NamedGroup::Sect193r1 => 4,
            NamedGroup::Sect193r2 => 5,
            NamedGroup::Sect233k1 => 6,
            NamedGroup::Sect233r1 => 7,
            NamedGroup::Sect239k1 => 8,
            NamedGroup::Sect283k1 => 9,
            NamedGroup::Sect283r1 => 10,
            NamedGroup::Sect409k1 => 11,
            NamedGroup::Sect409r1 => 12,
            NamedGroup::Sect571k1 => 13,
            NamedGroup::Sect571r1 => 14,
            NamedGroup::Secp160k1 => 15,
            NamedGroup::Secp160r1 => 16,
            NamedGroup::Secp160r2 => 17,
            NamedGroup::Secp192k1 => 18,
            NamedGroup::Secp192r1 => 19,
            NamedGroup::Secp224k1 => 20,
            NamedGroup::Secp224r1 => 21,
            NamedGroup::Secp256k1 => 22,
            NamedGroup::Secp256r1 => 23,
            NamedGroup::Secp384r1 => 24,
            NamedGroup::Secp521r1 => 25,
            NamedGroup::X25519 => 29,
            NamedGroup::X448 => 30,
            NamedGroup::Unknown(value) => *value,
        }
    }

    pub(crate) fn parse(input: &[u8]) -> IResult<&[u8], NamedGroup> {
        let (input, value) = be_u16(input)?;
        Ok((input, NamedGroup::from_u16(value)))
    }

    /// Returns true if this named group is supported by this implementation.
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            NamedGroup::Secp256r1
                | NamedGroup::Secp384r1
                | NamedGroup::X25519
                | NamedGroup::Secp521r1
        )
    }

    /// All supported named groups.
    pub fn all_supported() -> &'static [NamedGroup] {
        &[
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveType {
    ExplicitPrime,
    ExplicitChar2,
    NamedCurve,
    Unknown(u8),
}

impl CurveType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => CurveType::ExplicitPrime,
            2 => CurveType::ExplicitChar2,
            3 => CurveType::NamedCurve,
            _ => CurveType::Unknown(value),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            CurveType::ExplicitPrime => 1,
            CurveType::ExplicitChar2 => 2,
            CurveType::NamedCurve => 3,
            CurveType::Unknown(value) => *value,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], CurveType> {
        let (input, value) = be_u8(input)?;
        Ok((input, CurveType::from_u8(value)))
    }
}
