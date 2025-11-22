use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

/// Elliptic curves for ECDHE key exchange (RFC 4492, RFC 8422).
///
/// Specifies the named curve to use for Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
/// key exchange. dimpl supports P-256 (Secp256r1) and P-384 (Secp384r1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCurve {
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
    /// Unknown or unsupported curve.
    Unknown(u16),
}

impl NamedCurve {
    /// Convert a wire format u16 value to a `NamedCurve`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => NamedCurve::Sect163k1,
            2 => NamedCurve::Sect163r1,
            3 => NamedCurve::Sect163r2,
            4 => NamedCurve::Sect193r1,
            5 => NamedCurve::Sect193r2,
            6 => NamedCurve::Sect233k1,
            7 => NamedCurve::Sect233r1,
            8 => NamedCurve::Sect239k1,
            9 => NamedCurve::Sect283k1,
            10 => NamedCurve::Sect283r1,
            11 => NamedCurve::Sect409k1,
            12 => NamedCurve::Sect409r1,
            13 => NamedCurve::Sect571k1,
            14 => NamedCurve::Sect571r1,
            15 => NamedCurve::Secp160k1,
            16 => NamedCurve::Secp160r1,
            17 => NamedCurve::Secp160r2,
            18 => NamedCurve::Secp192k1,
            19 => NamedCurve::Secp192r1,
            20 => NamedCurve::Secp224k1,
            21 => NamedCurve::Secp224r1,
            22 => NamedCurve::Secp256k1,
            23 => NamedCurve::Secp256r1,
            24 => NamedCurve::Secp384r1,
            25 => NamedCurve::Secp521r1,
            29 => NamedCurve::X25519,
            30 => NamedCurve::X448,
            _ => NamedCurve::Unknown(value),
        }
    }

    /// Convert this `NamedCurve` to its wire format u16 value.
    pub fn as_u16(&self) -> u16 {
        match self {
            NamedCurve::Sect163k1 => 1,
            NamedCurve::Sect163r1 => 2,
            NamedCurve::Sect163r2 => 3,
            NamedCurve::Sect193r1 => 4,
            NamedCurve::Sect193r2 => 5,
            NamedCurve::Sect233k1 => 6,
            NamedCurve::Sect233r1 => 7,
            NamedCurve::Sect239k1 => 8,
            NamedCurve::Sect283k1 => 9,
            NamedCurve::Sect283r1 => 10,
            NamedCurve::Sect409k1 => 11,
            NamedCurve::Sect409r1 => 12,
            NamedCurve::Sect571k1 => 13,
            NamedCurve::Sect571r1 => 14,
            NamedCurve::Secp160k1 => 15,
            NamedCurve::Secp160r1 => 16,
            NamedCurve::Secp160r2 => 17,
            NamedCurve::Secp192k1 => 18,
            NamedCurve::Secp192r1 => 19,
            NamedCurve::Secp224k1 => 20,
            NamedCurve::Secp224r1 => 21,
            NamedCurve::Secp256k1 => 22,
            NamedCurve::Secp256r1 => 23,
            NamedCurve::Secp384r1 => 24,
            NamedCurve::Secp521r1 => 25,
            NamedCurve::X25519 => 29,
            NamedCurve::X448 => 30,
            NamedCurve::Unknown(value) => *value,
        }
    }

    pub(crate) fn parse(input: &[u8]) -> IResult<&[u8], NamedCurve> {
        let (input, value) = be_u16(input)?;
        Ok((input, NamedCurve::from_u16(value)))
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
