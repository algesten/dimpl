use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCurve {
    Sect163k1,
    Sect163r1,
    Sect163r2,
    Sect193r1,
    Sect193r2,
    Sect233k1,
    Sect233r1,
    Sect239k1,
    Sect283k1,
    Sect283r1,
    Sect409k1,
    Sect409r1,
    Sect571k1,
    Sect571r1,
    Secp160k1,
    Secp160r1,
    Secp160r2,
    Secp192k1,
    Secp192r1,
    Secp224k1,
    Secp224r1,
    Secp256k1,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    X25519,
    X448,
    Unknown(u16),
}

impl NamedCurve {
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

    pub fn to_u16(&self) -> u16 {
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

    pub fn parse(input: &[u8]) -> IResult<&[u8], NamedCurve> {
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

    pub fn to_u8(&self) -> u8 {
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
