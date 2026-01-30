//! DTLS 1.2 curve type definitions.
//!
//! NamedGroup is now in crate::types as it's shared between DTLS versions.
//! CurveType is DTLS 1.2 specific (used in ServerKeyExchange).

use nom::number::complete::be_u8;
use nom::IResult;

/// Curve type for ECDH parameters in DTLS 1.2.
///
/// This is specific to DTLS 1.2's ServerKeyExchange message format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveType {
    /// Explicit prime curve parameters.
    ExplicitPrime,
    /// Explicit characteristic-2 curve parameters.
    ExplicitChar2,
    /// Named curve (the common case).
    NamedCurve,
    /// Unknown curve type.
    Unknown(u8),
}

impl CurveType {
    /// Convert a u8 value to a `CurveType`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => CurveType::ExplicitPrime,
            2 => CurveType::ExplicitChar2,
            3 => CurveType::NamedCurve,
            _ => CurveType::Unknown(value),
        }
    }

    /// Convert this `CurveType` to its u8 value.
    pub fn as_u8(&self) -> u8 {
        match self {
            CurveType::ExplicitPrime => 1,
            CurveType::ExplicitChar2 => 2,
            CurveType::NamedCurve => 3,
            CurveType::Unknown(value) => *value,
        }
    }

    /// Parse a `CurveType` from wire format.
    pub fn parse(input: &[u8]) -> IResult<&[u8], CurveType> {
        let (input, value) = be_u8(input)?;
        Ok((input, CurveType::from_u8(value)))
    }
}
