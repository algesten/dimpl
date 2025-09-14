use crate::buffer::Buf;
use nom::{number::complete::be_u16, IResult};
use tinyvec::ArrayVec;

/// Supported Groups (previously known as EllipticCurves) extension
/// RFC 8422 Section 5.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NamedGroup {
    #[default]
    Secp256r1 = 0x0017, // NIST P-256
    Secp384r1 = 0x0018, // NIST P-384
    Secp521r1 = 0x0019, // NIST P-521
    X25519 = 0x001D,    // Curve25519
    X448 = 0x001E,      // Curve448
}

impl NamedGroup {
    pub fn parse(input: &[u8]) -> IResult<&[u8], NamedGroup> {
        let (input, value) = be_u16(input)?;
        let group = match value {
            0x0017 => NamedGroup::Secp256r1,
            0x0018 => NamedGroup::Secp384r1,
            0x0019 => NamedGroup::Secp521r1,
            0x001D => NamedGroup::X25519,
            0x001E => NamedGroup::X448,
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Switch,
                )))
            }
        };
        Ok((input, group))
    }

    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

/// SupportedGroups extension as defined in RFC 8422
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedGroupsExtension {
    pub groups: ArrayVec<[NamedGroup; 5]>,
}

impl SupportedGroupsExtension {
    pub fn new(groups: ArrayVec<[NamedGroup; 5]>) -> Self {
        SupportedGroupsExtension { groups }
    }

    /// Create a default SupportedGroupsExtension with standard curves
    pub fn default() -> Self {
        let mut groups = ArrayVec::new();
        groups.push(NamedGroup::Secp256r1); // NIST P-256 (widely supported)
        groups.push(NamedGroup::Secp384r1); // NIST P-384 (stronger)
        SupportedGroupsExtension { groups }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SupportedGroupsExtension> {
        let (input, list_len) = be_u16(input)?;
        let mut groups = ArrayVec::new();
        let mut remaining = list_len as usize;
        let mut current_input = input;

        while remaining > 0 {
            let (rest, group) = NamedGroup::parse(current_input)?;
            groups.push(group);
            current_input = rest;
            remaining -= 2; // Each group is 2 bytes
        }

        Ok((current_input, SupportedGroupsExtension { groups }))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        // Write the total length of all groups (2 bytes per group)
        output.extend_from_slice(&((self.groups.len() * 2) as u16).to_be_bytes());

        // Write each group
        for group in &self.groups {
            output.extend_from_slice(&group.as_u16().to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;
    use tinyvec::array_vec;

    #[test]
    fn test_supported_groups_extension() {
        let groups = array_vec![NamedGroup::X25519, NamedGroup::Secp256r1];

        let ext = SupportedGroupsExtension::new(groups.clone());

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        let expected = [
            0x00, 0x04, // Groups length (4 bytes)
            0x00, 0x1D, // X25519 (0x001D)
            0x00, 0x17, // secp256r1 (0x0017)
        ];

        assert_eq!(&*serialized, expected);

        let (_, parsed) = SupportedGroupsExtension::parse(&serialized).unwrap();

        assert_eq!(parsed.groups, groups);
    }
}
