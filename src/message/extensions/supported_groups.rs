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
    pub fn parse_opt(input: &[u8]) -> IResult<&[u8], Option<NamedGroup>> {
        let (input, value) = be_u16(input)?;
        Ok((input, NamedGroup::from_u16(value)))
    }

    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0017 => Some(NamedGroup::Secp256r1),
            0x0018 => Some(NamedGroup::Secp384r1),
            0x0019 => Some(NamedGroup::Secp521r1),
            0x001D => Some(NamedGroup::X25519),
            0x001E => Some(NamedGroup::X448),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

/// SupportedGroups extension as defined in RFC 8422
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedGroupsExtension {
    pub groups: ArrayVec<[NamedGroup; 16]>,
}

impl SupportedGroupsExtension {
    /// Create a default SupportedGroupsExtension with standard curves
    pub fn default() -> Self {
        let mut groups = ArrayVec::new();
        groups.push(NamedGroup::Secp256r1); // NIST P-256 (widely supported)
        groups.push(NamedGroup::Secp384r1); // NIST P-384 (stronger)
        SupportedGroupsExtension { groups }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SupportedGroupsExtension> {
        let (mut input, list_len) = be_u16(input)?;
        let mut groups = ArrayVec::new();
        let mut remaining = list_len as usize;

        // Parse groups; ignore unknown/unsupported ones (delegating to NamedGroup)
        while remaining >= 2 {
            let (rest, maybe_group) = NamedGroup::parse_opt(input)?;
            input = rest;
            remaining -= 2;
            if let Some(group) = maybe_group {
                groups.push(group);
            }
        }

        Ok((input, SupportedGroupsExtension { groups }))
    }

    pub fn serialize(&self, output: &mut Buf) {
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

        let ext = SupportedGroupsExtension {
            groups: groups.clone(),
        };

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

    #[test]
    fn test_supported_groups_parse_provided_bytes() {
        // Provided bytes: [0,10,0,29,0,23,0,24,1,0,1,1]
        // Meaning:
        // 0x000A -> list length = 10 bytes (5 groups)
        // groups: 0x001D (X25519), 0x0017 (P-256), 0x0018 (P-384), 0x0100 (unknown), 0x0101 (unknown)
        let bytes = [0, 10, 0, 29, 0, 23, 0, 24, 1, 0, 1, 1];

        let (rest, parsed) =
            SupportedGroupsExtension::parse(&bytes).expect("parse SupportedGroups");
        assert!(rest.is_empty());

        // Expect only the known groups in order as they appear
        assert_eq!(
            parsed.groups,
            array_vec![
                NamedGroup::X25519,
                NamedGroup::Secp256r1,
                NamedGroup::Secp384r1
            ]
        );
    }
}
