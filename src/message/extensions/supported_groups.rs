use crate::buffer::Buf;
use crate::crypto::CryptoProvider;
use crate::message::NamedGroup;
use arrayvec::ArrayVec;
use nom::IResult;

/// SupportedGroups extension as defined in RFC 8422
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedGroupsExtension {
    pub groups: ArrayVec<NamedGroup, 4>,
}

impl SupportedGroupsExtension {
    /// Create a SupportedGroupsExtension from a crypto provider
    pub fn from_provider(provider: &CryptoProvider) -> Self {
        let mut groups = ArrayVec::new();
        for kx_group in provider.supported_kx_groups() {
            groups.push(kx_group.name());
        }
        SupportedGroupsExtension { groups }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], SupportedGroupsExtension> {
        let (mut input, list_len) = nom::number::complete::be_u16(input)?;
        let mut groups: ArrayVec<NamedGroup, 4> = ArrayVec::new();
        let mut remaining = list_len as usize;

        // Parse groups; only include supported groups (skip Unknown and unsupported)
        while remaining >= 2 {
            let (rest, group) = NamedGroup::parse(input)?;
            input = rest;
            remaining -= 2;
            // Only add supported groups
            if group.is_supported() {
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

    #[test]
    fn test_supported_groups_extension() {
        let mut groups = ArrayVec::new();
        groups.push(NamedGroup::X25519);
        groups.push(NamedGroup::Secp256r1);

        let ext = SupportedGroupsExtension { groups };

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        let expected = [
            0x00, 0x04, // Groups length (4 bytes)
            0x00, 0x1D, // X25519 (0x001D)
            0x00, 0x17, // secp256r1 (0x0017)
        ];

        assert_eq!(&*serialized, expected);

        let (_, parsed) = SupportedGroupsExtension::parse(&serialized).unwrap();

        assert_eq!(parsed.groups.as_slice(), ext.groups.as_slice());
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

        // Expect only the supported groups in order as they appear
        assert_eq!(
            parsed.groups.as_slice(),
            &[
                NamedGroup::X25519,
                NamedGroup::Secp256r1,
                NamedGroup::Secp384r1
            ]
        );
    }

    #[test]
    fn capacity_matches_supported() {
        let ext = SupportedGroupsExtension {
            groups: ArrayVec::new(),
        };
        assert_eq!(
            ext.groups.capacity(),
            NamedGroup::supported().len(),
            "SupportedGroupsExtension capacity must match all supported NamedGroups"
        );
    }
}
