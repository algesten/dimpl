use crate::buffer::Buf;
use crate::SrtpProfile;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;

/// DTLS-SRTP protection profile identifiers
/// From RFC 5764 Section 4.1.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(non_camel_case_types)]
pub enum SrtpProfileId {
    #[default]
    SRTP_AES128_CM_SHA1_80 = 0x0001,
    SRTP_AEAD_AES_128_GCM = 0x0007,
    SRTP_AEAD_AES_256_GCM = 0x0008,
}

impl SrtpProfileId {
    pub fn parse(input: &[u8]) -> IResult<&[u8], SrtpProfileId> {
        let (input, value) = be_u16(input)?;
        let profile = match value {
            0x0001 => SrtpProfileId::SRTP_AES128_CM_SHA1_80,
            0x0007 => SrtpProfileId::SRTP_AEAD_AES_128_GCM,
            0x0008 => SrtpProfileId::SRTP_AEAD_AES_256_GCM,
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Switch,
                )))
            }
        };
        Ok((input, profile))
    }

    pub fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// All supported SRTP profile IDs.
    pub fn all() -> &'static [SrtpProfileId] {
        &[
            SrtpProfileId::SRTP_AES128_CM_SHA1_80,
            SrtpProfileId::SRTP_AEAD_AES_128_GCM,
            SrtpProfileId::SRTP_AEAD_AES_256_GCM,
        ]
    }
}

impl From<SrtpProfile> for SrtpProfileId {
    fn from(profile: SrtpProfile) -> Self {
        match profile {
            SrtpProfile::AES128_CM_SHA1_80 => SrtpProfileId::SRTP_AES128_CM_SHA1_80,
            SrtpProfile::AEAD_AES_128_GCM => SrtpProfileId::SRTP_AEAD_AES_128_GCM,
            SrtpProfile::AEAD_AES_256_GCM => SrtpProfileId::SRTP_AEAD_AES_256_GCM,
        }
    }
}

impl From<SrtpProfileId> for SrtpProfile {
    fn from(profile: SrtpProfileId) -> Self {
        match profile {
            SrtpProfileId::SRTP_AES128_CM_SHA1_80 => SrtpProfile::AES128_CM_SHA1_80,
            SrtpProfileId::SRTP_AEAD_AES_128_GCM => SrtpProfile::AEAD_AES_128_GCM,
            SrtpProfileId::SRTP_AEAD_AES_256_GCM => SrtpProfile::AEAD_AES_256_GCM,
        }
    }
}

/// UseSrtp extension as defined in RFC 5764
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseSrtpExtension {
    pub profiles: ArrayVec<SrtpProfileId, 3>,
    pub mki: Vec<u8>, // MKI value (usually empty)
}

impl UseSrtpExtension {
    pub fn new(profiles: ArrayVec<SrtpProfileId, 3>, mki: Vec<u8>) -> Self {
        UseSrtpExtension { profiles, mki }
    }

    /// Create a default UseSrtpExtension with standard profiles
    pub fn default() -> Self {
        let mut profiles = ArrayVec::new();
        // Add profiles in order of preference (most secure first)
        profiles.push(SrtpProfileId::SRTP_AEAD_AES_256_GCM);
        profiles.push(SrtpProfileId::SRTP_AEAD_AES_128_GCM);
        profiles.push(SrtpProfileId::SRTP_AES128_CM_SHA1_80);

        // MKI is typically empty as per RFC 5764
        let mki = Vec::new();

        UseSrtpExtension { profiles, mki }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], UseSrtpExtension> {
        let (input, profiles_length) = be_u16(input)?;
        let (input, profiles_data) = take(profiles_length)(input)?;

        // Parse the profiles (ignore unknown profile IDs instead of failing)
        let mut profiles: ArrayVec<SrtpProfileId, 3> = ArrayVec::new();
        let mut profiles_rest = profiles_data;

        while profiles_rest.len() >= 2 {
            let (rest, value) = be_u16(profiles_rest)?;
            profiles_rest = rest;
            match value {
                0x0001 => profiles.push(SrtpProfileId::SRTP_AES128_CM_SHA1_80),
                0x0007 => profiles.push(SrtpProfileId::SRTP_AEAD_AES_128_GCM),
                0x0008 => profiles.push(SrtpProfileId::SRTP_AEAD_AES_256_GCM),
                _ => {
                    // Unknown SRTP profile: skip
                }
            }
        }

        // Parse MKI
        let (input, mki_length) = be_u8(input)?;
        let (input, mki) = take(mki_length)(input)?;

        Ok((
            input,
            UseSrtpExtension {
                profiles,
                mki: mki.to_vec(),
            },
        ))
    }

    pub fn serialize(&self, output: &mut Buf) {
        // Length of all profiles (2 bytes per profile)
        output.extend_from_slice(&((self.profiles.len() * 2) as u16).to_be_bytes());

        // Write each profile
        for profile in &self.profiles {
            output.extend_from_slice(&profile.as_u16().to_be_bytes());
        }

        // MKI length and data
        output.push(self.mki.len() as u8);
        output.extend_from_slice(&self.mki);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    #[test]
    fn test_use_srtp_extension() {
        let mut profiles = ArrayVec::new();
        profiles.push(SrtpProfileId::SRTP_AEAD_AES_256_GCM);
        profiles.push(SrtpProfileId::SRTP_AEAD_AES_128_GCM);
        profiles.push(SrtpProfileId::SRTP_AES128_CM_SHA1_80);

        let mki = vec![1, 2, 3];

        let ext = UseSrtpExtension::new(profiles, mki.clone());

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        let expected = [
            0x00, 0x06, // Profiles length (6 bytes)
            0x00, 0x08, // SRTP_AEAD_AES_256_GCM (0x0008)
            0x00, 0x07, // SRTP_AEAD_AES_128_GCM (0x0007)
            0x00, 0x01, // SRTP_AES128_CM_SHA1_80 (0x0001)
            0x03, // MKI length (3 bytes)
            0x01, 0x02, 0x03, // MKI
        ];

        assert_eq!(&*serialized, expected);

        let (_, parsed) = UseSrtpExtension::parse(&serialized).unwrap();

        assert_eq!(parsed.profiles.as_slice(), ext.profiles.as_slice());
        assert_eq!(parsed.mki, mki);
    }

    #[test]
    fn test_use_srtp_parse_provided_bytes() {
        let bytes = [0, 8, 0, 7, 0, 8, 0, 1, 0, 2, 0];

        let (_, parsed) = UseSrtpExtension::parse(&bytes).expect("parse UseSrtpExtension");

        assert_eq!(
            parsed.profiles.as_slice(),
            &[
                SrtpProfileId::SRTP_AEAD_AES_128_GCM,
                SrtpProfileId::SRTP_AEAD_AES_256_GCM,
                SrtpProfileId::SRTP_AES128_CM_SHA1_80
            ]
        );
        assert_eq!(parsed.mki, Vec::<u8>::new());
    }

    #[test]
    fn capacity_matches_profile_count() {
        let ext = UseSrtpExtension::default();
        assert_eq!(
            ext.profiles.capacity(),
            SrtpProfileId::all().len(),
            "UseSrtpExtension capacity must match all profile IDs"
        );
    }
}
