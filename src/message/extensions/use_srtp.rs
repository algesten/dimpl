use crate::buffer::Buf;
use crate::crypto::SrtpProfile;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use tinyvec::ArrayVec;

/// DTLS-SRTP protection profile identifiers
/// From RFC 5764 Section 4.1.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SrtpProfileId {
    #[default]
    SrtpAes128CmSha1_80 = 0x0001,
    SrtpAeadAes128Gcm = 0x0007,
}

impl SrtpProfileId {
    pub fn parse(input: &[u8]) -> IResult<&[u8], SrtpProfileId> {
        let (input, value) = be_u16(input)?;
        let profile = match value {
            0x0001 => SrtpProfileId::SrtpAes128CmSha1_80,
            0x0007 => SrtpProfileId::SrtpAeadAes128Gcm,
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

    /// Convert SrtpProfileId to SrtpProfile
    pub fn to_srtp_profile(&self) -> SrtpProfile {
        match self {
            SrtpProfileId::SrtpAes128CmSha1_80 => SrtpProfile::Aes128CmSha1_80,
            SrtpProfileId::SrtpAeadAes128Gcm => SrtpProfile::AeadAes128Gcm,
        }
    }
}

/// UseSrtp extension as defined in RFC 5764
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseSrtpExtension {
    pub profiles: ArrayVec<[SrtpProfileId; 32]>,
    pub mki: Vec<u8>, // MKI value (usually empty)
}

impl UseSrtpExtension {
    pub fn new(profiles: ArrayVec<[SrtpProfileId; 32]>, mki: Vec<u8>) -> Self {
        UseSrtpExtension { profiles, mki }
    }

    /// Create a default UseSrtpExtension with standard profiles
    pub fn default() -> Self {
        let mut profiles = ArrayVec::new();
        // Add profiles in order of preference (most secure first)
        profiles.push(SrtpProfileId::SrtpAeadAes128Gcm);
        profiles.push(SrtpProfileId::SrtpAes128CmSha1_80);

        // MKI is typically empty as per RFC 5764
        let mki = Vec::new();

        UseSrtpExtension { profiles, mki }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], UseSrtpExtension> {
        let (input, profiles_length) = be_u16(input)?;
        let (input, profiles_data) = take(profiles_length)(input)?;

        // Parse the profiles
        let mut profiles = ArrayVec::new();
        let mut profiles_rest = profiles_data;

        while !profiles_rest.is_empty() {
            let (rest, profile) = SrtpProfileId::parse(profiles_rest)?;
            profiles.push(profile);
            profiles_rest = rest;
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

    pub fn serialize(&self, output: &mut Buf<'static>) {
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
    use tinyvec::array_vec;

    #[test]
    fn test_use_srtp_extension() {
        let profiles = array_vec![
            SrtpProfileId::SrtpAeadAes128Gcm,
            SrtpProfileId::SrtpAes128CmSha1_80
        ];

        let mki = vec![1, 2, 3];

        let ext = UseSrtpExtension::new(profiles.clone(), mki.clone());

        let mut serialized = Buf::new();
        ext.serialize(&mut serialized);

        let expected = [
            0x00, 0x04, // Profiles length (4 bytes)
            0x00, 0x07, // SrtpAeadAes128Gcm (0x0007)
            0x00, 0x01, // SrtpAes128CmSha1_80 (0x0001)
            0x03, // MKI length (3 bytes)
            0x01, 0x02, 0x03, // MKI
        ];

        assert_eq!(&*serialized, expected);

        let (_, parsed) = UseSrtpExtension::parse(&serialized).unwrap();

        assert_eq!(parsed.profiles, profiles);
        assert_eq!(parsed.mki, mki);
    }
}
