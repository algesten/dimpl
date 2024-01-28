use core::fmt;

use arrayvec::ArrayVec;

use crate::codec::{Checked, CheckedMut, Codec, CodecVar, CodecVarLen, SliceCheck};
use crate::Error;

use super::varvec::{EcPointFormatList, RenegotiatedConnection, SrtpMki, SrtpProtectionProfiles};

pub struct Extensions {
    inner: ArrayVec<Extension, 100>,
}

impl Extensions {
    pub fn new() -> Self {
        Extensions {
            inner: ArrayVec::new(),
        }
    }
}

impl CodecVar for Extensions {
    fn encoded_length(&self) -> usize {
        self.inner.iter().map(|e| e.encoded_length()).sum()
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        // This is ok because the inner ArrayVec is less than usize.
        let len: u16 = self.inner.len() as u16;

        // Prepend length
        let mut out = len.encode_fixed(&mut out)?;

        // Encode each extension.
        for e in &self.inner {
            out = e.encode_variable(out)?;
        }

        Ok(())
    }

    fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
        let (byte_len, mut bytes) = u16::decode_fixed(&bytes)?;
        let byte_len = byte_len as usize;

        let mut inner = ArrayVec::new();

        let mut total: usize = 0;

        while total < byte_len {
            let l = Extension::do_read_internal_length(bytes)?;
            println!("{} {} {}", l, total, bytes.len());
            total += l as usize;
            let (e, b) = Extension::decode_variable_internal_length(&bytes, ())?;
            inner.push(e);
            bytes = b;
        }

        Ok(Self { inner })
    }
}

impl CodecVarLen for Extensions {
    fn min_needed_length() -> usize {
        unreachable!("The length is calculated by iterating the extensions")
    }

    fn read_internal_length(_: Checked<u8>) -> Result<usize, Error> {
        unreachable!("The length is calculated by iterating the extensions")
    }

    fn do_read_internal_length(bytes: &[u8]) -> Result<usize, Error> {
        let (byte_len, mut bytes) = u16::decode_fixed(&bytes)?;
        let byte_len = byte_len as usize;

        let mut total = 0;

        while total < byte_len {
            // Each extension is at least 4 bytes, 2 for type, 2 for length
            let (checked, _) = bytes.checked_split(4)?;

            let checked = checked.skip(2)?; // skip the type
            let (data_len, _) = u16::decode_fixed(&checked)?;

            // The single extension
            let ext_len = data_len as usize + 4;
            total += ext_len; // Increase total

            let (_, rest) = bytes.checked_split(ext_len)?;
            bytes = rest;
        }

        Ok(total + 2)
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.inner.iter()).finish()
    }
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
#[derive(Debug, Clone)]
pub enum Extension {
    RenegotiationInfo(RenegotiationInfo),
    EcPointFormat(EcPointFormatList),
    UseSrtp(UseSrtp),
    ExtendedMasterSecret(ExtendedMasterSecret),
    Unknown(u16),
}

impl From<Extension> for u16 {
    fn from(value: Extension) -> Self {
        match value {
            Extension::RenegotiationInfo(_) => 65281,
            Extension::EcPointFormat(_) => 11,
            Extension::UseSrtp(_) => 14,
            Extension::ExtendedMasterSecret(_) => 23,
            Extension::Unknown(_) => {
                unreachable!("Encode unknown ExtensionType")
            }
        }
    }
}

// https://www.ietf.org/rfc/rfc5746.txt
#[derive(Debug, Clone)]
pub struct RenegotiationInfo {
    pub inner: RenegotiatedConnection,
}

// https://www.rfc-editor.org/rfc/rfc8422.html
#[derive(Debug, Clone)]
pub enum EcPointFormat {
    Uncompressed,
    Unknown(u8),
}

impl Codec for EcPointFormat {
    fn encoded_length() -> usize {
        1
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        match self {
            EcPointFormat::Uncompressed => {
                out[0] = 0;
            }
            EcPointFormat::Unknown(_) => unreachable!("Attempt to encode Unknown EcPointFormat"),
        }
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        Ok(match bytes[0] {
            0 => EcPointFormat::Uncompressed,
            _ => EcPointFormat::Unknown(bytes[0]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct UseSrtp {
    pub profiles: SrtpProtectionProfiles,
    pub srtp_mki: SrtpMki,
}

impl CodecVar for UseSrtp {
    fn encoded_length(&self) -> usize {
        self.profiles.encoded_length() + self.srtp_mki.encoded_length()
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        let out = self.profiles.encode_variable(&mut out)?;
        self.srtp_mki.encode_variable(out)?;
        Ok(())
    }

    fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
        let (profiles, bytes) =
            SrtpProtectionProfiles::decode_variable_internal_length(&bytes, ())?;
        let (srtp_mki, _) = SrtpMki::decode_variable_internal_length(bytes, ())?;

        Ok(UseSrtp { profiles, srtp_mki })
    }
}

impl CodecVarLen for UseSrtp {
    fn min_needed_length() -> usize {
        unreachable!("min_needed_length on UseSrtp")
    }

    fn read_internal_length(_: Checked<u8>) -> Result<usize, Error> {
        unreachable!("read_internal_length on UseSrtp")
    }

    fn do_read_internal_length(bytes: &[u8]) -> Result<usize, Error> {
        let (checked, bytes) = bytes.checked_split(2)?;
        let len1 = SrtpProtectionProfiles::read_internal_length(checked)?;
        let (checked, _) = bytes.checked_split(len1 as usize)?;
        let len2 = SrtpMki::read_internal_length(checked)?;
        Ok(len1 + len2 + 4)
    }
}

// SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_80 = {0x00, 0x01};
// SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_32 = {0x00, 0x02};
// SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_80      = {0x00, 0x05};
// SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_32      = {0x00, 0x06};
// SRTPProtectionProfile SRTP_AEAD_AES_128_GCM       = {0x00, 0x07};
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum SrtpProtectionProfile {
    SRTP_AEAD_AES_128_GCM,
    Unknown(u8, u8),
}

impl Codec for SrtpProtectionProfile {
    fn encoded_length() -> usize {
        2
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        match self {
            SrtpProtectionProfile::SRTP_AEAD_AES_128_GCM => {
                out[0] = 0x00;
                out[1] = 0x07;
            }
            SrtpProtectionProfile::Unknown(_, _) => {
                unreachable!("Attempt to encode SrtpProtectionProfile Unknown")
            }
        }
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        Ok(match (bytes[0], bytes[1]) {
            (0x00, 0x07) => SrtpProtectionProfile::SRTP_AEAD_AES_128_GCM,
            _ => SrtpProtectionProfile::Unknown(bytes[0], bytes[1]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedMasterSecret;

impl CodecVar for ExtendedMasterSecret {
    fn encoded_length(&self) -> usize {
        2
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        out[0] = 0;
        out[1] = 0;
        Ok(())
    }

    fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
        if bytes[0] == 0 && bytes[1] == 0 {
            Ok(Self)
        } else {
            Err(Error::BadIncomingExtension)
        }
    }
}

// impl TryFrom<u16> for Extension {
//     type Error = Error;

//     fn try_from(value: u16) -> Result<Self, Self::Error> {
//         use Extension::*;
//         Ok(match value {
//             65281 => RenegotiationInfo,
//             11 => EcPointFormat,
//             35 => SessionTicket,
//             14 => UseSrtp,
//             23 => ExtendedMasterSecret,
//             _ => Unknown(value),
//         })
//     }
// }

impl CodecVar for Extension {
    fn encoded_length(&self) -> usize {
        use Extension::*;
        match self {
            RenegotiationInfo(i) => i.encoded_length(),
            EcPointFormat(i) => i.encoded_length(),
            UseSrtp(i) => i.encoded_length(),
            ExtendedMasterSecret(i) => i.encoded_length(),
            Unknown(_) => {
                unreachable!("Encoded length of Unknown Extension")
            }
        }
    }

    fn encode(&self, out: CheckedMut<'_, u8>) -> Result<(), Error> {
        use Extension::*;
        match self {
            RenegotiationInfo(i) => i.encode(out),
            EcPointFormat(i) => i.encode(out),
            UseSrtp(i) => i.encode(out),
            ExtendedMasterSecret(i) => i.encode(out),
            Unknown(_) => {
                unreachable!("Encoded of Unknown Extension")
            }
        }
    }

    fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
        let (typ, bytes) = u16::decode_fixed(&bytes)?;
        println!("typ {} {}", typ, bytes.len());
        Ok(match typ {
            65281 => Self::RenegotiationInfo(
                RenegotiationInfo::decode_variable_internal_length(&bytes, ())?.0,
            ),
            11 => Self::EcPointFormat(
                EcPointFormatList::decode_variable_internal_length(&bytes, ())?.0,
            ),
            14 => Self::UseSrtp(UseSrtp::decode_variable_internal_length(&bytes, ())?.0),
            23 => {
                Self::ExtendedMasterSecret(ExtendedMasterSecret::decode_variable(&bytes, 2, ())?.0)
            }
            _ => Self::Unknown(typ),
        })
    }
}

impl CodecVarLen for Extension {
    fn min_needed_length() -> usize {
        4
    }

    fn read_internal_length(bytes: Checked<u8>) -> Result<usize, Error> {
        // First 2 is the type.
        let bytes = bytes.skip(2)?;
        let (len, _) = u16::decode_fixed(&bytes)?;
        Ok(len as usize + 4)
    }
}

// For wrapper structs that proxy the encoding to an `inner` target.
macro_rules! passthrough {
    ($name:ty, $typ:ty) => {
        impl CodecVar for $name {
            fn encoded_length(&self) -> usize {
                self.inner.encoded_length()
            }

            fn encode(&self, out: CheckedMut<'_, u8>) -> Result<(), Error> {
                self.inner.encode(out)
            }

            fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
                let inner = <$typ>::decode(bytes, ())?;
                Ok(Self { inner })
            }
        }

        impl CodecVarLen for $name {
            fn min_needed_length() -> usize {
                2
            }

            fn read_internal_length(bytes: Checked<u8>) -> Result<usize, Error> {
                let (len, _) = u16::decode_fixed(&bytes)?;
                Ok(len as usize + 2)
            }
        }
    };
}

passthrough!(RenegotiationInfo, RenegotiatedConnection);

#[cfg(test)]
mod test {
    use super::*;

    const TEST_DATA: &[u8] = &[
        0x00, 0x1e, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        0x00, 0x23, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x17,
        0x00, 0x00,
    ];

    #[test]
    fn decode_extensions() {
        let x = Extensions::decode_variable_internal_length(TEST_DATA, ()).unwrap();

        // Extension { extension_type: RenegotiationInfo, extension_data: [0] },
        // Extension { extension_type: EcPointFormat, extension_data: [3, 0, 1, 2] },
        // Extension { extension_type: SessionTicket, extension_data: [] },
        // Extension { extension_type: UseSrtp, extension_data: [0, 2, 0, 7, 0] },
        // Extension { extension_type: ExtendedMasterSecret, extension_data: [] }]
    }
}
