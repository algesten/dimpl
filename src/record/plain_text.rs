use core::fmt;

use crate::codec::{Checked, CheckedMut, Codec, CodecVar, CodecVarLen};
use crate::types::ctype::ContentType;
use crate::types::numerics::{Epoch, Length16, SequenceNumber};
use crate::types::version::ProtocolVersion;
use crate::Error;

use super::fragment::DtlsFragment;

#[derive(Clone)]
pub struct DtlsPlainText {
    epoch: Epoch,
    sequence_number: SequenceNumber,
    fragment: DtlsFragment,
}

impl DtlsPlainText {
    pub fn new(
        epoch: Epoch,
        sequence_number: SequenceNumber,
        fragment: impl Into<DtlsFragment>,
    ) -> Self {
        DtlsPlainText {
            epoch,
            sequence_number,
            fragment: fragment.into(),
        }
    }

    pub fn content_type(&self) -> ContentType {
        (&self.fragment).into()
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        (&self.fragment).into()
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn sequence_number(&self) -> SequenceNumber {
        self.sequence_number
    }

    pub fn fragment_length(&self) -> usize {
        todo!()
    }

    pub fn fragment(&self) -> &DtlsFragment {
        &self.fragment
    }
}

// https://datatracker.ietf.org/doc/html/rfc6347#page-8
//
// struct {
//     ContentType type;
//     ProtocolVersion version;
//     uint16 epoch;                                    // New field
//     uint48 sequence_number;                          // New field
//     uint16 length;
//     opaque fragment[DTLSPlaintext.length];
//   } DTLSPlaintext;
impl CodecVar for DtlsPlainText {
    fn encoded_length(&self) -> usize {
        Self::min_needed_length() + self.fragment.encoded_length()
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        let out = self.content_type().encode_fixed(&mut *out)?;
        let out = self.protocol_version().encode_fixed(out)?;
        let out = self.epoch().encode_fixed(out)?;
        let out = self.sequence_number().encode_fixed(out)?;
        let len: Length16 = self.fragment_length().try_into()?;
        let out = len.encode_fixed(out)?;

        self.fragment().encode_variable(out)?;

        Ok(())
    }

    fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
        let (content_type, bytes) = ContentType::decode_fixed(&bytes)?;
        let (protocol_version, bytes) = ProtocolVersion::decode_fixed(bytes)?;
        let (epoch, bytes) = Epoch::decode_fixed(bytes)?;
        let (sequence_number, bytes) = SequenceNumber::decode_fixed(bytes)?;
        let (length, bytes) = Length16::decode_fixed(bytes)?;

        let (fragment, _) = DtlsFragment::decode_variable(bytes, *length as usize, content_type)?;

        // Ensure decoded values equal that of what's expected by the fragment type.
        fragment.assert_decoded(content_type, protocol_version)?;

        Ok(Self {
            epoch,
            sequence_number,
            fragment,
        })
    }
}

impl CodecVarLen for DtlsPlainText {
    fn min_needed_length() -> usize {
        ContentType::encoded_length()
            + ProtocolVersion::encoded_length()
            + Epoch::encoded_length()
            + SequenceNumber::encoded_length()
            + Length16::encoded_length()
    }

    fn read_internal_length(bytes: Checked<u8>) -> Result<usize, Error> {
        let offset = Self::min_needed_length() - Length16::encoded_length();
        let (length, _) = Length16::decode_fixed(&bytes[offset..])?;
        let total = Self::min_needed_length() + *length as usize;
        Ok(total)
    }
}

impl fmt::Debug for DtlsPlainText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DtlsPlainText")
            .field("content_type", &self.content_type())
            .field("protocol_version", &self.protocol_version())
            .field("epoch", &self.epoch())
            .field("sequence_number", &self.sequence_number())
            .field("length", &self.fragment_length())
            .field("fragment", self.fragment())
            .finish()
    }
}
