use core::fmt;

use crate::codec::{CheckedSlice, Codec, CodecVariable};
use crate::types::{ContentType, Epoch, Length16, ProtocolVersion, SequenceNumber};
use crate::DimplError;

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
impl CodecVariable<()> for DtlsPlainText {
    fn encoded_length(&self) -> usize {
        ContentType::encoded_length()
            + ProtocolVersion::encoded_length()
            + Epoch::encoded_length()
            + SequenceNumber::encoded_length()
            + Length16::encoded_length()
            + self.fragment.encoded_length()
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        let out = {
            self.content_type().encode(out)?;
            &mut out[ContentType::encoded_length()..]
        };

        let out = {
            self.protocol_version().encode(out)?;
            &mut out[ProtocolVersion::encoded_length()..]
        };

        let out = {
            self.epoch().encode(out)?;
            &mut out[Epoch::encoded_length()..]
        };

        let out = {
            self.sequence_number().encode(out)?;
            &mut out[SequenceNumber::encoded_length()..]
        };

        let out = {
            let len: Length16 = self.fragment_length().try_into()?;
            len.encode(out)?;
            &mut out[Length16::encoded_length()..]
        };

        self.fragment().encode(out)
    }

    fn decode(bytes: &[u8], _: ()) -> Result<Self, DimplError> {
        let (checked, bytes) = bytes.checked_get(..ContentType::encoded_length())?;
        let content_type = ContentType::decode(checked)?;

        let (checked, bytes) = bytes.checked_get(..ProtocolVersion::encoded_length())?;
        let protocol_version = ProtocolVersion::decode(checked)?;

        let (checked, bytes) = bytes.checked_get(..Epoch::encoded_length())?;
        let epoch = Epoch::decode(checked)?;

        let (checked, bytes) = bytes.checked_get(..SequenceNumber::encoded_length())?;
        let sequence_number = SequenceNumber::decode(checked)?;

        let (checked, bytes) = bytes.checked_get(..Length16::encoded_length())?;
        let length = Length16::decode(checked)?;

        let (checked, _) = bytes.checked_get(..(*length as usize))?;

        let fragment = DtlsFragment::decode(checked, content_type)?;

        // Ensure decoded values equal that of what's expected by the fragment type.
        fragment.assert_decoded(content_type, protocol_version)?;

        Ok(Self {
            epoch,
            sequence_number,
            fragment,
        })
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
