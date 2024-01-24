use crate::codec::Codec;
use crate::DimplError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl Codec for ContentType {
    fn encode_length(&self) -> usize {
        1
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        out[0] = (*self).into();
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DimplError> {
        Self::try_from(bytes[0])
    }
}

impl From<ContentType> for u8 {
    fn from(value: ContentType) -> Self {
        use ContentType::*;
        match value {
            ChangeCipherSpec => 20,
            Alert => 21,
            Handshake => 22,
            ApplicationData => 23,
        }
    }
}

impl TryFrom<u8> for ContentType {
    type Error = DimplError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use ContentType::*;
        let t = match value {
            20 => ChangeCipherSpec,
            21 => Alert,
            22 => Handshake,
            23 => ApplicationData,
            _ => return Err(DimplError::InvalidContentType(value)),
        };
        Ok(t)
    }
}
