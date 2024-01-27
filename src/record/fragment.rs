use crate::codec::CodecVariable;
use crate::types::ctype::ContentType;
use crate::types::version::ProtocolVersion;
use crate::DimplError;

use super::handshake::{Handshake, HandshakeVariant};

#[derive(Debug, Clone)]
pub enum DtlsFragment {
    Handshake(Handshake),
}

impl DtlsFragment {
    pub fn assert_decoded(
        &self,
        content_type: ContentType,
        protocol_version: ProtocolVersion,
    ) -> Result<(), DimplError> {
        match self {
            DtlsFragment::Handshake(h) => match &h.body {
                HandshakeVariant::ClientHello(_) => {
                    ensure_content_type(ContentType::Handshake, content_type)?;
                    ensure_protocol_version(ProtocolVersion::Dtls1_0, protocol_version)?;
                }
            },
        }
        Ok(())
    }
}

fn ensure_content_type(expected: ContentType, decoded: ContentType) -> Result<(), DimplError> {
    if expected != decoded {
        Err(DimplError::BadContentType(expected, decoded))
    } else {
        Ok(())
    }
}

fn ensure_protocol_version(
    expected: ProtocolVersion,
    decoded: ProtocolVersion,
) -> Result<(), DimplError> {
    if expected != decoded {
        Err(DimplError::BadProtocolVersion(expected, decoded))
    } else {
        Ok(())
    }
}

impl CodecVariable<ContentType> for DtlsFragment {
    fn encoded_length(&self) -> usize {
        match self {
            DtlsFragment::Handshake(i) => i.encoded_length(),
        }
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        match self {
            DtlsFragment::Handshake(i) => i.encode(out),
        }
    }

    fn decode(bytes: &[u8], content_type: ContentType) -> Result<Self, DimplError> {
        Ok(match content_type {
            ContentType::Handshake => Self::Handshake(Handshake::decode(bytes, ())?),
            ContentType::ChangeCipherSpec => todo!(),
            ContentType::ApplicationData => todo!(),
            ContentType::Alert => todo!(),
        })
    }
}

impl From<&DtlsFragment> for ContentType {
    fn from(value: &DtlsFragment) -> Self {
        match value {
            DtlsFragment::Handshake(_) => ContentType::Handshake,
        }
    }
}

impl From<&DtlsFragment> for ProtocolVersion {
    fn from(value: &DtlsFragment) -> Self {
        match value {
            DtlsFragment::Handshake(h) => {
                if matches!(h.body, HandshakeVariant::ClientHello(_)) {
                    return ProtocolVersion::Dtls1_0;
                } else {
                    todo!()
                }
            }
        }
    }
}
