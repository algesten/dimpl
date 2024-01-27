use crate::codec::{Checked, CheckedMut, CodecVar};
use crate::types::ctype::ContentType;
use crate::types::version::ProtocolVersion;
use crate::Error;

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
    ) -> Result<(), Error> {
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

fn ensure_content_type(expected: ContentType, decoded: ContentType) -> Result<(), Error> {
    if expected != decoded {
        Err(Error::BadContentType(expected, decoded))
    } else {
        Ok(())
    }
}

fn ensure_protocol_version(
    expected: ProtocolVersion,
    decoded: ProtocolVersion,
) -> Result<(), Error> {
    if expected != decoded {
        Err(Error::BadProtocolVersion(expected, decoded))
    } else {
        Ok(())
    }
}

impl CodecVar<ContentType> for DtlsFragment {
    fn encoded_length(&self) -> usize {
        match self {
            DtlsFragment::Handshake(i) => i.encoded_length(),
        }
    }

    fn encode(&self, out: CheckedMut<'_, u8>) -> Result<(), Error> {
        match self {
            DtlsFragment::Handshake(i) => i.encode(out),
        }
    }

    fn decode(bytes: Checked<u8>, content_type: ContentType) -> Result<Self, Error> {
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
