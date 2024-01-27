use crate::codec::{Checked, CheckedMut, Codec, CodecVar};
use crate::types::handshake::HandshakeType;
use crate::types::numerics::{FragmentLength, FragmentOffset, Length24, MessageSeq};
use crate::Error;

use super::client_hello::ClientHello;

#[derive(Debug, Clone)]
pub struct Handshake {
    pub handshake_type: HandshakeType,
    pub length: Length24,
    pub message_seq: MessageSeq,
    pub fragment_offset: FragmentOffset,
    pub fragment_length: FragmentLength,
    pub body: HandshakeVariant,
}

impl CodecVar for Handshake {
    fn encoded_length(&self) -> usize {
        HandshakeType::encoded_length()
            + Length24::encoded_length()
            + MessageSeq::encoded_length()
            + FragmentOffset::encoded_length()
            + FragmentLength::encoded_length()
            + self.body.encoded_length()
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        let out = self.handshake_type.encode_fixed(&mut *out)?;
        let out = self.length.encode_fixed(out)?;
        let out = self.message_seq.encode_fixed(out)?;
        let out = self.fragment_offset.encode_fixed(out)?;
        let out = self.fragment_length.encode_fixed(out)?;
        self.body.encode_variable(out)?;
        Ok(())
    }

    fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
        let (handshake_type, bytes) = HandshakeType::decode_fixed(&bytes)?;
        let (length, bytes) = Length24::decode_fixed(bytes)?;
        let (message_seq, bytes) = MessageSeq::decode_fixed(bytes)?;
        let (fragment_offset, bytes) = FragmentOffset::decode_fixed(bytes)?;
        let (fragment_length, bytes) = FragmentLength::decode_fixed(bytes)?;

        let (body, _) =
            HandshakeVariant::decode_variable(bytes, *fragment_length as usize, handshake_type)?;

        Ok(Handshake {
            handshake_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length,
            body,
        })
    }
}

#[derive(Debug, Clone)]
pub enum HandshakeVariant {
    ClientHello(ClientHello),
}

impl CodecVar<HandshakeType> for HandshakeVariant {
    fn encoded_length(&self) -> usize {
        match self {
            HandshakeVariant::ClientHello(i) => i.encoded_length(),
        }
    }

    fn encode(&self, out: CheckedMut<'_, u8>) -> Result<(), Error> {
        match self {
            HandshakeVariant::ClientHello(i) => i.encode(out),
        }
    }

    fn decode(bytes: Checked<u8>, handshake_type: HandshakeType) -> Result<Self, Error> {
        Ok(match handshake_type {
            HandshakeType::HelloRequest => todo!(),
            HandshakeType::ClientHello => Self::ClientHello(ClientHello::decode(bytes, ())?),
            HandshakeType::ServerHello => todo!(),
            HandshakeType::HelloVerifyRequest => todo!(),
            HandshakeType::Certificate => todo!(),
            HandshakeType::ServerKeyExchange => todo!(),
            HandshakeType::CertificateRequest => todo!(),
            HandshakeType::ServerHelloDone => todo!(),
            HandshakeType::CertificateVerify => todo!(),
            HandshakeType::ClientKeyExchange => todo!(),
            HandshakeType::Finished => todo!(),
        })
    }
}
