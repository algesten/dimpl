use crate::codec::{CheckedSlice, Codec};
use crate::DimplError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch(u16);

impl Epoch {
    /// Increase the epoch by one and error if it wraps.
    pub fn increase(&self) -> Result<Epoch, DimplError> {
        // https://datatracker.ietf.org/doc/html/rfc6347#section-4.1
        //
        // Similarly, implementations MUST NOT allow the epoch to wrap, but
        // instead MUST establish a new association
        match self.0.checked_add(1) {
            Some(v) => Ok(Epoch(v)),
            None => Err(DimplError::WrappedEpoch),
        }
    }
}

impl Codec for Epoch {
    fn encode_length(&self) -> usize {
        2
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        (&mut out[..self.encode_length()]).copy_from_slice(&self.0.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DimplError> {
        Ok(Self(u16::from_be_bytes(bytes.checked_arr()?)))
    }
}

/// Dtls sequence number u48.
///
/// Stored as big endian.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DtlsSeq(u64); // u48

impl DtlsSeq {
    /// Attempt increase the DtlsSeq. If this returns None, we must either
    /// abandon or rehandshake.
    pub fn maybe_increase(&self) -> Option<DtlsSeq> {
        // As in TLS, implementations MUST either abandon an association or
        // rehandshake prior to allowing the sequence number to wrap.
        let m = self.0 + 1;

        if Self::assert(m).is_err() {
            None
        } else {
            Some(DtlsSeq(m))
        }
    }

    #[inline(always)]
    fn assert(n: u64) -> Result<(), DimplError> {
        // 2^48
        const U48MAX: u64 = 2_u64.pow(48);

        if n > U48MAX {
            Err(DimplError::TooBigDtlsSeq(n))
        } else {
            Ok(())
        }
    }
}

impl Codec for DtlsSeq {
    fn encode_length(&self) -> usize {
        6
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        (&mut out[..self.encode_length()]).copy_from_slice(&self.0.to_be_bytes()[2..]);
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DimplError> {
        let b = bytes.checked_get(..6)?;
        let x = [0, 0, b[0], b[1], b[2], b[3], b[4], b[5]];
        let n = u64::from_be_bytes(x);
        Self::assert(n)?;
        Ok(Self(n))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Length(u16);

impl Length {
    #[inline(always)]
    fn assert(n: u16) -> Result<(), DimplError> {
        // https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.1
        //
        // The length (in bytes) of the following TLSPlaintext.fragment.  The
        // length MUST NOT exceed 2^14.
        if n > 16_384 {
            Err(DimplError::TooBigLength(n))
        } else {
            Ok(())
        }
    }
}

impl Codec for Length {
    fn encode_length(&self) -> usize {
        2
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        (&mut out[..self.encode_length()]).copy_from_slice(&self.0.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DimplError> {
        let n = u16::from_be_bytes(bytes.checked_arr()?);
        Self::assert(n)?;
        Ok(Self(n))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn len_allowed() {
        let x = &[0, 1, 2];
        let bytes = 16_384_u16.to_be_bytes();
        let r = Length::decode(&bytes);
        assert!(r.is_ok());
    }

    #[test]
    fn len_disallowed() {
        // let bytes = 16_385_u16.to_be_bytes();
        // let r = Length::decode(&bytes);
        // assert_eq!(r.unwrap_err(), DimplError::TooBigLength(16385));
    }
}
