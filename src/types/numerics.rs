use crate::codec::Codec;
use crate::DimplError;
use core::mem;
use core::ops::Deref;

trait NumericByteOffsets {
    fn offset() -> usize;
}

// ident - name
// numer - the numeric types to store the value in internally
// bytes - number of bytes to encode/decode into
// max   - max allowed value
macro_rules! numeric {
    ($name:ident, $numer:ty, $bytes:expr, $max:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name($numer);

        impl $name {
            #[inline(always)]
            fn assert(n: u64) -> Result<(), DimplError> {
                let n: u64 = n.into();

                if n > $max {
                    Err(DimplError::TooBigDtlsSeq(n))
                } else {
                    Ok(())
                }
            }
        }

        impl NumericByteOffsets for $name {
            fn offset() -> usize {
                mem::size_of::<$numer>() - Self::encoded_length()
            }
        }

        impl Codec for $name {
            fn encoded_length() -> usize {
                $bytes
            }

            fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
                let src = self.0.to_be_bytes();
                let dst = &mut out[..Self::encoded_length()];
                for (i, d) in dst.iter_mut().enumerate() {
                    *d = src[i + Self::offset()];
                }
                Ok(())
            }

            fn decode(bytes: &[u8]) -> Result<Self, DimplError> {
                let src = &bytes[..Self::encoded_length()];
                let x: $numer = 0;
                let mut a = x.to_be_bytes();
                for (i, d) in src.iter().enumerate() {
                    a[Self::offset() + i] = *d;
                }
                let n = <$numer>::from_be_bytes(a);
                Self::assert(n as u64)?;
                Ok(Self(n))
            }
        }

        impl Deref for $name {
            type Target = $numer;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl TryFrom<usize> for $name {
            type Error = DimplError;

            fn try_from(value: usize) -> Result<Self, Self::Error> {
                Self::assert(value as u64)?;
                Ok(Self(value as $numer))
            }
        }
    };
}

// uint16
numeric!(Epoch, u16, 2, u16::MAX as u64);

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

// uint48
numeric!(SequenceNumber, u64, 6, 2_u64.pow(48));

impl SequenceNumber {
    /// Attempt increase the DtlsSeq. If this returns None, we must either
    /// abandon or rehandshake.
    pub fn maybe_increase(&self) -> Option<SequenceNumber> {
        // As in TLS, implementations MUST either abandon an association or
        // rehandshake prior to allowing the sequence number to wrap.
        let m = self.0 + 1;

        if Self::assert(m).is_err() {
            None
        } else {
            Some(SequenceNumber(m))
        }
    }
}

// uint16
//
// https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.1
//
// The length (in bytes) of the following TLSPlaintext.fragment.  The
// length MUST NOT exceed 2^14.
numeric!(Length16, u16, 2, 16_384);

// uint24
numeric!(Length24, u32, 3, 2_u64.pow(24));

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn len_allowed() {
        let bytes = 16_384_u16.to_be_bytes();
        let r = Length16::decode(&bytes);
        assert!(r.is_ok());
    }

    #[test]
    fn len_disallowed() {
        // let bytes = 16_385_u16.to_be_bytes();
        // let r = Length::decode(&bytes);
        // assert_eq!(r.unwrap_err(), DimplError::TooBigLength(16385));
    }
}
