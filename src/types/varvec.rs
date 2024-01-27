use core::fmt;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ops::Range;

use arrayvec::ArrayVec;

use crate::codec::{Checked, CheckedMut, Codec, CodecVar, CodecVarLen, SliceCheck};
use crate::Error;

// name - name of variable vector type
// t    - type held in the vector
// n    - max number of elements
// r    - allowed range of elements
macro_rules! varvec {
    ($name:ident, $t:ty, $n:expr, $r:expr) => {
        #[derive(Clone)]
        pub struct $name {
            inner: ArrayVec<$t, $n>,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    inner: ArrayVec::new(),
                }
            }

            fn required_range() -> Range<usize> {
                $r
            }

            fn assert_size(&self) -> Result<(), Error> {
                let range = Self::required_range();
                let len = self.len();
                if !range.contains(&len) {
                    return Err(Error::BadVariableVecSize);
                }
                Ok(())
            }

            /// Byte length of the actual elements.
            fn element_byte_length(&self) -> usize {
                self.inner.len() * <$t>::encoded_length()
            }
        }

        impl Deref for $name {
            type Target = ArrayVec<$t, $n>;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }

        impl CodecVar for $name
        where
            $t: Codec,
        {
            fn encoded_length(&self) -> usize {
                // Example from https://datatracker.ietf.org/doc/html/rfc5246#section-4.3
                //
                // uint16 longer<0..800>;
                // /* zero to 400 16-bit unsigned integers */
                //
                if $n < u8::MAX as usize {
                    1 + self.element_byte_length()
                } else if $n < u16::MAX as usize {
                    2 + self.element_byte_length()
                } else {
                    unreachable!("Too large N")
                }
            }

            fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
                self.assert_size()?;

                // Encode the length and return the positioned out
                let mut out = if $n < u8::MAX as usize {
                    // Encode byte length as 1 byte.
                    (self.element_byte_length() as u8).encode_fixed(&mut *out)?
                } else if $n < u16::MAX as usize {
                    // Encode byte length as 2 bytes
                    (self.element_byte_length() as u16).encode_fixed(&mut *out)?
                } else {
                    unreachable!("Too large N")
                };

                for t in &self.inner {
                    out = t.encode_fixed(out)?;
                }

                Ok(())
            }

            fn decode(bytes: Checked<u8>, _: ()) -> Result<Self, Error> {
                // Skip the length field
                let bytes = if $n < u8::MAX as usize {
                    bytes.skip(1)?
                } else if $n < u16::MAX as usize {
                    bytes.skip(2)?
                } else {
                    unreachable!("Too large N")
                };

                // Expected number of elements in array.
                let length = bytes.len() / <$t>::encoded_length();

                let mut inner = ArrayVec::<$t, $n>::new();

                for chunk in bytes.chunks(<$t>::encoded_length()) {
                    // Last chunk might contain fewer elements.
                    if chunk.len() != <$t>::encoded_length() {
                        // https://datatracker.ietf.org/doc/html/rfc5246#section-4.3
                        //
                        // The length of an encoded vector must be an even multiple of the length
                        // of a single element (for example, a 17-byte vector of uint16 would be illegal).
                        return Err(Error::IncorrectVariableVecLength);
                    }
                    let (chunk, _) = chunk.checked_split(<$t>::encoded_length())?;
                    let t = <$t>::decode(chunk)?;
                    inner.push(t);
                }

                // If this is wrong, we must have a bug earlier.
                assert_eq!(inner.len(), length);

                let ret = Self { inner };

                // Check the decoded vector is in the required range.
                ret.assert_size()?;

                Ok(ret)
            }
        }

        impl CodecVarLen for SessionId {
            fn min_needed_length() -> usize {
                if $n < u8::MAX as usize {
                    1
                } else if $n < u16::MAX as usize {
                    2
                } else {
                    unreachable!("Too large N")
                }
            }

            fn read_internal_length(bytes: Checked<u8>) -> Result<usize, Error> {
                let length = if $n < u8::MAX as usize {
                    // Read length a 1 byte
                    let (l, _) = u8::decode_fixed(&*bytes)?;
                    l as usize + 1
                } else if $n < u16::MAX as usize {
                    // Read length as 2 bytes
                    let (l, _) = u16::decode_fixed(&*bytes)?;
                    l as usize + 2
                } else {
                    unreachable!("Too large N")
                };

                Ok(length)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("{}", &self.inner)
                    .finish()
            }
        }
    };
}

varvec!(SessionId, u8, 32, 0..32);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_var_vec() {
        let mut x = SessionId::new();
        x.push(42);
        x.push(43);

        let mut out = [0; 4];

        x.encode_variable(&mut out).unwrap();

        assert_eq!(&out, &[2, 42, 43, 0])
    }

    #[test]
    fn decode_var_vec() {
        let bytes: &[u8] = &[2, 42, 43, 0];

        let (x, _) = SessionId::decode_variable_internal_length(&bytes, ()).unwrap();

        const CMP: &[u8] = &[42, 43];
        assert_eq!(&*x, CMP);
    }
}
