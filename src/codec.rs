use core::ops::Deref;
use core::ops::DerefMut;

use crate::Error;

/// Values that encode/decode to a fixed size.
pub trait Codec: Sized {
    /// The fixed size in bytes.
    fn encoded_length() -> usize;

    /// Encode the value into the output.
    ///
    /// The CheckedSliceMut ensures the output has been length checked to
    /// be able to contain `encoded_length()` bytes.
    fn encode(&self, out: CheckedMut<'_, u8>) -> Result<(), Error>;

    /// Helper to check output buffer size and encode a fixed value.
    fn encode_fixed<'a>(&self, out: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let (checked, rest) = out.checked_split_mut(Self::encoded_length())?;
        self.encode(checked)?;
        Ok(rest)
    }

    /// Decode the value from the input.
    ///
    /// The CheckedSlice ensures the input has been length checked to
    /// have at least `encoded_length()` number of bytes.
    fn decode(bytes: Checked<u8>) -> Result<Self, Error>;

    /// Helper to check length and decode a fixed value.
    fn decode_fixed(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (checked, rest) = bytes.checked_split(Self::encoded_length())?;
        Ok((Self::decode(checked)?, rest))
    }
}

/// Values that encode/decodes to a variable size.
pub trait CodecVar<Context = ()>: Sized {
    /// The variable size in bytes.
    fn encoded_length(&self) -> usize;

    /// Encode the value into the output.
    ///
    /// The output can be assumed be checked for available space enough to
    /// fit the length in `Self::encoded_length`.
    fn encode(&self, out: CheckedMut<'_, u8>) -> Result<(), Error>;

    // Helper to check output buffer size and encode a fixed value.
    fn encode_variable<'a>(&self, out: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let (checked, rest) = out.checked_split_mut(self.encoded_length())?;
        self.encode(checked)?;
        Ok(rest)
    }

    /// Decode the value from the input.
    ///
    /// The input can be assumed to be checked for _some kind of size_. The
    /// length of a variable type is preceeded the encoded length. This length
    /// is available as input.
    fn decode(bytes: Checked<u8>, ctx: Context) -> Result<Self, Error>;

    /// Helper to decode a variable value when the length is known.
    fn decode_variable(bytes: &[u8], len: usize, ctx: Context) -> Result<(Self, &[u8]), Error> {
        let (checked, rest) = bytes.checked_split(len)?;
        Ok((Self::decode(checked, ctx)?, rest))
    }
}

/// Value that encodes/decodes with a variable size, and the size is known internally.
///
/// Typically the length is read from some field in the incoming data.
pub trait CodecVarLen<Context = ()>: CodecVar<Context> {
    /// Minimum needed bytes to be able to read the internal length.
    fn min_needed_length() -> usize;

    /// Attempt to read the internal length from the provided checked length.
    ///
    /// The returned length should contain the internal length.
    fn read_internal_length(bytes: Checked<u8>) -> Result<usize, Error>;

    /// Helper to decode a variable value when the length is internal to the read.
    fn decode_variable_internal_length(bytes: &[u8], ctx: Context) -> Result<(Self, &[u8]), Error> {
        let (checked, _) = bytes.checked_split(Self::min_needed_length())?;
        let length = Self::read_internal_length(checked)?;
        Self::decode_variable(bytes, length, ctx)
    }
}

/// Helper trait implemented for slice to check lengths.
pub trait SliceCheck {
    type Output: 'static + Sized;
    /// Split slice in two. First half is checked so that it is `mid` size.
    /// The second half is however long is left.
    ///
    /// Errors if the slice length is not enough for `mid.`
    fn checked_split(&self, mid: usize) -> Result<(Checked<Self::Output>, &[Self::Output]), Error>;

    /// Mut variant of `checked_split`.
    fn checked_split_mut(
        &mut self,
        mid: usize,
    ) -> Result<(CheckedMut<Self::Output>, &mut [Self::Output]), Error>;
}

/// Blanket implementation of helper over all slices.
impl<T: 'static + Clone + Sized> SliceCheck for [T] {
    type Output = T;

    fn checked_split(
        &self,
        mid: usize,
    ) -> Result<(Checked<'_, Self::Output>, &[Self::Output]), Error> {
        if mid <= self.len() {
            let (c, rest) = self.split_at(mid);
            Ok((Checked(c), rest))
        } else {
            Err(Error::TooShort)
        }
    }

    fn checked_split_mut(
        &mut self,
        mid: usize,
    ) -> Result<(CheckedMut<'_, Self::Output>, &mut [Self::Output]), Error> {
        if mid <= self.len() {
            let (c, rest) = self.split_at_mut(mid);
            Ok((CheckedMut(c), rest))
        } else {
            Err(Error::TooShort)
        }
    }
}

/// Wrapper type around a slice to mark the slice is length checked.
pub struct Checked<'a, T: Sized>(&'a [T]);
/// Mut variant of `CheckedSlice`.
pub struct CheckedMut<'a, T: Sized>(&'a mut [T]);

impl<'a, T> Checked<'a, T> {
    pub fn skip(self, n: usize) -> Result<Checked<'a, T>, Error> {
        if n < self.0.len() {
            Ok(Checked(&self.0[n..]))
        } else {
            Err(Error::TooShort)
        }
    }
}

impl<'a, T> Deref for Checked<'a, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T> Deref for CheckedMut<'a, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T> DerefMut for CheckedMut<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Codec for u8 {
    fn encoded_length() -> usize {
        1
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        out[0] = *self;
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        Ok(bytes[0])
    }
}

impl Codec for u16 {
    fn encoded_length() -> usize {
        2
    }

    fn encode(&self, mut out: CheckedMut<'_, u8>) -> Result<(), Error> {
        (&mut out[..2]).copy_from_slice(&self.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: Checked<u8>) -> Result<Self, Error> {
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}
