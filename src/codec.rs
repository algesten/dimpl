use crate::DimplError;

/// Values that encode/decode to a fixed size.
pub trait Codec: Sized {
    /// The fixed size in bytes.
    fn encoded_length() -> usize;

    /// Encode the value into the output.
    ///
    /// The output can be assumed be checked for available space enough to
    /// fit the length in `Self::encoded_length`.
    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError>;

    /// Helper to check output buffer size and encode a fixed value.
    fn encode_fixed<'a>(&self, out: &'a mut [u8]) -> Result<&'a mut [u8], DimplError> {
        let (checked, rest) = out.checked_split_mut(Self::encoded_length())?;
        self.encode(checked)?;
        Ok(rest)
    }

    /// Decode the value from the input.
    ///
    /// The input can be assumed to be checked for enough size to read
    /// `Self::encoded_length` number of bytes.
    fn decode(bytes: &[u8]) -> Result<Self, DimplError>;

    /// Helper to check length and decode a fixed value.
    fn decode_fixed(bytes: &[u8]) -> Result<(Self, &[u8]), DimplError> {
        let (checked, rest) = bytes.checked_get(Self::encoded_length())?;
        Ok((Self::decode(checked)?, rest))
    }
}

/// Values that encode/decodes to a variable size.
pub trait CodecVariable<Context = ()>: Sized {
    /// The variable size in bytes.
    fn encoded_length(&self) -> usize;

    /// Encode the value into the output.
    ///
    /// The output can be assumed be checked for available space enough to
    /// fit the length in `Self::encoded_length`.
    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError>;

    // Helper to check output buffer size and encode a fixed value.
    fn encode_variable<'a>(&self, out: &'a mut [u8]) -> Result<&'a mut [u8], DimplError> {
        let (checked, rest) = out.checked_split_mut(self.encoded_length())?;
        self.encode(checked)?;
        Ok(rest)
    }

    /// Decode the value from the input.
    ///
    /// The input can be assumed to be checked for _some kind of size_. The
    /// length of a variable type is preceeded the encoded length. This length
    /// is available as input.
    fn decode(bytes: &[u8], ctx: Context) -> Result<Self, DimplError>;

    /// Helper to decode a fixed value.
    fn decode_variable(
        bytes: &[u8],
        len: usize,
        ctx: Context,
    ) -> Result<(Self, &[u8]), DimplError> {
        let (checked, rest) = bytes.checked_get(len)?;
        Ok((Self::decode(checked, ctx)?, rest))
    }
}

pub trait CheckedSlice {
    type Output: 'static + Sized;
    fn checked_get(&self, mid: usize) -> Result<(&[Self::Output], &[Self::Output]), DimplError>;
    fn checked_split_mut(
        &mut self,
        mid: usize,
    ) -> Result<(&mut [Self::Output], &mut [Self::Output]), DimplError>;
}

impl<T: 'static + Clone> CheckedSlice for [T] {
    type Output = T;

    fn checked_get(&self, mid: usize) -> Result<(&[Self::Output], &[Self::Output]), DimplError> {
        if mid <= self.len() {
            Ok(self.split_at(mid))
        } else {
            Err(DimplError::TooShort)
        }
    }

    fn checked_split_mut(
        &mut self,
        mid: usize,
    ) -> Result<(&mut [Self::Output], &mut [Self::Output]), DimplError> {
        if mid <= self.len() {
            Ok(self.split_at_mut(mid))
        } else {
            Err(DimplError::TooShort)
        }
    }
}

impl Codec for u8 {
    fn encoded_length() -> usize {
        1
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        out[0] = *self;
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DimplError> {
        Ok(bytes[0])
    }
}

impl Codec for u16 {
    fn encoded_length() -> usize {
        2
    }

    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError> {
        (&mut out[..2]).copy_from_slice(&self.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DimplError> {
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}
