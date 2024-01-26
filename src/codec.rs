use crate::DimplError;
use core::ops::RangeTo;

/// Values that encode/decode to a fixed size.
pub trait Codec: Sized {
    /// The fixed size in bytes.
    fn encoded_length() -> usize;

    // Encode the value into the output.
    //
    // The output can be assumed be checked for available space enough to
    // fit the length in `Self::encoded_length`.
    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError>;

    // Decode the value from the input.
    //
    // The input can be assumed to be checked for enough size to read
    // `Self::encoded_length` number of bytes.
    fn decode(bytes: &[u8]) -> Result<Self, DimplError>;
}

/// Values that encode/decodes to a variable size.
pub trait CodecVariable<Context>: Sized {
    /// The variable size in bytes.
    fn encoded_length(&self) -> usize;

    // Encode the value into the output.
    //
    // The output can be assumed be checked for available space enough to
    // fit the length in `Self::encoded_length`.
    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError>;

    // Decode the value from the input.
    //
    // The input can be assumed to be checked for _some kind of size_. The
    // length of a variable type is preceeded the encoded length. This length
    // is available as input.
    fn decode(bytes: &[u8], ctx: Context) -> Result<Self, DimplError>;
}

pub trait CheckedSlice {
    type Output: 'static + Sized;
    fn checked_get(
        &self,
        r: RangeTo<usize>,
    ) -> Result<(&[Self::Output], &[Self::Output]), DimplError>;
    fn checked_arr<'a, const N: usize>(&self) -> Result<[Self::Output; N], DimplError>
    where
        [Self::Output; N]: TryFrom<&'a [Self::Output]>;
}

impl<T: 'static + Clone> CheckedSlice for [T] {
    type Output = T;

    fn checked_get(
        &self,
        r: RangeTo<usize>,
    ) -> Result<(&[Self::Output], &[Self::Output]), DimplError> {
        if r.end <= self.len() {
            Ok(self.split_at(r.end))
        } else {
            Err(DimplError::TooShort)
        }
    }

    fn checked_arr<'a, const N: usize>(&self) -> Result<[Self::Output; N], DimplError>
    where
        [Self::Output; N]: TryFrom<&'a [Self::Output]>,
    {
        let r = ..N;
        // This unwrap should always succeed since we chek the size with checked_get.
        let t: &[T; N] = self.checked_get(r)?.0.try_into().unwrap();
        Ok(t.clone())
    }
}
