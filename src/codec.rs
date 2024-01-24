use crate::DimplError;
use std::ops::RangeTo;

pub trait Codec: Sized {
    fn encode_length(&self) -> usize;
    fn encode(&self, out: &mut [u8]) -> Result<(), DimplError>;
    fn decode(bytes: &[u8]) -> Result<Self, DimplError>;
}

pub trait CheckedSlice {
    type Output: 'static + Sized;
    fn checked_get(&self, r: RangeTo<usize>) -> Result<&[Self::Output], DimplError>;
    fn checked_arr<'a, const N: usize>(&self) -> Result<[Self::Output; N], DimplError>
    where
        [Self::Output; N]: TryFrom<&'a [Self::Output]>;
}

impl<T: 'static + Clone> CheckedSlice for [T] {
    type Output = T;

    fn checked_get(&self, r: RangeTo<usize>) -> Result<&[Self::Output], DimplError> {
        if let Some(t) = self.get(r) {
            Ok(t)
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
        let t: &[T; N] = self.checked_get(r)?.try_into().unwrap();
        Ok(t.clone())
    }
}
