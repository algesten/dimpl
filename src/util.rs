use std::ops::RangeFrom;

use nom::error::{make_error, ErrorKind, ParseError};
use nom::{Err, IResult, InputIter, InputLength, Parser, Slice};
use tinyvec::{Array, ArrayVec};

#[inline(always)]
pub fn many0<I, O, E, F, A>(mut f: F) -> impl FnMut(I) -> IResult<I, ArrayVec<A>, E>
where
    I: Clone + InputLength,
    F: Parser<I, O, E>,
    E: ParseError<I>,
    A: Array<Item = O>,
{
    move |mut i: I| {
        let mut acc = ArrayVec::default();
        loop {
            let len = i.input_len();
            match f.parse(i.clone()) {
                Err(Err::Error(_)) => return Ok((i, acc)),
                Err(e) => return Err(e),
                Ok((i1, o)) => {
                    // infinite loop check: the parser must always consume
                    if i1.input_len() == len {
                        return Err(Err::Error(E::from_error_kind(i, ErrorKind::Many0)));
                    }

                    i = i1;
                    acc.push(o);
                }
            }
        }
    }
}

#[inline(always)]
pub fn many1<I, O, E, F, A>(mut f: F) -> impl FnMut(I) -> IResult<I, ArrayVec<A>, E>
where
    I: Clone + InputLength,
    F: Parser<I, O, E>,
    E: ParseError<I>,
    A: Array<Item = O>,
{
    move |mut i: I| match f.parse(i.clone()) {
        Err(Err::Error(err)) => Err(Err::Error(E::append(i, ErrorKind::Many1, err))),
        Err(e) => Err(e),
        Ok((i1, o)) => {
            let mut acc = ArrayVec::default();
            acc.push(o);
            i = i1;

            loop {
                let len = i.input_len();
                match f.parse(i.clone()) {
                    Err(Err::Error(_)) => return Ok((i, acc)),
                    Err(e) => return Err(e),
                    Ok((i1, o)) => {
                        // infinite loop check: the parser must always consume
                        if i1.input_len() == len {
                            return Err(Err::Error(E::from_error_kind(i, ErrorKind::Many1)));
                        }

                        i = i1;
                        acc.push(o);
                    }
                }
            }
        }
    }
}

pub fn be_u48<I, E: ParseError<I>>(input: I) -> IResult<I, u64, E>
where
    I: Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
{
    let bound: usize = 6;

    if input.input_len() < bound {
        Err(Err::Error(make_error(input, ErrorKind::Eof)))
    } else {
        let mut res = 0u64;

        for byte in input.iter_elements().take(bound) {
            res = (res << 8) + byte as u64;
        }

        Ok((input.slice(bound..), res))
    }
}
