use nom::error::{ErrorKind, ParseError};
use nom::{Err, IResult, InputLength, Parser};
use smallvec::{Array, SmallVec};

pub fn many1<I, O, E, F, A>(mut f: F) -> impl FnMut(I) -> IResult<I, SmallVec<A>, E>
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
            let mut acc = SmallVec::default();
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
