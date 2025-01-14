use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u16, be_u24};
use nom::Err;
use nom::IResult;
use std::ops::Deref;

macro_rules! wrapped_slice {
    ($name:ident, $length_parser:path, $min:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name<'a>(pub &'a [u8]);

        impl<'a> Deref for $name<'a> {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                self.0
            }
        }

        impl<'a> $name<'a> {
            pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
                let (input, len) = $length_parser(input)?;
                #[allow(unused_comparisons)]
                if len < $min {
                    return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
                }
                let (input, data) = take(len)(input)?;
                Ok((input, $name(data)))
            }
        }
    };
}

wrapped_slice!(Asn1Cert, be_u24, 0);
wrapped_slice!(DistinguishedName, be_u16, 1);
