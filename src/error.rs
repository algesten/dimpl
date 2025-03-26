#[derive(Debug)]
pub enum Error {
    ParseIncomplete,
    ParseError(nom::error::ErrorKind),
    UnexpectedMessage(String),
    CryptoError(String),
    CertificateError(String),
    SecurityError(String),
}

impl<'a> From<nom::Err<nom::error::Error<&'a [u8]>>> for Error {
    fn from(value: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        match value {
            nom::Err::Incomplete(_) => Error::ParseIncomplete,
            nom::Err::Error(x) => Error::ParseError(x.code),
            nom::Err::Failure(x) => Error::ParseError(x.code),
        }
    }
}
