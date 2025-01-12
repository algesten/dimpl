use super::error::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished<'a> {
    pub verify_data: &'a [u8],
}

impl<'a> Finished<'a> {
    pub fn new(verify_data: &'a [u8]) -> Self {
        Finished { verify_data }
    }

    pub fn parse(data: &'a [u8]) -> Result<Finished<'a>, ParseError<ErrorKind>> {
        if data.is_empty() {
            return Err(ParseError::new(ErrorKind::VerifyDataNotEnough, 0));
        }
        Ok(Finished { verify_data: data })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.verify_data);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    VerifyDataNotEnough,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, // Verify data
    ];

    #[test]
    fn roundtrip() {
        let original = Finished::new(&MESSAGE);

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = Finished::parse(&serialized).unwrap();

        assert_eq!(parsed.verify_data, original.verify_data);
    }

    #[test]
    fn parse_verify_data_not_enough() {
        let error = Finished::parse(&[]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::VerifyDataNotEnough);
    }
}
