use crate::buffer::Buf;
use crate::message::CipherSuite;
use nom::bytes::complete::take;
use nom::IResult;

#[derive(Debug, PartialEq, Eq)]
pub struct Finished<'a> {
    pub verify_data: &'a [u8],
}

impl<'a> Finished<'a> {
    pub fn new(verify_data: &'a [u8]) -> Self {
        Finished { verify_data }
    }

    pub fn parse(input: &'a [u8], cipher_suite: CipherSuite) -> IResult<&'a [u8], Finished<'a>> {
        let verify_data_length = cipher_suite.verify_data_length();
        let (input, verify_data) = take(verify_data_length)(input)?;
        Ok((input, Finished { verify_data }))
    }

    pub fn serialize(&self, output: &mut Buf<'static>) {
        output.extend_from_slice(self.verify_data);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::buffer::Buf;
    use crate::message::CipherSuite;

    #[test]
    fn roundtrip() {
        let verify_data = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let finished = Finished::new(&verify_data);

        // Serialize and compare to MESSAGE
        let mut serialized = Buf::new();
        finished.serialize(&mut serialized);

        // Parse and compare with original
        let (rest, parsed) =
            Finished::parse(&serialized, CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256).unwrap();
        assert_eq!(parsed, finished);

        assert!(rest.is_empty());
    }
}
