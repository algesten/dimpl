use nom::{number::complete::be_u8, IResult};
use tinyvec::ArrayVec;

/// EC Point Format as defined in RFC 4492 Section 5.1.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ECPointFormat {
    #[default]
    Uncompressed = 0x00,
    AnsiX962CompressedPrime = 0x01,
    AnsiX962CompressedChar2 = 0x02,
}

impl ECPointFormat {
    pub fn parse(input: &[u8]) -> IResult<&[u8], ECPointFormat> {
        let (input, value) = be_u8(input)?;
        let format = match value {
            0x00 => ECPointFormat::Uncompressed,
            0x01 => ECPointFormat::AnsiX962CompressedPrime,
            0x02 => ECPointFormat::AnsiX962CompressedChar2,
            _ => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Switch,
                )))
            }
        };
        Ok((input, format))
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// ECPointFormats extension as defined in RFC 4492
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECPointFormatsExtension {
    pub formats: ArrayVec<[ECPointFormat; 3]>,
}

impl ECPointFormatsExtension {
    pub fn new(formats: ArrayVec<[ECPointFormat; 3]>) -> Self {
        ECPointFormatsExtension { formats }
    }

    /// Create a default ECPointFormatsExtension with standard formats
    pub fn default() -> Self {
        let mut formats = ArrayVec::new();
        // Most implementations only support uncompressed format
        formats.push(ECPointFormat::Uncompressed);

        ECPointFormatsExtension { formats }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], ECPointFormatsExtension> {
        let (input, list_len) = be_u8(input)?;
        let mut formats = ArrayVec::new();
        let mut remaining = list_len as usize;
        let mut current_input = input;

        while remaining > 0 {
            let (rest, format) = ECPointFormat::parse(current_input)?;
            formats.push(format);
            current_input = rest;
            remaining -= 1; // Each format is 1 byte
        }

        Ok((current_input, ECPointFormatsExtension { formats }))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        // Write the number of formats
        output.push(self.formats.len() as u8);

        // Write each format
        for format in &self.formats {
            output.push(format.as_u8());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinyvec::array_vec;

    #[test]
    fn test_ec_point_formats_extension() {
        let formats = array_vec![
            ECPointFormat::Uncompressed,
            ECPointFormat::AnsiX962CompressedPrime
        ];

        let ext = ECPointFormatsExtension::new(formats.clone());

        let mut serialized = Vec::new();
        ext.serialize(&mut serialized);

        let expected = [
            0x02, // Number of formats (2)
            0x00, // Uncompressed (0x00)
            0x01, // ANSI X9.62 compressed prime (0x01)
        ];

        assert_eq!(serialized, expected);

        let (_, parsed) = ECPointFormatsExtension::parse(&serialized).unwrap();

        assert_eq!(parsed.formats, formats);
    }
}
