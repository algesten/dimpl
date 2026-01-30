use super::Extension;
use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::IResult;

/// EncryptedExtensions message (RFC 8446 Section 4.3.1).
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedExtensions {
    pub extensions: ArrayVec<Extension, 5>,
}

impl EncryptedExtensions {
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], EncryptedExtensions> {
        let original_input = input;
        let (input, extensions_len) = be_u16(input)?;
        let (input, extensions_data) = take(extensions_len)(input)?;

        let data_base_offset =
            base_offset + (extensions_data.as_ptr() as usize - original_input.as_ptr() as usize);

        let mut extensions = ArrayVec::new();
        let mut rest = extensions_data;
        let mut current_offset = data_base_offset;
        while !rest.is_empty() {
            let before_len = rest.len();
            let (new_rest, ext) = Extension::parse(rest, current_offset)?;
            let parsed_len = before_len - new_rest.len();
            current_offset += parsed_len;

            if ext.extension_type.is_known() {
                extensions.push(ext);
            }
            rest = new_rest;
        }

        Ok((input, EncryptedExtensions { extensions }))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        let mut extensions_len = 0usize;
        for ext in &self.extensions {
            let ext_data = ext.extension_data(buf);
            extensions_len += 4 + ext_data.len();
        }

        output.extend_from_slice(&(extensions_len as u16).to_be_bytes());

        for ext in &self.extensions {
            ext.serialize(buf, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0x00, 0x0C, // Extensions length (12)
        0x00, 0x0A, // ExtensionType::SupportedGroups
        0x00, 0x08, // Extension data length
        0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, // Extension data
    ];

    #[test]
    fn roundtrip() {
        let (rest, parsed) = EncryptedExtensions::parse(MESSAGE, 0).unwrap();
        assert!(rest.is_empty());

        let mut serialized = Buf::new();
        parsed.serialize(MESSAGE, &mut serialized);
        assert_eq!(&*serialized, MESSAGE);
    }
}
