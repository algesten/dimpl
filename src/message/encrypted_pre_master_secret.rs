use super::error::ParseError;
use super::PublicKeyEncrypted;

#[derive(Debug)]
pub struct EncryptedPreMasterSecret<'a> {
    pub encrypted: PublicKeyEncrypted<'a>,
}

impl<'a> EncryptedPreMasterSecret<'a> {
    pub fn new(encrypted: PublicKeyEncrypted<'a>) -> Self {
        EncryptedPreMasterSecret { encrypted }
    }

    pub fn parse(data: &'a [u8]) -> Result<EncryptedPreMasterSecret<'a>, ParseError<ErrorKind>> {
        let encrypted = PublicKeyEncrypted(data);
        Ok(EncryptedPreMasterSecret { encrypted })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.encrypted.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Encrypted data
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    #[test]
    fn roundtrip() {
        let original = EncryptedPreMasterSecret::new(PublicKeyEncrypted(&MESSAGE));

        let mut serialized = Vec::new();
        original.serialize(&mut serialized);

        assert_eq!(serialized, MESSAGE);

        let parsed = EncryptedPreMasterSecret::parse(&serialized).unwrap();

        assert_eq!(parsed.encrypted.0, original.encrypted.0);
    }
}
