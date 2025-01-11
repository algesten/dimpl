#[derive(Debug)]
pub struct ChangeCipherSpec;

impl ChangeCipherSpec {
    pub fn parse(data: &[u8]) -> Option<(usize, ChangeCipherSpec)> {
        if data.len() < 1 || data[0] != 1 {
            return None;
        }

        Some((1, ChangeCipherSpec))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.push(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_change_cipher_spec() {
        let data = [1];

        let change_cipher_spec = ChangeCipherSpec::parse(&data).unwrap();
        assert_eq!(change_cipher_spec.0, 1);
    }

    #[test]
    fn parse_invalid_change_cipher_spec() {
        let data = [0];

        let change_cipher_spec = ChangeCipherSpec::parse(&data);
        assert!(change_cipher_spec.is_none());
    }
}
