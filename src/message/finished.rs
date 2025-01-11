use smallvec::SmallVec;

#[derive(Debug)]
pub struct Finished {
    pub verify_data: SmallVec<[u8; 12]>,
}

impl Finished {
    pub fn parse(data: &[u8]) -> Option<(usize, Finished)> {
        if data.len() < 12 {
            return None;
        }

        let verify_data = SmallVec::from_slice(&data[..12]);

        Some((12, Finished { verify_data }))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&self.verify_data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_finished() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, // verify_data
        ];

        let finished = Finished::parse(&data).unwrap();
        assert_eq!(
            finished.1.verify_data.as_ref(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]
        );
    }

    #[test]
    fn parse_invalid_finished() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, // incomplete verify_data
        ];

        let finished = Finished::parse(&data);
        assert!(finished.is_none());
    }
}
