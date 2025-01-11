use smallvec::SmallVec;

#[derive(Debug)]
pub struct ApplicationData {
    pub data: SmallVec<[u8; 1024]>,
}

impl ApplicationData {
    pub fn parse(data: &[u8]) -> Option<(usize, ApplicationData)> {
        let app_data = SmallVec::from_slice(data);
        Some((data.len(), ApplicationData { data: app_data }))
    }

    pub fn serialize(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&self.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_application_data() {
        let data = [
            0x01, 0x02, 0x03, 0x04, // application data
        ];

        let application_data = ApplicationData::parse(&data).unwrap();
        assert_eq!(application_data.1.data.as_ref(), &[0x01, 0x02, 0x03, 0x04]);
    }
}
