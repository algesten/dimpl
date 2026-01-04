use super::Asn1Cert;
use crate::buffer::Buf;
use arrayvec::ArrayVec;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::number::complete::be_u8;
use nom::{number::complete::be_u24, IResult};
use std::ops::Range;

/// DTLS 1.2 Certificate format
#[derive(Debug, PartialEq, Eq)]
pub struct Certificate {
    pub certificate_list: ArrayVec<Asn1Cert, 32>,
}

/// TLS 1.3 / DTLS 1.3 Certificate format
/// RFC 8446 Section 4.4.2
#[derive(Debug, PartialEq, Eq)]
pub struct Certificate13 {
    /// Certificate request context (opaque <0..2^8-1>)
    pub context: Range<usize>,
    /// Certificate entries with extensions
    pub certificate_list: ArrayVec<CertificateEntry13, 32>,
}

/// TLS 1.3 CertificateEntry
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CertificateEntry13 {
    /// The certificate data
    pub cert_data: Range<usize>,
    /// Per-certificate extensions (we just store the range)
    pub extensions_range: Range<usize>,
}

impl Certificate {
    pub fn new(certificate_list: ArrayVec<Asn1Cert, 32>) -> Self {
        Certificate { certificate_list }
    }

    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Certificate> {
        let original_input = input;
        let (input, total_len) = be_u24(input)?;
        let (input, certs_data) = take(total_len)(input)?;

        // Calculate base offset for certs_data within the root buffer
        let certs_base_offset =
            base_offset + (certs_data.as_ptr() as usize - original_input.as_ptr() as usize);

        // Parse certificates manually with dynamic base_offset
        let mut certificate_list = ArrayVec::new();
        let mut rest = certs_data;
        while !rest.is_empty() {
            let offset =
                certs_base_offset + (rest.as_ptr() as usize - certs_data.as_ptr() as usize);
            let (new_rest, cert) = Asn1Cert::parse(rest, offset)?;
            certificate_list.push(cert);
            rest = new_rest;
        }

        Ok((input, Certificate { certificate_list }))
    }

    pub fn serialize(&self, buf: &[u8], output: &mut Buf) {
        let total_len: usize = self
            .certificate_list
            .iter()
            .map(|cert| 3 + cert.as_slice(buf).len())
            .sum();
        output.extend_from_slice(&(total_len as u32).to_be_bytes()[1..]);

        for cert in &self.certificate_list {
            let cert_data = cert.as_slice(buf);
            output.extend_from_slice(&(cert_data.len() as u32).to_be_bytes()[1..]);
            output.extend_from_slice(cert_data);
        }
    }
}

impl Certificate13 {
    /// Parse a TLS 1.3 Certificate message
    /// Format:
    ///   certificate_request_context <0..2^8-1>
    ///   CertificateEntry certificate_list<0..2^24-1>
    pub fn parse(input: &[u8], base_offset: usize) -> IResult<&[u8], Certificate13> {
        let original_input = input;

        // Context length (1 byte) + context data
        let (input, context_len) = be_u8(input)?;
        let (input, _context_data) = take(context_len)(input)?;

        // Calculate the range for context
        let context_start = base_offset + 1;
        let context_end = context_start + context_len as usize;
        let context = context_start..context_end;

        // Certificate list length (3 bytes)
        let (input, list_len) = be_u24(input)?;
        let (input, list_data) = take(list_len)(input)?;

        // Parse certificate entries
        let list_base_offset =
            base_offset + (list_data.as_ptr() as usize - original_input.as_ptr() as usize);
        let mut certificate_list = ArrayVec::new();
        let mut rest = list_data;

        while !rest.is_empty() {
            let entry_offset =
                list_base_offset + (rest.as_ptr() as usize - list_data.as_ptr() as usize);

            // cert_data length (3 bytes) + cert_data
            let (r, cert_len) = be_u24(rest)?;
            let (r, _cert_data) = take(cert_len)(r)?;
            let cert_start = entry_offset + 3;
            let cert_end = cert_start + cert_len as usize;

            // extensions length (2 bytes) + extensions
            let (r, ext_len) = be_u16(r)?;
            let (r, _ext_data) = take(ext_len)(r)?;
            let ext_start = cert_end + 2;
            let ext_end = ext_start + ext_len as usize;

            certificate_list.push(CertificateEntry13 {
                cert_data: cert_start..cert_end,
                extensions_range: ext_start..ext_end,
            });

            rest = r;
        }

        Ok((
            input,
            Certificate13 {
                context,
                certificate_list,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::Buf;

    const MESSAGE: &[u8] = &[
        0x00, 0x00, 0x0C, // Total length
        0x00, 0x00, 0x04, // Certificate 1 length
        0x01, 0x02, 0x03, 0x04, // Certificate 1 data
        0x00, 0x00, 0x02, // Certificate 2 length
        0x05, 0x06, // Certificate 2 data
    ];

    #[test]
    fn roundtrip() {
        // Parse the message with base_offset 0
        let (rest, parsed) = Certificate::parse(MESSAGE, 0).unwrap();
        assert!(rest.is_empty());

        // Serialize and compare to MESSAGE
        let mut serialized = Buf::new();
        parsed.serialize(MESSAGE, &mut serialized);
        assert_eq!(&*serialized, MESSAGE);
    }
}
