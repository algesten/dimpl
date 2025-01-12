use super::{CurveType, KeyExchangeAlgorithm, NamedCurve};
use nom::error::{Error, ErrorKind};
use nom::number::complete::{be_u16, be_u8};
use nom::Err;
use nom::{bytes::complete::take, IResult};

#[derive(Debug, PartialEq, Eq)]
pub struct ServerKeyExchange<'a> {
    pub params: ServerKeyExchangeParams<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerKeyExchangeParams<'a> {
    ServerDhParams(ServerDhParams<'a>),
    ServerEcdhParams(ServerEcdhParams<'a>),
}

impl<'a> ServerKeyExchange<'a> {
    pub fn parse(
        input: &'a [u8],
        key_exchange_algorithm: KeyExchangeAlgorithm,
    ) -> IResult<&'a [u8], ServerKeyExchange<'a>> {
        let (input, params) = match key_exchange_algorithm {
            KeyExchangeAlgorithm::EDH => {
                let (input, dh_params) = ServerDhParams::parse(input)?;
                (input, ServerKeyExchangeParams::ServerDhParams(dh_params))
            }
            KeyExchangeAlgorithm::EECDH => {
                let (input, ecdh_params) = ServerEcdhParams::parse(input)?;
                (
                    input,
                    ServerKeyExchangeParams::ServerEcdhParams(ecdh_params),
                )
            }
            _ => return Err(Err::Failure(Error::new(input, ErrorKind::Tag))),
        };

        Ok((input, ServerKeyExchange { params }))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        match &self.params {
            ServerKeyExchangeParams::ServerDhParams(dh_params) => dh_params.serialize(output),
            ServerKeyExchangeParams::ServerEcdhParams(ecdh_params) => ecdh_params.serialize(output),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerDhParams<'a> {
    pub p: &'a [u8],
    pub g: &'a [u8],
    pub ys: &'a [u8],
}

impl<'a> ServerDhParams<'a> {
    pub fn new(p: &'a [u8], g: &'a [u8], ys: &'a [u8]) -> Self {
        ServerDhParams { p, g, ys }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ServerDhParams<'a>> {
        let (input, p_len) = be_u16(input)?;
        if p_len < 1 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, p) = take(p_len)(input)?;
        let (input, g_len) = be_u16(input)?;
        if g_len < 1 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, g) = take(g_len)(input)?;
        let (input, ys_len) = be_u16(input)?;
        if ys_len < 1 {
            return Err(Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (input, ys) = take(ys_len)(input)?;

        Ok((input, ServerDhParams { p, g, ys }))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&(self.p.len() as u16).to_be_bytes());
        output.extend_from_slice(self.p);
        output.extend_from_slice(&(self.g.len() as u16).to_be_bytes());
        output.extend_from_slice(self.g);
        output.extend_from_slice(&(self.ys.len() as u16).to_be_bytes());
        output.extend_from_slice(self.ys);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerEcdhParams<'a> {
    pub curve_type: CurveType,
    pub named_curve: NamedCurve,
    pub public_key: &'a [u8],
}

impl<'a> ServerEcdhParams<'a> {
    pub fn new(curve_type: CurveType, named_curve: NamedCurve, public_key: &'a [u8]) -> Self {
        ServerEcdhParams {
            curve_type,
            named_curve,
            public_key,
        }
    }

    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], ServerEcdhParams<'a>> {
        let (input, curve_type) = CurveType::parse(input)?;
        let (input, named_curve) = NamedCurve::parse(input)?;
        let (input, public_key_len) = be_u8(input)?;
        let (input, public_key) = take(public_key_len)(input)?;

        Ok((
            input,
            ServerEcdhParams {
                curve_type,
                named_curve,
                public_key,
            },
        ))
    }

    pub fn serialize(&self, output: &mut Vec<u8>) {
        output.push(self.curve_type.to_u8());
        output.extend_from_slice(&self.named_curve.to_u16().to_be_bytes());
        output.push(self.public_key.len() as u8);
        output.extend_from_slice(self.public_key);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const MESSAGE_DH: &[u8] = &[
        0x00, 0x04, // p length
        0x01, 0x02, 0x03, 0x04, // p
        0x00, 0x02, // g length
        0x05, 0x06, // g
        0x00, 0x02, // ys length
        0x07, 0x08, // ys
    ];

    const MESSAGE_ECDH: &[u8] = &[
        0x03, // curve_type
        0x00, 0x17, // named_curve
        0x04, // public_key length
        0x01, 0x02, 0x03, 0x04, // public_key
    ];

    #[test]
    fn roundtrip_dh() {
        let mut serialized = Vec::new();

        let dh_params =
            ServerDhParams::new(&MESSAGE_DH[2..6], &MESSAGE_DH[8..10], &MESSAGE_DH[12..14]);

        let server_key_exchange = ServerKeyExchange {
            params: ServerKeyExchangeParams::ServerDhParams(dh_params),
        };

        // Serialize and compare to DH_MESSAGE
        server_key_exchange.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE_DH);

        // Parse and compare with original
        let (rest, parsed) =
            ServerKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EDH).unwrap();
        assert_eq!(parsed, server_key_exchange);

        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_ecdh() {
        let mut serialized = Vec::new();

        let ecdh_params = ServerEcdhParams::new(
            CurveType::NamedCurve,
            NamedCurve::Secp256r1,
            &MESSAGE_ECDH[4..],
        );

        let server_key_exchange = ServerKeyExchange {
            params: ServerKeyExchangeParams::ServerEcdhParams(ecdh_params),
        };

        // Serialize and compare to ECDH_MESSAGE
        server_key_exchange.serialize(&mut serialized);
        assert_eq!(serialized, MESSAGE_ECDH);

        // Parse and compare with original
        let (rest, parsed) =
            ServerKeyExchange::parse(&serialized, KeyExchangeAlgorithm::EECDH).unwrap();
        assert_eq!(parsed, server_key_exchange);

        assert!(rest.is_empty());
    }
}
