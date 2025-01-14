use nom::error::{Error as NomError, ErrorKind};
use nom::{Err, IResult};
use self_cell::self_cell;
use tinyvec::ArrayVec;

use crate::engine::Buffer;
use crate::message::{Body, CipherSuite, ContentType, DTLSRecord, Handshake};
use crate::util::many1;
use crate::Error;

self_cell!(
    /// Holds both the UDP packet and the parsed result of that packet.
    ///
    /// A self-referential struct.
    pub(crate) struct Incoming {
        owner: Buffer, // Buffer with UDP packet data
        #[covariant]
        dependent: Records, // Parsed records from that UDP packet
    }

    impl {Debug}
);

impl Incoming {
    /// Parse an incoming UDP packet
    ///
    /// * `packet` is the data from the UDP socket.
    /// * `c` is a reference to the `CipherSuite` that's been selected. Some of
    ///   the parsing requires to know this to parse correctly. For Client code,
    ///   this value is only known after we receive ServerHello, which means it
    ///   can start empty and be filled in as soon as we know the value.
    /// * `into` the buffer in which we want to store the UDP data.
    ///
    /// Will surface parser errors.
    pub fn parse_packet<'b>(
        packet: &'b [u8],
        c: &mut Option<CipherSuite>,
        mut into: Buffer,
    ) -> Result<Incoming, Error> {
        // The Buffer is where we store the raw packet data.
        into.resize(packet.len(), 0);
        into.copy_from_slice(packet);

        // håll i hatten
        let incoming = Incoming::try_new(into, |data| Ok::<_, Error>(Records::parse(&data, c)?.1))?;

        Ok(incoming)
    }
}

/// A number of records parsed from a single UDP packet.
#[derive(Debug)]
pub(crate) struct Records<'a> {
    records: ArrayVec<[Record<'a>; 32]>,
}

impl<'a> Records<'a> {
    pub fn parse(input: &'a [u8], c: &mut Option<CipherSuite>) -> IResult<&'a [u8], Records<'a>> {
        let (rest, records) = many1(|input| Record::parse(input, c))(input)?;
        if !rest.is_empty() {
            return Err(Err::Failure(NomError::new(rest, ErrorKind::LengthValue)));
        }
        Ok((&[], Records { records }))
    }
}

/// One record parsed from a UDP packet.
#[derive(Debug, Default)]
pub(crate) struct Record<'a> {
    /// The parsed DTLSRecord
    pub record: DTLSRecord<'a>,

    /// If the DTLSRecord is of ContentType Handshake, this is the parsed handshake.
    pub handshake: Option<Handshake<'a>>,
}

impl<'a> Record<'a> {
    pub fn parse(input: &'a [u8], c: &mut Option<CipherSuite>) -> IResult<&'a [u8], Record<'a>> {
        let (input, record) = DTLSRecord::parse(input)?;
        let handshake = if record.content_type != ContentType::Handshake {
            None
        } else {
            let (_, handshake) = Handshake::parse(input, *c)?;

            // When we get the ServerHello, we know which cipher suite was selected.
            // Parsing further messages after this must be informed by that choice.
            if let Body::ServerHello(server_hello) = &handshake.body {
                *c = Some(server_hello.cipher_suite);
            }

            Some(handshake)
        };
        Ok((input, Record { record, handshake }))
    }
}
