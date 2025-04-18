use std::ops::Deref;

use nom::error::{Error as NomError, ErrorKind};
use nom::{Err, IResult};
use self_cell::self_cell;
use tinyvec::ArrayVec;

use crate::buffer::Buffer;
use crate::message::{Body, CipherSuite, ContentType, DTLSRecord, Handshake};
use crate::util::many1;
use crate::Error;

/// Holds both the UDP packet and the parsed result of that packet.
///
/// A self-referential struct.
#[derive(Debug)]
pub struct Incoming(Inner);

impl Incoming {
    // pub fn into_inner(self) -> Buffer {
    //     self.0.into_owner()
    // }

    pub fn records(&self) -> &Records {
        self.0.borrow_dependent()
    }

    pub fn first(&self) -> &Record {
        // Invariant: Every Incoming must have at least one Record
        // or the parser would have failed. See use of many1 below.
        &self.records()[0]
    }

    pub fn last(&self) -> &Record {
        // Invariant: See above.
        self.records().last().unwrap()
    }
}

self_cell!(
    struct Inner {
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
    ) -> Result<Self, Error> {
        // The Buffer is where we store the raw packet data.
        into.resize(packet.len(), 0);
        into.copy_from_slice(packet);

        // håll i hatten
        let inner = Inner::try_new(into, |data| Ok::<_, Error>(Records::parse(&data, c)?.1))?;

        Ok(Incoming(inner))
    }
}

/// A number of records parsed from a single UDP packet.
#[derive(Debug)]
pub struct Records<'a> {
    pub records: ArrayVec<[Record<'a>; 32]>,
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

impl<'a> Deref for Records<'a> {
    type Target = [Record<'a>];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

/// One record parsed from a UDP packet.
#[derive(Debug, Default)]
pub struct Record<'a> {
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
            // Parse incoming as fragments
            let (_, handshake) = Handshake::parse(input, *c, true)?;

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
