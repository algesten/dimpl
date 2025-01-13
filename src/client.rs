use std::marker::PhantomData;
use std::time::Instant;

use smallvec::{smallvec, SmallVec};

use crate::message::{CipherSuite, Cookie, ProtocolVersion, Random, SessionId};
use crate::state::client::CLIENT_HELLO;

pub struct Client<State> {
    client_version: ProtocolVersion,
    random: Random,
    /// SessionId is set by the server and only sent by the client if we
    /// are reusing a session (key renegotiation).
    session_id: Option<SessionId>,
    /// Cookie is sent by the server in the HelloVerifyRequest.
    cookie: Option<Cookie>,
    cipher_suites: SmallVec<[CipherSuite; 32]>,
    _ph: PhantomData<State>,
}

impl Default for Client<CLIENT_HELLO> {
    fn default() -> Self {
        Self {
            client_version: ProtocolVersion::DTLS1_2,
            random: Random::parse(&[0; 32]).unwrap().1, // placeholder
            session_id: None,
            cookie: None,
            cipher_suites: smallvec![],
            _ph: PhantomData,
        }
    }
}

impl Client<()> {
    pub fn new(now: Instant, s: impl IntoIterator<Item = CipherSuite>) -> Client<CLIENT_HELLO> {
        Client {
            random: Random::new(now),
            cipher_suites: s.into_iter().collect(),
            ..Client::default()
        }
    }

    fn transition<State2>(self) -> Client<State2> {
        Client {
            client_version: self.client_version,
            random: self.random,
            session_id: self.session_id,
            cookie: self.cookie,
            cipher_suites: self.cipher_suites,
            _ph: PhantomData,
        }
    }
}
