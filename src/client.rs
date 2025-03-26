use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

use tinyvec::array_vec;

use crate::engine::Engine;
use crate::incoming::Record;
use crate::message::{
    CipherSuite, ClientHello, CompressionMethod, ContentType, Cookie, MessageType, ProtocolVersion,
    Random, SessionId,
};
use crate::{Config, Error, Output};

pub struct Client {
    /// Random unique data (with gmt timestamp). Used for signature checks.
    random: Random,

    /// SessionId is set by the server and only sent by the client if we
    /// are reusing a session (key renegotiation).
    session_id: Option<SessionId>,

    /// Cookie is sent by the server in the optional HelloVerifyRequest.
    /// It might remain null if there is no HelloVerifyRequest.
    cookie: Option<Cookie>,

    /// The cipher suites in use. Set by ServerHello.
    cipher_suite: Option<CipherSuite>,

    /// Current client state.
    state: ClientState,

    /// Engine in common between server and client.
    engine: Engine,
}

/// Current state of the client.
#[derive(Debug)]
pub enum ClientState {
    /// Send the ClientHello
    SendClientHello,

    /// Waiting for a ServerHello, or maybe a HelloVerifyRequest
    ///
    /// Wait until we see ServerHelloDone.
    AwaitServerHello { can_hello_verify: bool },

    /// Send the client certificate and keys.
    ///
    /// All the messages up to Finished.
    SendClientCertAndKeys,

    /// Await server message until Finished.
    AwaitServerFinished,

    /// Send and receive encrypted data.
    Running,
}

impl Client {
    pub fn new(now: Instant, config: Arc<Config>) -> Client {
        Client {
            random: Random::new(now),
            session_id: None,
            cookie: None,
            cipher_suite: None,
            state: ClientState::SendClientHello,
            engine: Engine::new(config),
        }
    }

    pub fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.engine.parse_packet(packet, &mut self.cipher_suite)?;
        self.process_input()?;
        Ok(())
    }

    pub fn poll_output(&mut self) -> Output {
        self.engine.poll_output()
    }

    fn process_input(&self) -> Result<(), Error> {
        todo!()
    }
}
