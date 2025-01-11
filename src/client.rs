use std::marker::PhantomData;

use crate::state::client::CLIENT_HELLO;
use crate::state::ClientSend;

pub struct Client<State> {
    _ph: PhantomData<State>,
}

impl Client<()> {
    pub fn new() -> Client<CLIENT_HELLO> {
        Client { _ph: PhantomData }
    }

    fn transition<State2>(self) -> Client<State2> {
        // SAFETY: This transmute only changes the type state, a zero sized type.
        Client { _ph: PhantomData }
    }
}

impl<S: ClientSend> Client<S> {}
