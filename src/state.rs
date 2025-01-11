#![allow(private_bounds)]
#![allow(non_camel_case_types)]

trait Private {}

/// States in which a client sends and a server receives.
pub mod client {
    pub struct CLIENT_HELLO;
    pub struct CERTIFICATE;
    pub struct CLIENT_KEY_EXCHANGE;
    pub struct CERTIFICATE_VERIFY;
    pub struct CHANGE_CIPHER_SPEC;
    pub struct FINISHED;
    pub struct APPLICATION_DATA;
}

/// States in which a server sends and a client receives.
pub mod server {
    pub struct SERVER_HELLO;
    pub struct CERTIFICATE;
    pub struct SERVER_KEY_EXCHANGE;
    pub struct CERTIFICATE_REQUEST;
    pub struct SERVER_HELLO_DONE;
    pub struct CHANGE_CIPHER_SPEC;
    pub struct NEW_SESSION_TICKET;
    pub struct FINISHED;
    pub struct APPLICATION_DATA;
}

/// State which client sends.
pub trait ClientSend: Private {}
/// State which client expects a message from server.
pub trait ClientExpect: Private {}

/// State which server sends.
pub trait ServerSend: Private {}

/// State which server expects a message from client.
pub trait ServerExpect: Private {}

macro_rules! impl_client_send {
    ($($i:path),*) => {
        $(
            impl Private for $i {}
            impl ClientSend for $i {}
            impl ServerExpect for $i {}
        )*
    };
}

impl_client_send!(
    client::CLIENT_HELLO,
    client::CERTIFICATE,
    client::CLIENT_KEY_EXCHANGE,
    client::CERTIFICATE_VERIFY,
    client::CHANGE_CIPHER_SPEC,
    client::FINISHED,
    client::APPLICATION_DATA
);

macro_rules! impl_server_send {
    ($($i:path),*) => {
        $(
            impl Private for $i {}
            impl ServerSend for $i {}
            impl ClientExpect for $i {}
        )*
    };
}

impl_server_send!(
    server::SERVER_HELLO,
    server::CERTIFICATE,
    server::SERVER_KEY_EXCHANGE,
    server::CERTIFICATE_REQUEST,
    server::SERVER_HELLO_DONE,
    server::CHANGE_CIPHER_SPEC,
    server::NEW_SESSION_TICKET,
    server::FINISHED,
    server::APPLICATION_DATA
);
