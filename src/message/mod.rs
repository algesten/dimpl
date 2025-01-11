mod client_hello;
pub use client_hello::ClientHello;

mod server_hello;
pub use server_hello::ServerHello;

mod certificate;
pub use certificate::Certificate;

mod server_key_exchange;
pub use server_key_exchange::ServerKeyExchange;

mod certificate_verify;
pub use certificate_verify::CertificateVerify;

mod client_key_exchange;
pub use client_key_exchange::ClientKeyExchange;

mod finished;
pub use finished::Finished;

mod change_cipher_spec;
pub use change_cipher_spec::ChangeCipherSpec;

mod new_session_ticket;
pub use new_session_ticket::NewSessionTicket;

mod fragment;

mod handshake;
pub use handshake::Handshake;

#[derive(Debug)]
pub enum Message {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificate),
    ServerKeyExchange(ServerKeyExchange),
    CertificateVerify(CertificateVerify),
    ClientKeyExchange(ClientKeyExchange),
    Finished(Finished),
    ChangeCipherSpec(ChangeCipherSpec),
    NewSessionTicket(NewSessionTicket),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    EECDH_AESGCM,
    EDH_AESGCM,
    AES256_EECDH,
    AES256_EDH,
    Unknown(u16),
}

impl CipherSuite {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0xC02F => CipherSuite::EECDH_AESGCM,
            0xC030 => CipherSuite::EDH_AESGCM,
            0xC031 => CipherSuite::AES256_EECDH,
            0xC032 => CipherSuite::AES256_EDH,
            _ => CipherSuite::Unknown(value),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            CipherSuite::EECDH_AESGCM => 0xC02F,
            CipherSuite::EDH_AESGCM => 0xC030,
            CipherSuite::AES256_EECDH => 0xC031,
            CipherSuite::AES256_EDH => 0xC032,
            CipherSuite::Unknown(value) => *value,
        }
    }
}
