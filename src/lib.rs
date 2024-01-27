//! str0m DTLS implementation.
//!
//! A [DTLS 1.2][dtls] implementation, which in turns is a variant
//! of [TLS 1.2][tls].
//!
//! [dtls]: https://datatracker.ietf.org/doc/html/rfc6347
//! [tls] : https://datatracker.ietf.org/doc/html/rfc5246

mod error;
pub use error::DimplError;

mod codec;

pub(crate) mod types;

mod record;
pub use record::DtlsPlainText;
