#![forbid(unsafe_code)]
#![warn(clippy::all)]
// #![deny(missing_docs)]

pub mod state;

mod client;
pub use client::Client;

mod message;
