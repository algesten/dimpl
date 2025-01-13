#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
// #![deny(missing_docs)]

pub mod state;

mod client;
pub use client::Client;

pub(crate) mod message;
