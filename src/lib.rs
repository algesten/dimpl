#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
// #![deny(missing_docs)]

#[macro_use]
extern crate log;

pub mod state;

mod client;
pub use client::Client;

pub(crate) mod message;

mod time_tricks;
