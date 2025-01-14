#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
// #![deny(missing_docs)]

const MAX_MTU: usize = 2200;

#[macro_use]
extern crate log;

pub mod state;

mod client;
pub use client::Client;

pub(crate) mod message;

mod time_tricks;

mod engine;
mod incoming;

mod util;

mod error;
pub use error::Error;
