#[cfg(not(windows))]
#[path = "../wolfssl/mod.rs"]
mod wolfssl_helper;

mod ack;
mod common;
#[cfg(feature = "rcgen")]
#[path = "../common/mod.rs"]
mod shared;
#[cfg(feature = "rcgen")]
#[path = "."]
mod rcgen {
    mod conformance;
    mod data;
    mod edge;
    mod fragmentation;
    mod handshake;
    mod key_update;
    mod reorder;
    mod retransmit;
}

#[cfg(not(windows))]
mod wolfssl;
