#![forbid(unsafe_code)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Cryptography, containers, and carrier operations for Sayeh.

mod error;

pub mod carrier;
#[cfg(feature = "contacts")]
pub mod contact;
pub mod container;
pub mod cost;
pub mod crypto;
pub mod embed;
pub mod frame;
pub mod pipeline;
pub mod probe;
pub mod steganalysis;

pub use error::{Error, Result};

/// The only wire version emitted by this crate.
pub const WIRE_VERSION: u8 = 4;

/// The embedding algorithm revision implemented by this crate.
pub const EMBEDDING_REVISION: u8 = 1;
