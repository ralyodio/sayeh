#![forbid(unsafe_code)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Cryptography, containers, and carrier operations for Sayeh.

/// The only wire version emitted by this crate.
pub const WIRE_VERSION: u8 = 4;

/// The embedding algorithm revision implemented by this crate.
pub const EMBEDDING_REVISION: u8 = 1;
