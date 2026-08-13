use thiserror::Error;

/// Errors returned at Sayeh's untrusted-input boundaries.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("no Sayeh payload was found")]
    NoPayload,
    #[error(
        "this is a v3 payload; v4 refuses it because v3 uses PBKDF2 and treats emoji ZWJ as data"
    )]
    LegacyV3Refused,
    #[error("the recovered data is not a canonical Sayeh v4 container")]
    InvalidContainer,
    #[error("the Sayeh payload is truncated")]
    Truncated,
    #[error("wire version {0} is not supported")]
    UnsupportedVersion(u8),
    #[error("embedding revision {0} is not supported")]
    UnsupportedEmbedding(u8),
    #[error("this payload uses a feature that this build does not support: {0}")]
    UnsupportedFeature(&'static str),
    #[error("Argon2 parameters are outside the accepted safety range")]
    KdfParameters,
    #[error("the password must not be empty")]
    EmptyPassword,
    #[error("decryption failed: the key is wrong or the payload was altered")]
    OpenFailed,
    #[error("the secure random source failed")]
    RandomSource,
    #[error("the cover already contains {carrier} carrier characters")]
    CoverContainsCarrier { carrier: &'static str },
    #[error("invalid file name")]
    InvalidFileName,
    #[error("content exceeds the 16 MiB limit")]
    ContentTooLarge,
    #[error("the selected operation does not match the payload mode")]
    ModeMismatch,
    #[error("contact key agreement failed")]
    KeyAgreement,
    #[error("contact counters start at one")]
    InvalidCounter,
    #[error("the contact message counter was already seen")]
    Replay,
    #[error("in-memory compression failed")]
    Compression,
    #[error("an internal length calculation overflowed")]
    LengthOverflow,
    #[error("an internal cryptographic operation failed")]
    Crypto,
}

/// Result type used throughout `sayeh-core`.
pub type Result<T> = core::result::Result<T, Error>;
