use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const KEY_BYTES: usize = 32;
pub const SALT_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 24;
pub const TAG_BYTES: usize = 16;

/// Validated Argon2id parameters carried only by password-mode headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    memory_kib: u32,
    passes: u32,
    lanes: u8,
}

impl Argon2Params {
    pub const MIN_MEMORY_KIB: u32 = 19_456;
    pub const MAX_MEMORY_KIB: u32 = 1_048_576;
    pub const MIN_PASSES: u32 = 2;
    pub const MAX_PASSES: u32 = 10;
    pub const MIN_LANES: u8 = 1;
    pub const MAX_LANES: u8 = 8;

    /// The measured 64 MiB, single-lane mobile profile.
    pub const DEFAULT: Self = Self {
        memory_kib: 65_536,
        passes: 10,
        lanes: 1,
    };

    /// Validates untrusted header values before any memory allocation.
    pub fn new(memory_kib: u32, passes: u32, lanes: u8) -> Result<Self> {
        if !(Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&memory_kib)
            || !(Self::MIN_PASSES..=Self::MAX_PASSES).contains(&passes)
            || !(Self::MIN_LANES..=Self::MAX_LANES).contains(&lanes)
        {
            return Err(Error::KdfParameters);
        }
        Ok(Self {
            memory_kib,
            passes,
            lanes,
        })
    }

    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    pub const fn passes(self) -> u32 {
        self.passes
    }

    pub const fn lanes(self) -> u8 {
        self.lanes
    }
}

/// Derives a 256-bit key with Argon2id v1.3.
pub fn derive_password_key(
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    parameters: Argon2Params,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let params = Params::new(
        parameters.memory_kib(),
        parameters.passes(),
        u32::from(parameters.lanes()),
        Some(KEY_BYTES),
    )
    .map_err(|_| Error::KdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

pub(crate) fn seal(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)
}

pub(crate) fn open(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::OpenFailed)
}

pub(crate) fn random_array<R, const N: usize>(rng: &mut R) -> Result<[u8; N]>
where
    R: RngCore + CryptoRng,
{
    let mut value = [0u8; N];
    rng.try_fill_bytes(&mut value)
        .map_err(|_| Error::RandomSource)?;
    Ok(value)
}
