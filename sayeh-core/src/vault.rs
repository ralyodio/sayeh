use rand_core::OsRng;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::{
    Argon2Params, NONCE_BYTES, SALT_BYTES, TAG_BYTES, derive_password_key, open, random_array, seal,
};
use crate::{Error, Result};

const MAGIC: [u8; 5] = *b"SYKV1";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 62;
const BUCKET_BYTES: usize = 4096;
const MAX_VAULT_BYTES: usize = 1024 * 1024;

/// Encrypts serialized contact state with the operating-system random source.
pub fn seal_vault(plaintext: &[u8], password: &[u8], parameters: Argon2Params) -> Result<Vec<u8>> {
    seal_vault_with_rng(plaintext, password, parameters, &mut OsRng)
}

/// Deterministic-RNG vault entry point for tests.
pub fn seal_vault_with_rng<R>(
    plaintext: &[u8],
    password: &[u8],
    parameters: Argon2Params,
    rng: &mut R,
) -> Result<Vec<u8>>
where
    R: RngCore + CryptoRng,
{
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    if plaintext.len() > MAX_VAULT_BYTES {
        return Err(Error::ContentTooLarge);
    }
    let salt = random_array::<R, SALT_BYTES>(rng)?;
    let nonce = random_array::<R, NONCE_BYTES>(rng)?;
    let key = derive_password_key(password, &salt, parameters)?;
    let inner_len = 4usize
        .checked_add(plaintext.len())
        .ok_or(Error::LengthOverflow)?;
    let buckets = inner_len
        .checked_add(BUCKET_BYTES - 1)
        .ok_or(Error::LengthOverflow)?
        / BUCKET_BYTES;
    let padded_len = buckets
        .max(1)
        .checked_mul(BUCKET_BYTES)
        .ok_or(Error::LengthOverflow)?;
    let mut inner = Zeroizing::new(vec![0u8; padded_len]);
    inner
        .get_mut(..4)
        .ok_or(Error::LengthOverflow)?
        .copy_from_slice(
            &u32::try_from(plaintext.len())
                .map_err(|_| Error::LengthOverflow)?
                .to_be_bytes(),
        );
    let data_end = 4usize
        .checked_add(plaintext.len())
        .ok_or(Error::LengthOverflow)?;
    inner
        .get_mut(4..data_end)
        .ok_or(Error::LengthOverflow)?
        .copy_from_slice(plaintext);
    rng.try_fill_bytes(inner.get_mut(data_end..).ok_or(Error::LengthOverflow)?)
        .map_err(|_| Error::RandomSource)?;
    let ciphertext_len = inner
        .len()
        .checked_add(TAG_BYTES)
        .ok_or(Error::LengthOverflow)?;
    let header = header(parameters, &salt, &nonce, ciphertext_len)?;
    let ciphertext = seal(&key, &nonce, &inner, &header)?;
    let total = header
        .len()
        .checked_add(ciphertext.len())
        .ok_or(Error::LengthOverflow)?;
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Authenticates and decrypts serialized contact state.
pub fn open_vault(bytes: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if password.is_empty() {
        return Err(Error::OpenFailed);
    }
    if bytes.len() < HEADER_BYTES || !bytes.starts_with(&MAGIC) {
        return Err(Error::OpenFailed);
    }
    let version = bytes.get(5).copied().ok_or(Error::OpenFailed)?;
    if version != VERSION {
        return Err(Error::OpenFailed);
    }
    let memory = read_u32(bytes, 6)?;
    let passes = read_u32(bytes, 10)?;
    let lanes = bytes.get(14).copied().ok_or(Error::OpenFailed)?;
    if bytes.get(15..18) != Some(&[0u8; 3]) {
        return Err(Error::OpenFailed);
    }
    let parameters = Argon2Params::new(memory, passes, lanes).map_err(|_| Error::OpenFailed)?;
    let salt: [u8; SALT_BYTES] = bytes
        .get(18..34)
        .ok_or(Error::OpenFailed)?
        .try_into()
        .map_err(|_| Error::OpenFailed)?;
    let nonce: [u8; NONCE_BYTES] = bytes
        .get(34..58)
        .ok_or(Error::OpenFailed)?
        .try_into()
        .map_err(|_| Error::OpenFailed)?;
    let ciphertext_len = usize::try_from(read_u32(bytes, 58)?).map_err(|_| Error::OpenFailed)?;
    let total = HEADER_BYTES
        .checked_add(ciphertext_len)
        .ok_or(Error::OpenFailed)?;
    if bytes.len() != total || ciphertext_len > MAX_VAULT_BYTES + BUCKET_BYTES + TAG_BYTES {
        return Err(Error::OpenFailed);
    }
    let aad = bytes.get(..HEADER_BYTES).ok_or(Error::OpenFailed)?;
    let ciphertext = bytes.get(HEADER_BYTES..).ok_or(Error::OpenFailed)?;
    let key = derive_password_key(password, &salt, parameters).map_err(|_| Error::OpenFailed)?;
    let inner = open(&key, &nonce, ciphertext, aad)?;
    let length = usize::try_from(read_u32(&inner, 0)?).map_err(|_| Error::OpenFailed)?;
    if length > MAX_VAULT_BYTES {
        return Err(Error::OpenFailed);
    }
    let end = 4usize.checked_add(length).ok_or(Error::OpenFailed)?;
    let plaintext = inner.get(4..end).ok_or(Error::OpenFailed)?.to_vec();
    Ok(Zeroizing::new(plaintext))
}

fn header(
    parameters: Argon2Params,
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext_len: usize,
) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(&MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&parameters.memory_kib().to_be_bytes());
    header.extend_from_slice(&parameters.passes().to_be_bytes());
    header.push(parameters.lanes());
    header.extend_from_slice(&[0u8; 3]);
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    header.extend_from_slice(
        &u32::try_from(ciphertext_len)
            .map_err(|_| Error::LengthOverflow)?
            .to_be_bytes(),
    );
    if header.len() != HEADER_BYTES {
        return Err(Error::LengthOverflow);
    }
    Ok(header)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::OpenFailed)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(Error::OpenFailed)?
        .try_into()
        .map_err(|_| Error::OpenFailed)?;
    Ok(u32::from_be_bytes(value))
}
