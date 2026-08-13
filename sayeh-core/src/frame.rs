use core::fmt;
use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FILE_NAME_BYTES: usize = 255;
pub const FRAME_FIXED_BYTES: usize = 24;
pub const BUCKET_BYTES: usize = 64;
const FRAME_VERSION: u8 = 1;

/// Borrowed content passed to a sealing operation.
#[derive(Debug, Clone, Copy)]
pub enum Content<'a> {
    Text(&'a str),
    File { name: &'a str, bytes: &'a [u8] },
}

impl Content<'_> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::File { bytes, .. } => bytes,
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        match self {
            Self::Text(_) => None,
            Self::File { name, .. } => Some(name),
        }
    }
}

/// Decrypted content whose buffers are wiped on drop.
pub struct OpenedPayload {
    text: bool,
    file_name: Option<Zeroizing<String>>,
    bytes: Zeroizing<Vec<u8>>,
    counter: u64,
    created_at: u64,
}

impl OpenedPayload {
    pub const fn is_text(&self) -> bool {
        self.text
    }

    pub fn file_name(&self) -> Option<&str> {
        self.file_name.as_deref().map(String::as_str)
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn text(&self) -> Option<&str> {
        if self.text {
            std::str::from_utf8(self.bytes()).ok()
        } else {
            None
        }
    }

    pub const fn counter(&self) -> u64 {
        self.counter
    }

    pub const fn created_at(&self) -> u64 {
        self.created_at
    }
}

impl fmt::Debug for OpenedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedPayload")
            .field("text", &self.text)
            .field("file_name", &self.file_name.as_ref().map(|_| "[REDACTED]"))
            .field("bytes", &"[REDACTED]")
            .field("counter", &self.counter)
            .field("created_at", &self.created_at)
            .finish()
    }
}

pub(crate) fn encode(content: Content<'_>, counter: u64, created_at: u64) -> Result<Vec<u8>> {
    let bytes = content.bytes();
    if bytes.len() > MAX_CONTENT_BYTES {
        return Err(Error::ContentTooLarge);
    }
    let name = content.file_name().unwrap_or("");
    validate_name(name, content.file_name().is_some())?;
    let total = FRAME_FIXED_BYTES
        .checked_add(name.len())
        .and_then(|value| value.checked_add(bytes.len()))
        .ok_or(Error::LengthOverflow)?;
    let mut frame = Vec::with_capacity(total);
    frame.push(FRAME_VERSION);
    frame.push(if content.file_name().is_some() { 2 } else { 1 });
    frame.extend_from_slice(
        &u16::try_from(name.len())
            .map_err(|_| Error::LengthOverflow)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&counter.to_be_bytes());
    frame.extend_from_slice(&created_at.to_be_bytes());
    frame.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::LengthOverflow)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(name.as_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}

pub(crate) fn compress(frame: &[u8]) -> Result<(Vec<u8>, bool)> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(frame).map_err(|_| Error::Compression)?;
    let compressed = encoder.finish().map_err(|_| Error::Compression)?;
    if compressed.len() < frame.len() {
        Ok((compressed, true))
    } else {
        Ok((frame.to_vec(), false))
    }
}

pub(crate) fn pad<R>(encoded: &[u8], rng: &mut R) -> Result<Zeroizing<Vec<u8>>>
where
    R: RngCore + CryptoRng,
{
    let needed = 4usize
        .checked_add(encoded.len())
        .ok_or(Error::LengthOverflow)?;
    let buckets = needed
        .checked_add(BUCKET_BYTES - 1)
        .ok_or(Error::LengthOverflow)?
        / BUCKET_BYTES;
    let total = buckets
        .max(1)
        .checked_mul(BUCKET_BYTES)
        .ok_or(Error::LengthOverflow)?;
    let mut padded = Zeroizing::new(vec![0u8; total]);
    let length = u32::try_from(encoded.len()).map_err(|_| Error::LengthOverflow)?;
    let prefix = padded.get_mut(..4).ok_or(Error::LengthOverflow)?;
    prefix.copy_from_slice(&length.to_be_bytes());
    let body_end = 4usize
        .checked_add(encoded.len())
        .ok_or(Error::LengthOverflow)?;
    let body = padded.get_mut(4..body_end).ok_or(Error::LengthOverflow)?;
    body.copy_from_slice(encoded);
    let padding = padded.get_mut(body_end..).ok_or(Error::LengthOverflow)?;
    rng.try_fill_bytes(padding)
        .map_err(|_| Error::RandomSource)?;
    Ok(padded)
}

pub(crate) fn decode(padded: &[u8], compressed: bool) -> Result<OpenedPayload> {
    let length_bytes: [u8; 4] = padded
        .get(..4)
        .ok_or(Error::OpenFailed)?
        .try_into()
        .map_err(|_| Error::OpenFailed)?;
    let encoded_len =
        usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| Error::OpenFailed)?;
    let end = 4usize.checked_add(encoded_len).ok_or(Error::OpenFailed)?;
    let encoded = padded.get(4..end).ok_or(Error::OpenFailed)?;
    let frame = if compressed {
        let decoder = DeflateDecoder::new(encoded);
        let mut bounded = decoder.take((MAX_CONTENT_BYTES + FRAME_FIXED_BYTES + 257) as u64);
        let mut output = Vec::new();
        bounded
            .read_to_end(&mut output)
            .map_err(|_| Error::OpenFailed)?;
        if output.len() > MAX_CONTENT_BYTES + FRAME_FIXED_BYTES + MAX_FILE_NAME_BYTES {
            return Err(Error::OpenFailed);
        }
        Zeroizing::new(output)
    } else {
        Zeroizing::new(encoded.to_vec())
    };
    parse_frame(&frame).map_err(|_| Error::OpenFailed)
}

fn parse_frame(frame: &[u8]) -> Result<OpenedPayload> {
    let mut reader = FrameReader::new(frame);
    if reader.byte()? != FRAME_VERSION {
        return Err(Error::InvalidContainer);
    }
    let kind = reader.byte()?;
    if !matches!(kind, 1 | 2) {
        return Err(Error::InvalidContainer);
    }
    let name_len = usize::from(reader.u16()?);
    let counter = reader.u64()?;
    let created_at = reader.u64()?;
    let content_len = usize::try_from(reader.u32()?).map_err(|_| Error::LengthOverflow)?;
    if content_len > MAX_CONTENT_BYTES || name_len > MAX_FILE_NAME_BYTES {
        return Err(Error::ContentTooLarge);
    }
    if (kind == 1 && name_len != 0) || (kind == 2 && name_len == 0) {
        return Err(Error::InvalidContainer);
    }
    let name_bytes = reader.take(name_len)?;
    let content = reader.take(content_len)?;
    if !reader.finished() {
        return Err(Error::InvalidContainer);
    }
    let name = std::str::from_utf8(name_bytes).map_err(|_| Error::InvalidFileName)?;
    validate_name(name, kind == 2)?;
    if kind == 1 {
        std::str::from_utf8(content).map_err(|_| Error::InvalidContainer)?;
    }
    Ok(OpenedPayload {
        text: kind == 1,
        file_name: if kind == 2 {
            Some(Zeroizing::new(name.to_owned()))
        } else {
            None
        },
        bytes: Zeroizing::new(content.to_vec()),
        counter,
        created_at,
    })
}

fn validate_name(name: &str, required: bool) -> Result<()> {
    if (!required && !name.is_empty())
        || (required && name.is_empty())
        || name.len() > MAX_FILE_NAME_BYTES
        || name == "."
        || name == ".."
        || name.chars().any(|ch| matches!(ch, '/' | '\\' | '\0'))
    {
        return Err(Error::InvalidFileName);
    }
    Ok(())
}

struct FrameReader<'a> {
    frame: &'a [u8],
    position: usize,
}

impl<'a> FrameReader<'a> {
    const fn new(frame: &'a [u8]) -> Self {
        Self { frame, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::LengthOverflow)?;
        let value = self.frame.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or(Error::Truncated)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| Error::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| Error::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn finished(&self) -> bool {
        self.position == self.frame.len()
    }
}
