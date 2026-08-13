use core::fmt;
use std::str::FromStr;

use unicode_general_category::{GeneralCategory, get_general_category};

use crate::{Error, Result};

const ZERO_WIDTH: [char; 4] = ['\u{200b}', '\u{2060}', '\u{2062}', '\u{2064}'];
const ZERO_WIDTH_COMPAT: [char; 2] = ['\u{200b}', '\u{2060}'];
const VARIATION_SELECTORS: [char; 16] = [
    '\u{fe00}', '\u{fe01}', '\u{fe02}', '\u{fe03}', '\u{fe04}', '\u{fe05}', '\u{fe06}', '\u{fe07}',
    '\u{fe08}', '\u{fe09}', '\u{fe0a}', '\u{fe0b}', '\u{fe0c}', '\u{fe0d}', '\u{fe0e}', '\u{fe0f}',
];
const TAGS: [char; 128] = make_tags();

const fn make_tags() -> [char; 128] {
    let mut out = ['\u{e0000}'; 128];
    let mut index = 0;
    while index < out.len() {
        let value = 0xe0000 + index as u32;
        out[index] = match char::from_u32(value) {
            Some(ch) => ch,
            None => '\u{e0000}',
        };
        index += 1;
    }
    out
}

/// A wire-format carrier backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum CarrierKind {
    ZeroWidth = 1,
    ZeroWidthCompat = 2,
    VariationSelectors = 3,
    UnicodeTags = 4,
}

impl CarrierKind {
    /// Carriers in decoder preference order.
    pub const ALL: [Self; 4] = [
        Self::ZeroWidth,
        Self::ZeroWidthCompat,
        Self::VariationSelectors,
        Self::UnicodeTags,
    ];

    /// Parses the authenticated carrier identifier.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::ZeroWidth),
            2 => Ok(Self::ZeroWidthCompat),
            3 => Ok(Self::VariationSelectors),
            4 => Ok(Self::UnicodeTags),
            _ => Err(Error::InvalidContainer),
        }
    }

    /// Stable wire identifier.
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Human-readable command-line name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ZeroWidth => "zero-width",
            Self::ZeroWidthCompat => "zero-width-compat",
            Self::VariationSelectors => "variation-selectors",
            Self::UnicodeTags => "unicode-tags",
        }
    }

    /// Number of payload bits represented by one carrier scalar.
    pub const fn bits_per_symbol(self) -> u8 {
        match self {
            Self::ZeroWidth => 2,
            Self::ZeroWidthCompat => 1,
            Self::VariationSelectors => 4,
            Self::UnicodeTags => 7,
        }
    }

    /// Returns true when the scalar belongs to this carrier.
    pub fn contains(self, ch: char) -> bool {
        self.alphabet().contains(&ch)
    }

    /// Number of carrier scalars required for a byte stream.
    pub fn symbols_for_bytes(self, bytes: usize) -> Result<usize> {
        let bits = bytes.checked_mul(8).ok_or(Error::LengthOverflow)?;
        let width = usize::from(self.bits_per_symbol());
        bits.checked_add(width - 1)
            .ok_or(Error::LengthOverflow)
            .map(|value| value / width)
    }
}

impl fmt::Display for CarrierKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for CarrierKind {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "zero-width" | "zero" | "zw" | "default" => Ok(Self::ZeroWidth),
            "zero-width-compat" | "compat" | "zw-compat" => Ok(Self::ZeroWidthCompat),
            "variation-selectors" | "variation" | "vs" => Ok(Self::VariationSelectors),
            "unicode-tags" | "tags" | "tag" => Ok(Self::UnicodeTags),
            _ => Err(Error::InvalidContainer),
        }
    }
}

/// Common behavior implemented by carrier backends.
pub trait Carrier {
    fn alphabet(&self) -> &'static [char];
    fn encode<'a>(&'a self, data: &'a [u8]) -> CarrierEncoder<'a>;
    fn decode(&self, text: &str) -> Vec<u8>;
    fn detect(&self, text: &str) -> Option<Detection>;
}

impl Carrier for CarrierKind {
    fn alphabet(&self) -> &'static [char] {
        match self {
            Self::ZeroWidth => &ZERO_WIDTH,
            Self::ZeroWidthCompat => &ZERO_WIDTH_COMPAT,
            Self::VariationSelectors => &VARIATION_SELECTORS,
            Self::UnicodeTags => &TAGS,
        }
    }

    fn encode<'a>(&'a self, data: &'a [u8]) -> CarrierEncoder<'a> {
        CarrierEncoder {
            data,
            alphabet: self.alphabet(),
            width: self.bits_per_symbol(),
            bit_offset: 0,
        }
    }

    fn decode(&self, text: &str) -> Vec<u8> {
        decode_with_alphabet(text, self.alphabet(), self.bits_per_symbol())
    }

    fn detect(&self, text: &str) -> Option<Detection> {
        let mut count = 0usize;
        let mut first_byte = None;
        let mut last_byte = 0usize;
        for (offset, ch) in text.char_indices() {
            if self.contains(ch) {
                count = count.saturating_add(1);
                first_byte.get_or_insert(offset);
                last_byte = offset;
            }
        }
        first_byte.map(|first_byte| Detection {
            carrier: *self,
            symbols: count,
            first_byte,
            last_byte,
        })
    }
}

/// Iterator returned by a carrier encoder.
pub struct CarrierEncoder<'a> {
    data: &'a [u8],
    alphabet: &'static [char],
    width: u8,
    bit_offset: usize,
}

impl Iterator for CarrierEncoder<'_> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        let total_bits = self.data.len().checked_mul(8)?;
        if self.bit_offset >= total_bits {
            return None;
        }

        let mut symbol = 0usize;
        for _ in 0..self.width {
            symbol <<= 1;
            if self.bit_offset < total_bits {
                let byte = self.data.get(self.bit_offset / 8).copied()?;
                let shift = 7usize.saturating_sub(self.bit_offset % 8);
                symbol |= usize::from((byte >> shift) & 1);
                self.bit_offset = self.bit_offset.saturating_add(1);
            }
        }
        self.alphabet.get(symbol).copied()
    }
}

/// Location summary for carrier characters in text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    pub carrier: CarrierKind,
    pub symbols: usize,
    pub first_byte: usize,
    pub last_byte: usize,
}

fn decode_with_alphabet(text: &str, alphabet: &[char], width: u8) -> Vec<u8> {
    let mut output = Vec::new();
    let mut accumulator = 0u32;
    let mut held = 0u8;

    for ch in text.chars() {
        let Some(symbol) = alphabet.iter().position(|candidate| *candidate == ch) else {
            continue;
        };
        accumulator = (accumulator << width) | symbol as u32;
        held = held.saturating_add(width);
        if held >= 8 {
            let remaining = held - 8;
            output.push(((accumulator >> remaining) & 0xff) as u8);
            accumulator &= if remaining == 0 {
                0
            } else {
                (1u32 << remaining) - 1
            };
            held = remaining;
        }
    }
    output
}

/// Detects a v3 magic string without accepting or cleaning its ZWJ alphabet.
pub fn looks_like_v3(text: &str) -> bool {
    const V3_B4: [char; 4] = ['\u{200b}', '\u{200d}', '\u{2060}', '\u{2064}'];
    const V3_B2: [char; 2] = ['\u{200d}', '\u{200b}'];
    [(V3_B4.as_slice(), 2u8), (V3_B2.as_slice(), 1u8)]
        .iter()
        .any(|(alphabet, width)| {
            let magic = encode_with_alphabet(b"ZWS3", alphabet, *width);
            text.contains(&magic)
        })
}

fn encode_with_alphabet(data: &[u8], alphabet: &[char], width: u8) -> String {
    let mut output = String::new();
    let total_bits = data.len().saturating_mul(8);
    let mut bit_offset = 0usize;
    while bit_offset < total_bits {
        let mut symbol = 0usize;
        for _ in 0..width {
            symbol <<= 1;
            if let Some(byte) = data.get(bit_offset / 8) {
                let shift = 7usize.saturating_sub(bit_offset % 8);
                symbol |= usize::from((byte >> shift) & 1);
            }
            bit_offset = bit_offset.saturating_add(1);
        }
        if let Some(ch) = alphabet.get(symbol) {
            output.push(*ch);
        }
    }
    output
}

/// Removes raw v4 carriers while preserving ZWNJ and emoji ZWJ.
pub fn strip_safe(text: &str, identified: Option<CarrierKind>) -> String {
    text.chars()
        .filter(|ch| {
            if ZERO_WIDTH.contains(ch) {
                return false;
            }
            match identified {
                Some(CarrierKind::VariationSelectors) => !VARIATION_SELECTORS.contains(ch),
                Some(CarrierKind::UnicodeTags) => !TAGS.contains(ch),
                _ => true,
            }
        })
        .collect()
}

/// Destructive cleaning for callers that explicitly accept changed shaping.
pub fn strip_aggressive(text: &str) -> String {
    text.chars()
        .filter(|ch| {
            !matches!(get_general_category(*ch), GeneralCategory::Format)
                && !VARIATION_SELECTORS.contains(ch)
                && !TAGS.contains(ch)
        })
        .collect()
}

/// Counts every v4 carrier scalar, without double-counting shared alphabets.
pub fn count_any(text: &str) -> usize {
    text.chars()
        .filter(|ch| {
            ZERO_WIDTH.contains(ch) || VARIATION_SELECTORS.contains(ch) || TAGS.contains(ch)
        })
        .count()
}
