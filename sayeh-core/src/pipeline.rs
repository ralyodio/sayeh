use rand_core::OsRng;
use rand_core::{CryptoRng, RngCore};

use crate::carrier::{Carrier, CarrierKind, count_any, looks_like_v3, strip_safe};
use crate::container::{
    CONTACT_HEADER_BYTES, Header, ModeHeader, PASSWORD_HEADER_BYTES, PasswordHeader,
    SealedContainer,
};
use crate::cost::CostMap;
use crate::crypto::{
    Argon2Params, NONCE_BYTES, SALT_BYTES, TAG_BYTES, derive_password_key, open, random_array, seal,
};
use crate::embed::scatter_bytes;
use crate::frame::{
    BUCKET_BYTES, Content, FRAME_FIXED_BYTES, MAX_CONTENT_BYTES, OpenedPayload, compress, decode,
    encode, pad,
};
use crate::steganalysis::{Analysis, analyse};
use crate::{Error, Result};

/// Password-mode settings supplied by an application surface.
#[derive(Debug, Clone, Copy)]
pub struct PasswordOptions {
    pub carrier: CarrierKind,
    pub parameters: Argon2Params,
    pub created_at: u64,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            carrier: CarrierKind::ZeroWidth,
            parameters: Argon2Params::DEFAULT,
            created_at: 0,
        }
    }
}

/// Metadata returned after a successful hide operation.
#[derive(Debug, Clone, PartialEq)]
pub struct HideReport {
    pub carrier: CarrierKind,
    pub content_bytes: usize,
    pub container_bytes: usize,
    pub carrier_symbols: usize,
    pub safe_slots: usize,
    pub compressed: bool,
    pub analysis: Analysis,
}

/// Stego text and its measured report.
#[derive(Debug, Clone, PartialEq)]
pub struct HiddenMessage {
    pub text: String,
    pub report: HideReport,
}

/// Identified but still sealed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedPayload {
    carrier: CarrierKind,
    container: SealedContainer,
    symbols: usize,
}

impl ScannedPayload {
    pub const fn carrier(&self) -> CarrierKind {
        self.carrier
    }

    pub const fn container(&self) -> &SealedContainer {
        &self.container
    }

    pub const fn symbols(&self) -> usize {
        self.symbols
    }
}

/// Conservative capacity for incompressible content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    pub safe_slots: usize,
    pub container_bytes: usize,
    pub content_bytes: usize,
}

/// Header shape used by the capacity estimator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityMode {
    Password,
    Contact,
}

/// Hides bytes with an operating-system random source.
pub fn hide_password(
    cover: &str,
    content: Content<'_>,
    password: &[u8],
    options: PasswordOptions,
) -> Result<HiddenMessage> {
    hide_password_with_rng(cover, content, password, options, &mut OsRng)
}

/// Deterministic-RNG entry point used by vectors and property tests.
pub fn hide_password_with_rng<R>(
    cover: &str,
    content: Content<'_>,
    password: &[u8],
    options: PasswordOptions,
    rng: &mut R,
) -> Result<HiddenMessage>
where
    R: RngCore + CryptoRng,
{
    let salt = random_array::<R, SALT_BYTES>(rng)?;
    let nonce = random_array::<R, NONCE_BYTES>(rng)?;
    let key = derive_password_key(password, &salt, options.parameters)?;
    let frame = encode(content, 0, options.created_at)?;
    let (encoded, compressed) = compress(&frame)?;
    let padded = pad(&encoded, rng)?;
    let payload_len = padded
        .len()
        .checked_add(TAG_BYTES)
        .ok_or(Error::LengthOverflow)?;
    let header = Header::new(
        options.carrier,
        compressed,
        ModeHeader::Password(PasswordHeader::new(options.parameters, salt, nonce)),
    );
    let aad = header.encode(payload_len)?;
    let ciphertext = seal(&key, &nonce, &padded, &aad)?;
    let container = SealedContainer::new(header, ciphertext)?;
    let raw = container.marshal()?;
    let text = scatter_bytes(cover, &raw, options.carrier, &key, &nonce)?;
    let map = CostMap::new(cover, options.carrier);
    let carrier_symbols = options.carrier.symbols_for_bytes(raw.len())?;
    let analysis = analyse(&text, options.carrier);
    let report = HideReport {
        carrier: options.carrier,
        content_bytes: content.bytes().len(),
        container_bytes: raw.len(),
        carrier_symbols,
        safe_slots: map.safe_slots(),
        compressed,
        analysis,
    };
    Ok(HiddenMessage { text, report })
}

/// Auto-detects a v4 carrier and validates its public container structure.
pub fn scan(text: &str) -> Result<ScannedPayload> {
    let mut structural = None;
    for carrier in CarrierKind::ALL {
        let raw = carrier.decode(text);
        if !raw.starts_with(b"SYH4") {
            continue;
        }
        match SealedContainer::parse(&raw) {
            Ok(container) if container.header().carrier() == carrier => {
                let symbols = carrier
                    .detect(text)
                    .map_or(0, |detection| detection.symbols);
                return Ok(ScannedPayload {
                    carrier,
                    container,
                    symbols,
                });
            }
            Ok(_) => structural = Some(Error::InvalidContainer),
            Err(error) => structural = Some(error),
        }
    }
    if looks_like_v3(text) {
        return Err(Error::LegacyV3Refused);
    }
    if let Some(error) = structural {
        return Err(error);
    }
    if count_any(text) == 0 {
        Err(Error::NoPayload)
    } else {
        Err(Error::InvalidContainer)
    }
}

/// Opens password-mode content. Authentication and frame failures are uniform.
pub fn reveal_password(text: &str, password: &[u8]) -> Result<OpenedPayload> {
    let scanned = scan(text)?;
    open_password(scanned.container(), password)
}

pub(crate) fn open_password(container: &SealedContainer, password: &[u8]) -> Result<OpenedPayload> {
    let ModeHeader::Password(header) = container.header().mode() else {
        return Err(Error::ModeMismatch);
    };
    let key = derive_password_key(password, header.salt(), header.parameters())
        .map_err(|_| Error::OpenFailed)?;
    let plaintext = open(&key, header.nonce(), container.payload(), container.aad())?;
    decode(&plaintext, container.header().compressed()).map_err(|_| Error::OpenFailed)
}

/// Removes a recognized payload while keeping emoji ZWJ and Persian ZWNJ.
pub fn clean_safe(text: &str) -> String {
    let identified = scan(text).ok().map(|payload| payload.carrier());
    strip_safe(text, identified)
}

/// Computes the largest incompressible content that stays below the safe rate.
pub fn capacity(
    cover: &str,
    carrier: CarrierKind,
    mode: CapacityMode,
    file_name_bytes: usize,
) -> Result<Capacity> {
    if file_name_bytes > 255 {
        return Err(Error::InvalidFileName);
    }
    let safe_slots = CostMap::new(cover, carrier).safe_slots();
    let header_bytes = match mode {
        CapacityMode::Password => PASSWORD_HEADER_BYTES,
        CapacityMode::Contact => CONTACT_HEADER_BYTES,
    };
    let mut low = 0usize;
    let mut high = MAX_CONTENT_BYTES.saturating_add(1);
    while low < high {
        let middle = low + (high - low) / 2;
        let fits = container_size(header_bytes, file_name_bytes, middle)
            .and_then(|size| carrier.symbols_for_bytes(size))
            .is_ok_and(|symbols| symbols <= safe_slots);
        if fits {
            low = middle.saturating_add(1);
        } else {
            high = middle;
        }
    }
    let content_bytes = low.saturating_sub(1);
    let container_bytes = container_size(header_bytes, file_name_bytes, content_bytes)?;
    Ok(Capacity {
        safe_slots,
        container_bytes,
        content_bytes,
    })
}

fn container_size(header: usize, file_name: usize, content: usize) -> Result<usize> {
    let frame = FRAME_FIXED_BYTES
        .checked_add(file_name)
        .and_then(|value| value.checked_add(content))
        .ok_or(Error::LengthOverflow)?;
    let inner = 4usize.checked_add(frame).ok_or(Error::LengthOverflow)?;
    let padded = inner
        .checked_add(BUCKET_BYTES - 1)
        .ok_or(Error::LengthOverflow)?
        / BUCKET_BYTES
        * BUCKET_BYTES;
    header
        .checked_add(padded.max(BUCKET_BYTES))
        .and_then(|value| value.checked_add(TAG_BYTES))
        .ok_or(Error::LengthOverflow)
}
