use core::fmt;
use std::fmt::Write as _;

use hkdf::Hkdf;
use rand_core::OsRng;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::carrier::CarrierKind;
use crate::container::{ContactHeader, Header, ModeHeader, SealedContainer};
use crate::cost::CostMap;
use crate::crypto::{KEY_BYTES, NONCE_BYTES, TAG_BYTES, open, random_array, seal};
use crate::embed::scatter_bytes;
use crate::frame::{Content, OpenedPayload, compress, decode, encode, pad};
use crate::pipeline::{HiddenMessage, HideReport, scan};
use crate::steganalysis::analyse;
use crate::{Error, Result};

const INFO_PREFIX: &[u8] = b"sayeh/v4/contact/aead";
const FINGERPRINT_DOMAIN: &[u8] = b"sayeh/v4/fingerprint";
const WORDS: [&str; 32] = [
    "amber", "anchor", "apple", "atlas", "bamboo", "beacon", "birch", "blue", "cedar", "cinder",
    "coral", "dawn", "delta", "ember", "fern", "flint", "forest", "harbor", "hazel", "iris",
    "jade", "lagoon", "maple", "mesa", "mint", "north", "opal", "pearl", "pine", "river", "stone",
    "willow",
];

/// Static X25519 secret bytes, redacted from `Debug` and wiped on drop.
pub struct IdentitySecret {
    bytes: Zeroizing<[u8; 32]>,
}

impl IdentitySecret {
    /// Generates a new identity with the operating-system random source.
    pub fn generate() -> Result<Self> {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Deterministic-RNG constructor for vectors and tests.
    pub fn generate_with_rng<R>(rng: &mut R) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        Ok(Self {
            bytes: Zeroizing::new(random_array::<R, 32>(rng)?),
        })
    }

    /// Imports an identity from an already-decrypted backup.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Copies secret bytes only for an encrypted export boundary.
    pub fn expose_for_backup(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.bytes)
    }

    /// Corresponding public identity.
    pub fn public(&self) -> IdentityPublic {
        let secret = StaticSecret::from(*self.bytes);
        IdentityPublic(PublicKey::from(&secret).to_bytes())
    }

    fn dalek(&self) -> StaticSecret {
        StaticSecret::from(*self.bytes)
    }
}

impl fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentitySecret([REDACTED])")
    }
}

/// Public X25519 identity exchanged and verified out of band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityPublic([u8; 32]);

impl IdentityPublic {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality for identity checks near secret-bearing paths.
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// Contact-mode metadata supplied by the application store.
#[derive(Debug, Clone, Copy)]
pub struct ContactOptions {
    pub carrier: CarrierKind,
    pub counter: u64,
    pub created_at: u64,
}

/// One trial-decryption candidate and its replay floor.
#[derive(Debug, Clone, Copy)]
pub struct ContactCandidate {
    pub public: IdentityPublic,
    pub last_seen_counter: u64,
}

/// Authenticated sender index and opened content.
pub struct ContactOpened {
    pub candidate_index: usize,
    pub payload: OpenedPayload,
}

impl fmt::Debug for ContactOpened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactOpened")
            .field("candidate_index", &self.candidate_index)
            .field("payload", &self.payload)
            .finish()
    }
}

/// Human and QR fingerprint forms for one public identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub numeric: String,
    pub words: String,
    pub qr_payload: String,
    digest: [u8; 10],
}

impl Fingerprint {
    /// Constant-time comparison of the represented short authentication string.
    pub fn matches(&self, public: &IdentityPublic) -> bool {
        let expected = fingerprint_digest(public);
        bool::from(self.digest.ct_eq(&expected))
    }
}

/// Creates numeric, word, and full-key QR representations.
pub fn fingerprint(public: &IdentityPublic) -> Fingerprint {
    let digest = fingerprint_digest(public);
    let numeric = digest
        .chunks_exact(2)
        .map(|chunk| {
            let value = u16::from_be_bytes([chunk[0], chunk[1]]) % 10_000;
            format!("{value:04}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    let words = digest
        .iter()
        .take(8)
        .filter_map(|byte| WORDS.get(usize::from(*byte & 31)).copied())
        .collect::<Vec<_>>()
        .join(" ");
    let mut public_hex = String::with_capacity(64);
    for byte in public.as_bytes() {
        let _ = write!(public_hex, "{byte:02x}");
    }
    Fingerprint {
        numeric,
        words,
        qr_payload: format!("sayeh:x25519:{public_hex}"),
        digest,
    }
}

/// Hides content for a verified recipient with fresh ephemeral X25519.
pub fn hide_contact(
    cover: &str,
    content: Content<'_>,
    sender: &IdentitySecret,
    recipient: IdentityPublic,
    options: ContactOptions,
) -> Result<HiddenMessage> {
    hide_contact_with_rng(cover, content, sender, recipient, options, &mut OsRng)
}

/// Deterministic-RNG contact entry point for vectors and tests.
pub fn hide_contact_with_rng<R>(
    cover: &str,
    content: Content<'_>,
    sender: &IdentitySecret,
    recipient: IdentityPublic,
    options: ContactOptions,
    rng: &mut R,
) -> Result<HiddenMessage>
where
    R: RngCore + CryptoRng,
{
    if options.counter == 0 {
        return Err(Error::InvalidCounter);
    }
    let ephemeral_secret = StaticSecret::from(random_array::<R, 32>(rng)?);
    let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
    let nonce = random_array::<R, NONCE_BYTES>(rng)?;
    let key = sender_key(
        sender,
        recipient,
        &ephemeral_secret,
        ephemeral_public,
        &nonce,
    )?;
    let frame = encode(content, options.counter, options.created_at)?;
    let (encoded, compressed) = compress(&frame)?;
    let padded = pad(&encoded, rng)?;
    let payload_len = padded
        .len()
        .checked_add(TAG_BYTES)
        .ok_or(Error::LengthOverflow)?;
    let header = Header::new(
        options.carrier,
        compressed,
        ModeHeader::Contact(ContactHeader::new(ephemeral_public, nonce)),
    );
    let aad = header.encode(payload_len)?;
    let ciphertext = seal(&key, &nonce, &padded, &aad)?;
    let container = SealedContainer::new(header, ciphertext)?;
    let raw = container.marshal()?;
    let text = scatter_bytes(cover, &raw, options.carrier, &key, &nonce)?;
    let map = CostMap::new(cover, options.carrier);
    let report = HideReport {
        carrier: options.carrier,
        content_bytes: content.bytes().len(),
        container_bytes: raw.len(),
        carrier_symbols: options.carrier.symbols_for_bytes(raw.len())?,
        safe_slots: map.safe_slots(),
        compressed,
        analysis: analyse(&text, options.carrier),
    };
    Ok(HiddenMessage { text, report })
}

/// Tries verified contacts, authenticates one, and enforces its replay floor.
pub fn reveal_contact(
    text: &str,
    recipient: &IdentitySecret,
    candidates: &[ContactCandidate],
) -> Result<ContactOpened> {
    let scanned = scan(text)?;
    let ModeHeader::Contact(header) = scanned.container().header().mode() else {
        return Err(Error::ModeMismatch);
    };
    let mut replay = false;
    for (candidate_index, candidate) in candidates.iter().enumerate() {
        let Ok(key) = recipient_key(recipient, candidate.public, header) else {
            continue;
        };
        let Ok(plaintext) = open(
            &key,
            header.nonce(),
            scanned.container().payload(),
            scanned.container().aad(),
        ) else {
            continue;
        };
        let Ok(payload) = decode(&plaintext, scanned.container().header().compressed()) else {
            continue;
        };
        if payload.counter() == 0 || payload.counter() <= candidate.last_seen_counter {
            replay = true;
            continue;
        }
        return Ok(ContactOpened {
            candidate_index,
            payload,
        });
    }
    if replay {
        Err(Error::Replay)
    } else {
        Err(Error::OpenFailed)
    }
}

fn sender_key(
    sender: &IdentitySecret,
    recipient: IdentityPublic,
    ephemeral: &StaticSecret,
    ephemeral_public: [u8; 32],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let recipient_public = PublicKey::from(recipient.0);
    let ephemeral_shared = ephemeral.diffie_hellman(&recipient_public);
    let sender_secret = sender.dalek();
    let identity_shared = sender_secret.diffie_hellman(&recipient_public);
    derive_contact_key(
        ephemeral_shared.as_bytes(),
        identity_shared.as_bytes(),
        ephemeral_public,
        sender.public(),
        recipient,
        nonce,
    )
}

fn recipient_key(
    recipient: &IdentitySecret,
    sender: IdentityPublic,
    header: &ContactHeader,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let recipient_secret = recipient.dalek();
    let ephemeral_public = PublicKey::from(*header.ephemeral_public());
    let sender_public = PublicKey::from(sender.0);
    let ephemeral_shared = recipient_secret.diffie_hellman(&ephemeral_public);
    let identity_shared = recipient_secret.diffie_hellman(&sender_public);
    derive_contact_key(
        ephemeral_shared.as_bytes(),
        identity_shared.as_bytes(),
        *header.ephemeral_public(),
        sender,
        recipient.public(),
        header.nonce(),
    )
}

fn derive_contact_key(
    ephemeral_shared: &[u8; 32],
    identity_shared: &[u8; 32],
    ephemeral_public: [u8; 32],
    sender: IdentityPublic,
    recipient: IdentityPublic,
    nonce: &[u8; NONCE_BYTES],
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let zero = [0u8; 32];
    if bool::from(ephemeral_shared.ct_eq(&zero)) || bool::from(identity_shared.ct_eq(&zero)) {
        return Err(Error::KeyAgreement);
    }
    let mut input = Zeroizing::new([0u8; 64]);
    let first = input.get_mut(..32).ok_or(Error::LengthOverflow)?;
    first.copy_from_slice(ephemeral_shared);
    let second = input.get_mut(32..).ok_or(Error::LengthOverflow)?;
    second.copy_from_slice(identity_shared);
    let mut info = Vec::with_capacity(INFO_PREFIX.len() + 96);
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(&ephemeral_public);
    info.extend_from_slice(sender.as_bytes());
    info.extend_from_slice(recipient.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), input.as_slice());
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

fn fingerprint_digest(public: &IdentityPublic) -> [u8; 10] {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(public.as_bytes());
    let hash = hasher.finalize();
    let mut digest = [0u8; 10];
    if let Some(prefix) = hash.get(..digest.len()) {
        digest.copy_from_slice(prefix);
    }
    digest
}
