use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sayeh_core::carrier::CarrierKind;
use sayeh_core::contact::{ContactOptions, IdentitySecret, hide_contact_with_rng};
use sayeh_core::crypto::Argon2Params;
use sayeh_core::frame::Content;
use sayeh_core::pipeline::{PasswordOptions, hide_password_with_rng, scan};
use serde_json::json;
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("vectors") => write_vectors(),
        Some(command) => bail!("unknown xtask command: {command}"),
        None => bail!("usage: cargo xtask vectors"),
    }
}

fn write_vectors() -> Result<()> {
    let cover_pattern = ". ";
    let cover_repetitions = 4_000usize;
    let cover = cover_pattern.repeat(cover_repetitions);
    let parameters = Argon2Params::new(Argon2Params::MIN_MEMORY_KIB, Argon2Params::MIN_PASSES, 1)?;

    let password_seed = [0x11u8; 32];
    let mut password_rng = ChaCha20Rng::from_seed(password_seed);
    let password_hidden = hide_password_with_rng(
        &cover,
        Content::Text("Sayeh v4 password vector — سایه"),
        b"correct horse",
        PasswordOptions {
            carrier: CarrierKind::ZeroWidth,
            parameters,
            created_at: 1_700_000_001,
        },
        &mut password_rng,
    )?;
    let password_raw = scan(&password_hidden.text)?.container().marshal()?;

    let sender_bytes = [0x31u8; 32];
    let recipient_bytes = [0x32u8; 32];
    let sender = IdentitySecret::from_bytes(sender_bytes);
    let recipient = IdentitySecret::from_bytes(recipient_bytes);
    let contact_seed = [0x22u8; 32];
    let mut contact_rng = ChaCha20Rng::from_seed(contact_seed);
    let contact_hidden = hide_contact_with_rng(
        &cover,
        Content::File {
            name: "vector.bin",
            bytes: &[0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff],
        },
        &sender,
        recipient.public(),
        ContactOptions {
            carrier: CarrierKind::UnicodeTags,
            counter: 7,
            created_at: 1_700_000_002,
        },
        &mut contact_rng,
    )?;
    let contact_raw = scan(&contact_hidden.text)?.container().marshal()?;

    let document = json!({
        "schema": 1,
        "spec_version": "1.0.0-draft.1",
        "cover": {
            "pattern": cover_pattern,
            "repetitions": cover_repetitions
        },
        "password": {
            "rng_seed_hex": hex::encode(password_seed),
            "password_utf8": "correct horse",
            "content": {
                "kind": "text",
                "text": "Sayeh v4 password vector — سایه",
                "created_at": 1_700_000_001
            },
            "argon2": {
                "memory_kib": parameters.memory_kib(),
                "passes": parameters.passes(),
                "lanes": parameters.lanes()
            },
            "carrier": "zero-width",
            "container_hex": hex::encode(password_raw),
            "carrier_scalar_offsets": carrier_offsets(&password_hidden.text, CarrierKind::ZeroWidth),
            "stego_utf8_sha256": digest(&password_hidden.text)
        },
        "contact": {
            "rng_seed_hex": hex::encode(contact_seed),
            "sender_private_hex": hex::encode(sender_bytes),
            "recipient_private_hex": hex::encode(recipient_bytes),
            "content": {
                "kind": "file",
                "name": "vector.bin",
                "bytes_hex": "00017f80feff",
                "counter": 7,
                "created_at": 1_700_000_002
            },
            "carrier": "unicode-tags",
            "container_hex": hex::encode(contact_raw),
            "carrier_scalar_offsets": carrier_offsets(&contact_hidden.text, CarrierKind::UnicodeTags),
            "stego_utf8_sha256": digest(&contact_hidden.text)
        }
    });

    let path = workspace_root().join("vectors").join("wire-v4.json");
    let bytes = serde_json::to_vec_pretty(&document)?;
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

fn carrier_offsets(text: &str, carrier: CarrierKind) -> Vec<usize> {
    text.chars()
        .enumerate()
        .filter_map(|(offset, ch)| carrier.contains(ch).then_some(offset))
        .collect()
}

fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
