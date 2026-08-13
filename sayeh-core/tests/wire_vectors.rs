#![cfg(feature = "contacts")]

use std::io;
use std::str::FromStr;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sayeh_core::carrier::CarrierKind;
use sayeh_core::contact::{ContactOptions, IdentitySecret, hide_contact_with_rng};
use sayeh_core::crypto::Argon2Params;
use sayeh_core::frame::Content;
use sayeh_core::pipeline::{PasswordOptions, hide_password_with_rng, scan};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct WireVectors {
    cover: Cover,
    password: PasswordVector,
    contact: ContactVector,
}

#[derive(Deserialize)]
struct Cover {
    pattern: String,
    repetitions: usize,
}

#[derive(Deserialize)]
struct PasswordVector {
    rng_seed_hex: String,
    password_utf8: String,
    content: TextContent,
    argon2: Argon,
    carrier: String,
    container_hex: String,
    carrier_scalar_offsets: Vec<usize>,
    stego_utf8_sha256: String,
}

#[derive(Deserialize)]
struct TextContent {
    text: String,
    created_at: u64,
}

#[derive(Deserialize)]
struct Argon {
    memory_kib: u32,
    passes: u32,
    lanes: u8,
}

#[derive(Deserialize)]
struct ContactVector {
    rng_seed_hex: String,
    sender_private_hex: String,
    recipient_private_hex: String,
    content: FileContent,
    carrier: String,
    container_hex: String,
    carrier_scalar_offsets: Vec<usize>,
    stego_utf8_sha256: String,
}

#[derive(Deserialize)]
struct FileContent {
    name: String,
    bytes_hex: String,
    counter: u64,
    created_at: u64,
}

#[test]
fn deterministic_wire_vectors_match_data_file() -> Result<(), Box<dyn std::error::Error>> {
    let vectors: WireVectors = serde_json::from_str(include_str!("../../vectors/wire-v4.json"))?;
    let cover = vectors.cover.pattern.repeat(vectors.cover.repetitions);

    let carrier = CarrierKind::from_str(&vectors.password.carrier)?;
    let seed = array32(&vectors.password.rng_seed_hex)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let hidden = hide_password_with_rng(
        &cover,
        Content::Text(&vectors.password.content.text),
        vectors.password.password_utf8.as_bytes(),
        PasswordOptions {
            carrier,
            parameters: Argon2Params::new(
                vectors.password.argon2.memory_kib,
                vectors.password.argon2.passes,
                vectors.password.argon2.lanes,
            )?,
            created_at: vectors.password.content.created_at,
        },
        &mut rng,
    )?;
    assert_vector(
        &hidden.text,
        carrier,
        &vectors.password.container_hex,
        &vectors.password.carrier_scalar_offsets,
        &vectors.password.stego_utf8_sha256,
    )?;

    let contact_carrier = CarrierKind::from_str(&vectors.contact.carrier)?;
    let sender = IdentitySecret::from_bytes(array32(&vectors.contact.sender_private_hex)?);
    let recipient = IdentitySecret::from_bytes(array32(&vectors.contact.recipient_private_hex)?);
    let file = hex::decode(&vectors.contact.content.bytes_hex)?;
    let mut contact_rng = ChaCha20Rng::from_seed(array32(&vectors.contact.rng_seed_hex)?);
    let contact_hidden = hide_contact_with_rng(
        &cover,
        Content::File {
            name: &vectors.contact.content.name,
            bytes: &file,
        },
        &sender,
        recipient.public(),
        ContactOptions {
            carrier: contact_carrier,
            counter: vectors.contact.content.counter,
            created_at: vectors.contact.content.created_at,
        },
        &mut contact_rng,
    )?;
    assert_vector(
        &contact_hidden.text,
        contact_carrier,
        &vectors.contact.container_hex,
        &vectors.contact.carrier_scalar_offsets,
        &vectors.contact.stego_utf8_sha256,
    )?;
    Ok(())
}

fn assert_vector(
    text: &str,
    carrier: CarrierKind,
    container_hex: &str,
    expected_offsets: &[usize],
    expected_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = scan(text)?.container().marshal()?;
    assert_eq!(hex::encode(raw), container_hex);
    let offsets: Vec<usize> = text
        .chars()
        .enumerate()
        .filter_map(|(offset, ch)| carrier.contains(ch).then_some(offset))
        .collect();
    assert_eq!(offsets, expected_offsets);
    assert_eq!(hex::encode(Sha256::digest(text.as_bytes())), expected_hash);
    Ok(())
}

fn array32(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| io::Error::other("expected 32 bytes").into())
}
