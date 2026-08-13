use std::io;

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    argon2id: Vec<ArgonVector>,
    xchacha20poly1305: Vec<XChaChaVector>,
    x25519: Vec<X25519Vector>,
}

#[derive(Deserialize)]
struct ArgonVector {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    password_hex: String,
    salt_hex: String,
    secret_hex: String,
    associated_data_hex: String,
    tag_hex: String,
}

#[derive(Deserialize)]
struct XChaChaVector {
    key_hex: String,
    nonce_hex: String,
    aad_hex: String,
    plaintext_hex: String,
    ciphertext_and_tag_hex: String,
}

#[derive(Deserialize)]
struct X25519Vector {
    alice_private_hex: String,
    alice_public_hex: String,
    bob_private_hex: String,
    bob_public_hex: String,
    shared_secret_hex: String,
}

#[test]
fn published_argon2id_vector() -> Result<(), Box<dyn std::error::Error>> {
    let vectors = load()?;
    for vector in vectors.argon2id {
        let associated = hex::decode(vector.associated_data_hex)?;
        let mut builder = ParamsBuilder::new();
        builder
            .m_cost(vector.memory_kib)
            .t_cost(vector.passes)
            .p_cost(vector.lanes)
            .output_len(32)
            .data(AssociatedData::new(&associated).map_err(argon_error)?);
        let params = builder.build().map_err(argon_error)?;
        let secret = hex::decode(vector.secret_hex)?;
        let argon2 = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(argon_error)?;
        let password = hex::decode(vector.password_hex)?;
        let salt = hex::decode(vector.salt_hex)?;
        let mut tag = [0u8; 32];
        argon2
            .hash_password_into(&password, &salt, &mut tag)
            .map_err(argon_error)?;
        assert_eq!(tag.as_slice(), hex::decode(vector.tag_hex)?);
    }
    Ok(())
}

#[test]
fn published_xchacha20poly1305_vector() -> Result<(), Box<dyn std::error::Error>> {
    let vectors = load()?;
    for vector in vectors.xchacha20poly1305 {
        let key: [u8; 32] = hex::decode(vector.key_hex)?
            .try_into()
            .map_err(|_| "key length")?;
        let nonce: [u8; 24] = hex::decode(vector.nonce_hex)?
            .try_into()
            .map_err(|_| "nonce length")?;
        let aad = hex::decode(vector.aad_hex)?;
        let plaintext = hex::decode(vector.plaintext_hex)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| "AEAD rejected vector")?;
        assert_eq!(sealed, hex::decode(vector.ciphertext_and_tag_hex)?);
    }
    Ok(())
}

#[cfg(feature = "contacts")]
#[test]
fn published_x25519_vector() -> Result<(), Box<dyn std::error::Error>> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let vectors = load()?;
    for vector in vectors.x25519 {
        let alice_private: [u8; 32] = hex::decode(vector.alice_private_hex)?
            .try_into()
            .map_err(|_| "Alice private length")?;
        let bob_private: [u8; 32] = hex::decode(vector.bob_private_hex)?
            .try_into()
            .map_err(|_| "Bob private length")?;
        let alice = StaticSecret::from(alice_private);
        let bob = StaticSecret::from(bob_private);
        let alice_public = PublicKey::from(&alice);
        let bob_public = PublicKey::from(&bob);
        assert_eq!(
            alice_public.as_bytes(),
            &hex::decode(vector.alice_public_hex)?[..]
        );
        assert_eq!(
            bob_public.as_bytes(),
            &hex::decode(vector.bob_public_hex)?[..]
        );
        assert_eq!(
            alice.diffie_hellman(&bob_public).as_bytes(),
            &hex::decode(vector.shared_secret_hex)?[..]
        );
    }
    Ok(())
}

fn load() -> Result<Vectors, serde_json::Error> {
    serde_json::from_str(include_str!("../../vectors/primitive-kats.json"))
}

fn argon_error(error: argon2::Error) -> io::Error {
    io::Error::other(error.to_string())
}
