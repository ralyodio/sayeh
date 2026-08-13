#![cfg(feature = "contacts")]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sayeh_core::Error;
use sayeh_core::crypto::Argon2Params;
use sayeh_core::vault::{open_vault, seal_vault_with_rng};

fn parameters() -> Result<Argon2Params, Error> {
    Argon2Params::new(Argon2Params::MIN_MEMORY_KIB, Argon2Params::MIN_PASSES, 1)
}

#[test]
fn vault_round_trip_and_uniform_failure() -> Result<(), Error> {
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let sealed = seal_vault_with_rng(
        b"serialized identity and contacts",
        b"vault password",
        parameters()?,
        &mut rng,
    )?;
    assert_eq!(
        open_vault(&sealed, b"vault password")?.as_slice(),
        b"serialized identity and contacts"
    );
    assert_eq!(
        open_vault(&sealed, b"wrong password").err(),
        Some(Error::OpenFailed)
    );

    let mut tampered = sealed;
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    assert_eq!(
        open_vault(&tampered, b"vault password").err(),
        Some(Error::OpenFailed)
    );
    Ok(())
}
