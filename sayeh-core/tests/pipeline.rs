use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sayeh_core::Error;
use sayeh_core::carrier::CarrierKind;
use sayeh_core::crypto::Argon2Params;
use sayeh_core::frame::Content;
use sayeh_core::pipeline::{
    CapacityMode, PasswordOptions, capacity, hide_password_with_rng, reveal_password, scan,
};

fn test_parameters() -> Argon2Params {
    Argon2Params::new(Argon2Params::MIN_MEMORY_KIB, Argon2Params::MIN_PASSES, 1)
        .unwrap_or(Argon2Params::DEFAULT)
}

fn long_cover() -> String {
    "Meet me after work. Bring the notes, and call when you arrive. ".repeat(900)
}

#[test]
fn password_round_trip_all_carriers() -> Result<(), Error> {
    for carrier in CarrierKind::ALL {
        let mut rng = ChaCha20Rng::from_seed([carrier.id(); 32]);
        let hidden = hide_password_with_rng(
            &long_cover(),
            Content::Text("پیام محرمانه with 👨‍👩‍👧"),
            "رمز درست".as_bytes(),
            PasswordOptions {
                carrier,
                parameters: test_parameters(),
                created_at: 1_700_000_000,
            },
            &mut rng,
        )?;
        let opened = reveal_password(&hidden.text, "رمز درست".as_bytes())?;
        assert_eq!(opened.text(), Some("پیام محرمانه with 👨‍👩‍👧"));
        assert_eq!(opened.created_at(), 1_700_000_000);
        assert_eq!(scan(&hidden.text)?.carrier(), carrier);
    }
    Ok(())
}

#[test]
fn arbitrary_file_bytes_round_trip() -> Result<(), Error> {
    let bytes: Vec<u8> = (0u8..=255).collect();
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let hidden = hide_password_with_rng(
        &long_cover(),
        Content::File {
            name: "seed.bin",
            bytes: &bytes,
        },
        b"correct horse battery staple",
        PasswordOptions {
            carrier: CarrierKind::UnicodeTags,
            parameters: test_parameters(),
            created_at: 42,
        },
        &mut rng,
    )?;
    let opened = reveal_password(&hidden.text, b"correct horse battery staple")?;
    assert_eq!(opened.file_name(), Some("seed.bin"));
    assert_eq!(opened.bytes(), bytes);
    Ok(())
}

#[test]
fn wrong_password_and_tamper_are_indistinguishable() -> Result<(), Error> {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let hidden = hide_password_with_rng(
        &long_cover(),
        Content::Text("secret"),
        b"right",
        PasswordOptions {
            carrier: CarrierKind::ZeroWidth,
            parameters: test_parameters(),
            created_at: 7,
        },
        &mut rng,
    )?;
    assert_eq!(
        reveal_password(&hidden.text, b"wrong").err(),
        Some(Error::OpenFailed)
    );

    let mut characters: Vec<char> = hidden.text.chars().collect();
    if let Some(position) = characters
        .iter()
        .rposition(|ch| CarrierKind::ZeroWidth.contains(*ch))
    {
        let current = characters
            .get(position)
            .copied()
            .ok_or(Error::LengthOverflow)?;
        let replacement = if current == '\u{200b}' {
            '\u{2060}'
        } else {
            '\u{200b}'
        };
        if let Some(slot) = characters.get_mut(position) {
            *slot = replacement;
        }
    }
    let tampered: String = characters.into_iter().collect();
    assert_eq!(
        reveal_password(&tampered, b"right").err(),
        Some(Error::OpenFailed)
    );
    Ok(())
}

#[test]
fn estimator_refuses_signal_flare_covers() -> Result<(), Error> {
    let estimate = capacity(
        "two words",
        CarrierKind::ZeroWidth,
        CapacityMode::Password,
        0,
    )?;
    assert_eq!(estimate.content_bytes, 0);
    assert!(estimate.safe_slots < 10);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn round_trip_arbitrary_bytes_and_unicode_cover(
        bytes in prop::collection::vec(any::<u8>(), 0..257),
        prefix in prop::collection::vec(any::<char>().prop_filter("raw carriers are rejected at the boundary", |ch| {
            !CarrierKind::ZeroWidth.contains(*ch)
        }), 0..64),
        special in prop_oneof![
            Just("👨‍👩‍👧"),
            Just("می‌روم"),
            Just("a\u{301}"),
            Just("English فارسی"),
        ],
    ) {
        let mut cover: String = prefix.into_iter().collect();
        cover.push_str(special);
        cover.push(' ');
        cover.push_str(&long_cover());
        let mut seed = [0u8; 32];
        seed[0] = bytes.len() as u8;
        let mut rng = ChaCha20Rng::from_seed(seed);
        let hidden = hide_password_with_rng(
            &cover,
            Content::File { name: "blob.bin", bytes: &bytes },
            b"property password",
            PasswordOptions {
                carrier: CarrierKind::ZeroWidth,
                parameters: test_parameters(),
                created_at: 0,
            },
            &mut rng,
        )?;
        let opened = reveal_password(&hidden.text, b"property password")?;
        prop_assert_eq!(opened.bytes(), bytes);
    }
}
