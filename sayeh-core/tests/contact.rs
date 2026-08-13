#![cfg(feature = "contacts")]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sayeh_core::Error;
use sayeh_core::carrier::CarrierKind;
use sayeh_core::contact::{
    ContactCandidate, ContactOptions, IdentitySecret, fingerprint, hide_contact_with_rng,
    reveal_contact,
};
use sayeh_core::frame::Content;

fn long_cover() -> String {
    "I will send the ordinary notes after lunch, then call you. ".repeat(900)
}

#[test]
fn contact_mode_authenticates_sender_and_rejects_replay() -> Result<(), Error> {
    let sender = IdentitySecret::from_bytes([1u8; 32]);
    let recipient = IdentitySecret::from_bytes([2u8; 32]);
    let stranger = IdentitySecret::from_bytes([3u8; 32]);
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let hidden = hide_contact_with_rng(
        &long_cover(),
        Content::Text("contact secret"),
        &sender,
        recipient.public(),
        ContactOptions {
            carrier: CarrierKind::ZeroWidth,
            counter: 17,
            created_at: 99,
        },
        &mut rng,
    )?;
    let candidates = [
        ContactCandidate {
            public: stranger.public(),
            last_seen_counter: 0,
        },
        ContactCandidate {
            public: sender.public(),
            last_seen_counter: 16,
        },
    ];
    let opened = reveal_contact(&hidden.text, &recipient, &candidates)?;
    assert_eq!(opened.candidate_index, 1);
    assert_eq!(opened.payload.text(), Some("contact secret"));
    assert_eq!(opened.payload.counter(), 17);

    let replay_candidates = [ContactCandidate {
        public: sender.public(),
        last_seen_counter: 17,
    }];
    assert_eq!(
        reveal_contact(&hidden.text, &recipient, &replay_candidates).err(),
        Some(Error::Replay)
    );
    Ok(())
}

#[test]
fn fingerprint_has_human_and_full_key_forms() {
    let identity = IdentitySecret::from_bytes([42u8; 32]);
    let fingerprint = fingerprint(&identity.public());
    assert_eq!(fingerprint.numeric.split_whitespace().count(), 5);
    assert_eq!(fingerprint.words.split_whitespace().count(), 8);
    assert!(fingerprint.qr_payload.starts_with("sayeh:x25519:"));
    assert!(fingerprint.matches(&identity.public()));
    assert!(!fingerprint.matches(&IdentitySecret::from_bytes([43u8; 32]).public()));
}
