use std::io;

use proptest::prelude::*;
use sayeh_core::carrier::{Carrier, CarrierKind, looks_like_v3, strip_aggressive, strip_safe};
use sayeh_core::cost::CostMap;
use sayeh_core::embed::scatter;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct CarrierVectors {
    input_hex: String,
    vectors: Vec<CarrierVector>,
}

#[derive(Deserialize)]
struct CarrierVector {
    carrier_id: u8,
    bits_per_symbol: u8,
    codepoints: Vec<String>,
}

#[test]
fn carrier_vectors_are_data_driven() -> Result<(), Box<dyn std::error::Error>> {
    let vectors: CarrierVectors =
        serde_json::from_str(include_str!("../../vectors/carrier-vectors.json"))?;
    let input = hex::decode(vectors.input_hex)?;
    for vector in vectors.vectors {
        let carrier = CarrierKind::from_id(vector.carrier_id)?;
        assert_eq!(carrier.bits_per_symbol(), vector.bits_per_symbol);
        let expected: Vec<char> = vector
            .codepoints
            .iter()
            .map(|value| parse_codepoint(value))
            .collect::<Result<_, _>>()?;
        let encoded: Vec<char> = carrier.encode(&input).collect();
        assert_eq!(encoded, expected, "{}", carrier.name());
        let as_text: String = encoded.into_iter().collect();
        assert_eq!(carrier.decode(&as_text), input, "{}", carrier.name());
    }
    Ok(())
}

#[test]
fn safe_cleaning_preserves_persian_and_emoji_joiners() {
    let cover = "می‌روم با 👨‍👩‍👧 و 🕵️‍♂️";
    let dirty = format!("{cover}\u{200b}\u{2060}\u{2062}\u{2064}");
    assert_eq!(strip_safe(&dirty, None), cover);
    assert!(strip_aggressive(cover).chars().count() < cover.chars().count());
    assert!(
        !CarrierKind::ALL
            .iter()
            .any(|carrier| { carrier.contains('\u{200c}') || carrier.contains('\u{200d}') })
    );
}

#[test]
fn cost_map_forbids_arabic_letter_boundaries() {
    assert!(
        CostMap::new("کتابها", CarrierKind::ZeroWidth)
            .candidates()
            .is_empty()
    );
    assert!(
        CostMap::new("👨‍👩‍👧", CarrierKind::ZeroWidth)
            .candidates()
            .is_empty()
    );
}

#[test]
fn scattered_embedding_round_trips_cover_and_has_no_runs() -> Result<(), sayeh_core::Error> {
    let cover = "Please bring the notes after work. ".repeat(600);
    let symbols: Vec<char> = CarrierKind::ZeroWidth
        .encode(b"small carrier stream")
        .collect();
    let stego = scatter(
        &cover,
        &symbols,
        CarrierKind::ZeroWidth,
        &Zeroizing::new([7u8; 32]),
    )?;
    assert_eq!(strip_safe(&stego, Some(CarrierKind::ZeroWidth)), cover);
    let longest = stego
        .chars()
        .fold((0usize, 0usize), |(run, longest), ch| {
            if CarrierKind::ZeroWidth.contains(ch) {
                let next = run + 1;
                (next, longest.max(next))
            } else {
                (0, longest)
            }
        })
        .1;
    assert_eq!(longest, 1);
    Ok(())
}

#[test]
fn legacy_detector_recognizes_v3_without_cleaning_zwj() {
    let alphabet = ['\u{200b}', '\u{200d}', '\u{2060}', '\u{2064}'];
    let mut encoded = String::new();
    for byte in b"ZWS3" {
        for shift in [6u8, 4, 2, 0] {
            let index = usize::from((byte >> shift) & 3);
            if let Some(symbol) = alphabet.get(index) {
                encoded.push(*symbol);
            }
        }
    }
    let text = format!("👨‍👩‍👧{encoded} cover");
    assert!(looks_like_v3(&text));
    assert!(strip_safe(&text, None).contains('\u{200d}'));
}

proptest! {
    #[test]
    fn every_carrier_round_trips_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        for carrier in CarrierKind::ALL {
            let text: String = carrier.encode(&data).collect();
            prop_assert_eq!(carrier.decode(&text), data.clone(), "{}", carrier.name());
        }
    }
}

fn parse_codepoint(value: &str) -> Result<char, io::Error> {
    let hex = value
        .strip_prefix("U+")
        .ok_or_else(|| io::Error::other("code point lacks U+ prefix"))?;
    let scalar =
        u32::from_str_radix(hex, 16).map_err(|error| io::Error::other(error.to_string()))?;
    char::from_u32(scalar).ok_or_else(|| io::Error::other("invalid Unicode scalar"))
}
