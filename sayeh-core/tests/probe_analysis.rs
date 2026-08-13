use sayeh_core::carrier::{Carrier, CarrierKind};
use sayeh_core::probe;
use sayeh_core::steganalysis::analyse;

#[test]
fn probe_recommends_only_complete_surviving_alphabets() {
    let generated = probe::generate();
    assert_eq!(
        probe::analyse(&generated).recommendation,
        Some(CarrierKind::UnicodeTags)
    );

    let without_tags: String = generated
        .chars()
        .filter(|ch| !CarrierKind::UnicodeTags.contains(*ch))
        .collect();
    assert_eq!(
        probe::analyse(&without_tags).recommendation,
        Some(CarrierKind::VariationSelectors)
    );
}

#[test]
fn detector_exposes_the_contiguous_v3_failure_mode() {
    let carriers: String = CarrierKind::ZeroWidth
        .encode(b"ciphertext-like bytes with enough symbols")
        .collect();
    let contiguous = format!("a{carriers} visible cover");
    let report = analyse(&contiguous, CarrierKind::ZeroWidth);
    assert!(report.likely_detectable());
    assert_eq!(report.longest_run, carriers.chars().count());
    assert!(report.density > 1.0);
}
