use std::collections::{BTreeMap, BTreeSet};

use crate::carrier::{Carrier, CarrierKind};

/// Survival count for one candidate scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarSurvival {
    pub scalar: char,
    pub survived: u8,
}

/// Result of comparing a pasted probe with its visible markers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub scalars: Vec<ScalarSurvival>,
    pub recommendation: Option<CarrierKind>,
}

/// Produces the visible, line-oriented transport calibration message.
pub fn generate() -> String {
    let mut unique = BTreeSet::new();
    for carrier in CarrierKind::ALL {
        unique.extend(carrier.alphabet().iter().copied());
    }

    let mut output = String::from("SAYEH-PROBE/1\n");
    for (index, scalar) in unique.into_iter().enumerate() {
        output.push_str(&format!(
            "{index:04}|U+{:04X}|A{scalar}Z|A{scalar}Z|A{scalar}Z\n",
            scalar as u32
        ));
    }
    output
}

/// Measures exact scalar survival and recommends a fully surviving alphabet.
pub fn analyse(pasted: &str) -> ProbeReport {
    let mut measured = BTreeMap::<char, u8>::new();
    for line in pasted.lines() {
        let mut fields = line.split('|');
        let Some(_index) = fields.next() else {
            continue;
        };
        let Some(codepoint) = fields.next() else {
            continue;
        };
        let Some(hex) = codepoint.strip_prefix("U+") else {
            continue;
        };
        let Ok(value) = u32::from_str_radix(hex, 16) else {
            continue;
        };
        let Some(scalar) = char::from_u32(value) else {
            continue;
        };
        let marker = format!("A{scalar}Z");
        let survived = fields
            .take(3)
            .filter(|field| *field == marker)
            .count()
            .min(3) as u8;
        measured.insert(scalar, survived);
    }

    let mut expected = BTreeSet::new();
    for carrier in CarrierKind::ALL {
        expected.extend(carrier.alphabet().iter().copied());
    }
    let scalars: Vec<ScalarSurvival> = expected
        .into_iter()
        .map(|scalar| ScalarSurvival {
            scalar,
            survived: measured.get(&scalar).copied().unwrap_or(0),
        })
        .collect();

    let recommendation = [
        CarrierKind::UnicodeTags,
        CarrierKind::VariationSelectors,
        CarrierKind::ZeroWidth,
        CarrierKind::ZeroWidthCompat,
    ]
    .into_iter()
    .find(|carrier| {
        carrier
            .alphabet()
            .iter()
            .all(|scalar| measured.get(scalar).is_some_and(|survived| *survived == 3))
    });

    ProbeReport {
        scalars,
        recommendation,
    }
}
