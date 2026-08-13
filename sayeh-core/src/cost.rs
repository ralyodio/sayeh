use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_script::{Script, UnicodeScript};
use unicode_segmentation::UnicodeSegmentation;

use crate::carrier::CarrierKind;

/// One eligible cover gap and its contextual suspicion cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub byte_offset: usize,
    pub grapheme_index: usize,
    pub cost: u8,
}

/// Contextual embedding candidates derived from a concrete cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostMap {
    candidates: Vec<Candidate>,
    graphemes: usize,
}

impl CostMap {
    /// Builds revision 1's map without normalizing or rewriting the cover.
    pub fn new(cover: &str, carrier: CarrierKind) -> Self {
        let graphemes: Vec<(usize, &str)> = cover.grapheme_indices(true).collect();
        let mut candidates = Vec::with_capacity(graphemes.len().saturating_sub(1));

        for (index, pair) in graphemes.windows(2).enumerate() {
            let Some((_, left)) = pair.first().copied() else {
                continue;
            };
            let Some((right_offset, right)) = pair.get(1).copied() else {
                continue;
            };
            let Some(left_char) = left.chars().last() else {
                continue;
            };
            let Some(right_char) = right.chars().next() else {
                continue;
            };

            if left.contains('\u{200d}') || right.contains('\u{200d}') {
                continue;
            }
            if is_arabic_letter(left_char) && is_arabic_letter(right_char) {
                continue;
            }

            let after_punctuation = is_punctuation(left_char);
            let after_whitespace = left_char.is_whitespace();
            if matches!(
                carrier,
                CarrierKind::VariationSelectors | CarrierKind::UnicodeTags
            ) && !after_punctuation
                && !after_whitespace
            {
                continue;
            }

            let cost = if is_sentence_punctuation(left_char) {
                8
            } else if after_punctuation {
                16
            } else if after_whitespace {
                24
            } else if get_general_category(left_char) != get_general_category(right_char) {
                72
            } else if left_char.is_alphanumeric() && right_char.is_alphanumeric() {
                224
            } else {
                144
            };
            candidates.push(Candidate {
                byte_offset: right_offset,
                grapheme_index: index,
                cost,
            });
        }

        Self {
            candidates,
            graphemes: graphemes.len(),
        }
    }

    /// Finite-cost candidates in textual order.
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Number of extended grapheme clusters in the cover.
    pub const fn grapheme_count(&self) -> usize {
        self.graphemes
    }

    /// Cover-derived limit from spec section 8.
    pub fn safe_slots(&self) -> usize {
        let quality: u64 = self
            .candidates
            .iter()
            .map(|candidate| u64::from(255u8.saturating_sub(candidate.cost)))
            .sum();
        let slots = quality / (255 * 8);
        usize::try_from(slots)
            .unwrap_or(usize::MAX)
            .min(self.candidates.len())
    }
}

fn is_arabic_letter(ch: char) -> bool {
    ch.is_alphabetic() && ch.script() == Script::Arabic
}

fn is_sentence_punctuation(ch: char) -> bool {
    matches!(
        ch,
        '.' | '!' | '?' | '\u{061f}' | '\u{06d4}' | '\u{3002}' | '\u{ff01}' | '\u{ff1f}'
    )
}

fn is_punctuation(ch: char) -> bool {
    matches!(
        get_general_category(ch),
        GeneralCategory::ConnectorPunctuation
            | GeneralCategory::DashPunctuation
            | GeneralCategory::OpenPunctuation
            | GeneralCategory::ClosePunctuation
            | GeneralCategory::InitialPunctuation
            | GeneralCategory::FinalPunctuation
            | GeneralCategory::OtherPunctuation
    )
}
