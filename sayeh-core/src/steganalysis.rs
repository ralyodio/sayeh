use crate::carrier::{Carrier, CarrierKind};

/// Statistics used by the bundled detector.
#[derive(Debug, Clone, PartialEq)]
pub struct Analysis {
    pub carrier: CarrierKind,
    pub symbols: usize,
    pub visible_scalars: usize,
    pub density: f64,
    pub chi_square: f64,
    pub longest_run: usize,
    pub mean_gap: f64,
    pub gap_coefficient_of_variation: f64,
    pub positional_entropy: f64,
    pub suspicion_score: u8,
}

impl Analysis {
    /// A measured analysis threshold, not a security proof or an encode limit.
    pub const fn likely_detectable(&self) -> bool {
        self.suspicion_score >= 50
    }
}

/// Runs carrier density, symbol distribution, clustering, and position tests.
pub fn analyse(text: &str, carrier: CarrierKind) -> Analysis {
    let alphabet = carrier.alphabet();
    let mut counts = vec![0usize; alphabet.len()];
    let mut positions = Vec::new();
    let mut ordinal = 0usize;
    let mut visible = 0usize;
    let mut run = 0usize;
    let mut longest_run = 0usize;

    for ch in text.chars() {
        if let Some(index) = alphabet.iter().position(|candidate| *candidate == ch) {
            if let Some(count) = counts.get_mut(index) {
                *count = count.saturating_add(1);
            }
            positions.push(ordinal);
            run = run.saturating_add(1);
            longest_run = longest_run.max(run);
        } else {
            visible = visible.saturating_add(1);
            run = 0;
        }
        ordinal = ordinal.saturating_add(1);
    }

    let symbols = positions.len();
    let density = if visible == 0 {
        symbols as f64
    } else {
        symbols as f64 / visible as f64
    };
    let chi_square = chi_square(&counts, symbols);
    let (mean_gap, gap_cv) = gap_stats(&positions);
    let positional_entropy = entropy(&positions, ordinal);
    let suspicion_score = score(
        symbols,
        density,
        chi_square,
        longest_run,
        positional_entropy,
        alphabet.len(),
    );

    Analysis {
        carrier,
        symbols,
        visible_scalars: visible,
        density,
        chi_square,
        longest_run,
        mean_gap,
        gap_coefficient_of_variation: gap_cv,
        positional_entropy,
        suspicion_score,
    }
}

fn chi_square(counts: &[usize], total: usize) -> f64 {
    if total == 0 || counts.is_empty() {
        return 0.0;
    }
    let expected = total as f64 / counts.len() as f64;
    counts
        .iter()
        .map(|count| {
            let delta = *count as f64 - expected;
            delta * delta / expected
        })
        .sum()
}

fn gap_stats(positions: &[usize]) -> (f64, f64) {
    let gaps: Vec<f64> = positions
        .windows(2)
        .filter_map(|pair| pair.get(1).zip(pair.first()))
        .map(|(right, left)| right.saturating_sub(*left) as f64)
        .collect();
    if gaps.is_empty() {
        return (0.0, 0.0);
    }
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean == 0.0 {
        return (mean, 0.0);
    }
    let variance = gaps
        .iter()
        .map(|gap| {
            let delta = *gap - mean;
            delta * delta
        })
        .sum::<f64>()
        / gaps.len() as f64;
    (mean, variance.sqrt() / mean)
}

fn entropy(positions: &[usize], total: usize) -> f64 {
    if positions.is_empty() || total == 0 {
        return 0.0;
    }
    let mut bins = [0usize; 8];
    for position in positions {
        let index = position.saturating_mul(bins.len()) / total;
        let index = index.min(bins.len() - 1);
        if let Some(bin) = bins.get_mut(index) {
            *bin = bin.saturating_add(1);
        }
    }
    let count = positions.len() as f64;
    let raw = bins
        .iter()
        .filter(|bin| **bin > 0)
        .map(|bin| {
            let probability = *bin as f64 / count;
            -probability * probability.ln()
        })
        .sum::<f64>();
    raw / (bins.len() as f64).ln()
}

fn score(
    symbols: usize,
    density: f64,
    chi_square: f64,
    longest_run: usize,
    entropy: f64,
    alphabet_len: usize,
) -> u8 {
    if symbols == 0 {
        return 0;
    }
    let mut value = 25u8;
    value = value.saturating_add(if density >= 0.02 {
        45
    } else if density >= 0.005 {
        30
    } else {
        15
    });
    if symbols >= alphabet_len.saturating_mul(4) && chi_square <= alphabet_len as f64 {
        value = value.saturating_add(15);
    }
    if longest_run > 2 {
        value = value.saturating_add(10);
    }
    if symbols >= 8 && entropy < 0.65 {
        value = value.saturating_add(10);
    }
    value.min(100)
}

/// Fraction of samples crossing the detector threshold.
pub fn detection_rate<'a>(samples: impl IntoIterator<Item = &'a str>, carrier: CarrierKind) -> f64 {
    let mut total = 0usize;
    let mut detected = 0usize;
    for sample in samples {
        total = total.saturating_add(1);
        if analyse(sample, carrier).likely_detectable() {
            detected = detected.saturating_add(1);
        }
    }
    if total == 0 {
        0.0
    } else {
        detected as f64 / total as f64
    }
}
