use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::carrier::{Carrier, CarrierKind};
use crate::cost::{Candidate, CostMap};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy)]
struct RankedCandidate {
    candidate: Candidate,
    adjusted_cost: u16,
    tie_breaker: u64,
}

/// Derives the placement key independently from the AEAD key.
pub fn derive_seed(
    key: &[u8; 32],
    nonce: &[u8; 24],
    cover: &str,
    carrier: CarrierKind,
) -> Result<Zeroizing<[u8; 32]>> {
    let cover_hash = Sha256::digest(cover.as_bytes());
    let mut info = Vec::with_capacity(22 + cover_hash.len());
    info.extend_from_slice(b"sayeh/v4/embed/rev1");
    info.push(carrier.id());
    info.extend_from_slice(&cover_hash);

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), key);
    let mut seed = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, seed.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(seed)
}

/// Inserts a carrier stream into keyed low-cost cover gaps.
pub fn scatter(
    cover: &str,
    symbols: &[char],
    carrier: CarrierKind,
    seed: &Zeroizing<[u8; 32]>,
) -> Result<String> {
    if cover.chars().any(|ch| carrier.contains(ch)) {
        return Err(Error::CoverContainsCarrier {
            carrier: carrier.name(),
        });
    }

    let map = CostMap::new(cover, carrier);
    let mut rng = ChaCha20Rng::from_seed(**seed);
    let mut ranked: Vec<RankedCandidate> = map
        .candidates()
        .iter()
        .map(|candidate| RankedCandidate {
            candidate: *candidate,
            adjusted_cost: u16::from(candidate.cost) + (rng.next_u32() % 32) as u16,
            tie_breaker: rng.next_u64(),
        })
        .collect();
    ranked.sort_by_key(|entry| (entry.adjusted_cost, entry.tie_breaker));

    let position_count = symbols.len().min(ranked.len());
    let mut selected = Vec::with_capacity(position_count.max(usize::from(!symbols.is_empty())));
    for entry in &ranked {
        if selected.len() == position_count {
            break;
        }
        if selected.iter().all(|chosen: &Candidate| {
            chosen
                .grapheme_index
                .abs_diff(entry.candidate.grapheme_index)
                > 1
        }) {
            selected.push(entry.candidate);
        }
    }
    if selected.len() < position_count {
        for entry in &ranked {
            if selected.len() == position_count {
                break;
            }
            if !selected
                .iter()
                .any(|chosen| chosen.byte_offset == entry.candidate.byte_offset)
            {
                selected.push(entry.candidate);
            }
        }
    }
    if selected.len() != position_count {
        return Err(Error::LengthOverflow);
    }
    if selected.is_empty() && !symbols.is_empty() {
        selected.push(Candidate {
            byte_offset: 0,
            grapheme_index: 0,
            cost: u8::MAX,
        });
    }

    selected.sort_by_key(|candidate| candidate.byte_offset);
    let mut run_lengths = vec![0usize; selected.len()];
    if !selected.is_empty() {
        let base = symbols.len() / selected.len();
        run_lengths.fill(base);
        let remainder = symbols.len() % selected.len();
        let mut allocation_order = (0..selected.len())
            .map(|index| (rng.next_u64(), index))
            .collect::<Vec<_>>();
        allocation_order.sort_by_key(|entry| *entry);
        for (_, index) in allocation_order.into_iter().take(remainder) {
            let run = run_lengths.get_mut(index).ok_or(Error::LengthOverflow)?;
            *run = run.checked_add(1).ok_or(Error::LengthOverflow)?;
        }
    }

    let added_bytes = symbols
        .iter()
        .try_fold(0usize, |total, symbol| total.checked_add(symbol.len_utf8()))
        .ok_or(Error::LengthOverflow)?;
    let capacity = cover
        .len()
        .checked_add(added_bytes)
        .ok_or(Error::LengthOverflow)?;
    let mut output = String::with_capacity(capacity);
    let mut cursor = 0usize;
    let mut symbol_cursor = 0usize;

    for (candidate, run_length) in selected.iter().zip(run_lengths) {
        let part = cover
            .get(cursor..candidate.byte_offset)
            .ok_or(Error::LengthOverflow)?;
        output.push_str(part);
        let symbol_end = symbol_cursor
            .checked_add(run_length)
            .ok_or(Error::LengthOverflow)?;
        let run = symbols
            .get(symbol_cursor..symbol_end)
            .ok_or(Error::LengthOverflow)?;
        output.extend(run);
        symbol_cursor = symbol_end;
        cursor = candidate.byte_offset;
    }
    if symbol_cursor != symbols.len() {
        return Err(Error::LengthOverflow);
    }
    output.push_str(cover.get(cursor..).ok_or(Error::LengthOverflow)?);
    Ok(output)
}

/// Encodes and scatters a complete container.
pub fn scatter_bytes(
    cover: &str,
    data: &[u8],
    carrier: CarrierKind,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<String> {
    let symbols: Vec<char> = carrier.encode(data).collect();
    let seed = derive_seed(key, nonce, cover, carrier)?;
    scatter(cover, &symbols, carrier, &seed)
}
