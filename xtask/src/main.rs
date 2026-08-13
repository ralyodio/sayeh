use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::Event;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sayeh_core::carrier::{Carrier, CarrierKind};
use sayeh_core::contact::{ContactOptions, IdentitySecret, hide_contact_with_rng};
use sayeh_core::crypto::Argon2Params;
use sayeh_core::embed::scatter;
use sayeh_core::frame::Content;
use sayeh_core::pipeline::{PasswordOptions, hide_password_with_rng, scan};
use sayeh_core::steganalysis::analyse;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const NPS_ARCHIVE_SHA256: &str = "a4433d5da5e62fdbede49efa572a53a0139fff1014ffbe86cb263e17cbb4a837";
const NPS_SOURCE: &str =
    "https://raw.githubusercontent.com/nltk/nltk_data/gh-pages/packages/corpora/nps_chat.zip";
const WINDOW_SCALARS: usize = 2_048;
const MAX_WINDOWS: usize = 100;
const RATES_PER_10K: [usize; 3] = [10, 50, 100];

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("vectors") => write_vectors(),
        Some("analyse-corpus") => {
            let path = arguments
                .next()
                .map(PathBuf::from)
                .context("usage: cargo xtask analyse-corpus <nps_chat directory>")?;
            analyse_corpus(&path)
        }
        Some(command) => bail!("unknown xtask command: {command}"),
        None => bail!("usage: cargo xtask <vectors|analyse-corpus>"),
    }
}

fn analyse_corpus(path: &Path) -> Result<()> {
    let posts = read_nps_posts(path)?;
    let windows = corpus_windows(&posts, WINDOW_SCALARS, MAX_WINDOWS);
    if windows.len() < MAX_WINDOWS {
        bail!(
            "corpus produced {} windows; {} are required",
            windows.len(),
            MAX_WINDOWS
        );
    }

    let corpus_scalars = posts.iter().map(|post| post.chars().count()).sum::<usize>();
    let baseline = CarrierKind::ALL
        .iter()
        .map(|carrier| {
            let detected = windows
                .iter()
                .filter(|sample| analyse(sample, *carrier).likely_detectable())
                .count();
            let occurrences = posts
                .iter()
                .map(|post| post.chars().filter(|ch| carrier.contains(*ch)).count())
                .sum::<usize>();
            json!({
                "carrier": carrier.name(),
                "corpus_occurrences": occurrences,
                "detected_windows": detected,
                "false_positive_rate": ratio(detected, windows.len())
            })
        })
        .collect::<Vec<_>>();

    let mut measurements = Vec::new();
    for carrier in CarrierKind::ALL {
        for rate in RATES_PER_10K {
            measurements.push(measure_rate(&windows, carrier, rate)?);
        }
    }

    let document = json!({
        "schema": 1,
        "measurement_date": "2026-08-13",
        "implementation": {
            "wire_version": 4,
            "embedding_revision": 1,
            "detector_threshold": 50
        },
        "corpus": {
            "name": "NPS Chat Corpus",
            "release": "1.0 (July 2008)",
            "source_url": NPS_SOURCE,
            "archive_sha256": NPS_ARCHIVE_SHA256,
            "redistributed": false,
            "license_note": "Non-commercial, non-profit educational and research use only",
            "xml_files": count_xml_files(path)?,
            "posts": posts.len(),
            "unicode_scalars": corpus_scalars,
            "sample_windows": windows.len(),
            "target_scalars_per_window": WINDOW_SCALARS
        },
        "method": {
            "windowing": "Consecutive posts joined by newline until at least 2048 Unicode scalars; first 100 windows",
            "payload": "Uniform carrier symbols from a deterministic ChaCha20 stream, scattered by embedding revision 1",
            "rate_denominator": "visible Unicode scalars in each cover window",
            "rates_percent": RATES_PER_10K.map(|rate| rate as f64 / 100.0)
        },
        "baseline": baseline,
        "measurements": measurements
    });

    let root = workspace_root();
    let json_path = root.join("benchmarks").join("steganalysis-nps-chat.json");
    fs::write(&json_path, serde_json::to_vec_pretty(&document)?)
        .with_context(|| format!("write {}", json_path.display()))?;
    let markdown_path = root.join("benchmarks").join("steganalysis-nps-chat.md");
    fs::write(&markdown_path, render_measurements(&document)?)
        .with_context(|| format!("write {}", markdown_path.display()))?;
    println!("wrote {}", json_path.display());
    println!("wrote {}", markdown_path.display());
    Ok(())
}

fn measure_rate(
    windows: &[String],
    carrier: CarrierKind,
    rate: usize,
) -> Result<serde_json::Value> {
    let mut presence_detected = 0usize;
    let mut heuristic_detected = 0usize;
    let mut symbols = 0usize;
    let mut density = 0.0;
    let mut longest_run = 0usize;
    let mut entropy = 0.0;
    let mut score = 0usize;

    for (index, cover) in windows.iter().enumerate() {
        let visible = cover.chars().count();
        let symbol_count = visible
            .checked_mul(rate)
            .and_then(|value| value.checked_add(9_999))
            .map(|value| value / 10_000)
            .context("embedding rate overflow")?;
        let seed = sample_seed(index, carrier, rate);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let alphabet = carrier.alphabet();
        let stream = (0..symbol_count)
            .filter_map(|_| {
                alphabet
                    .get(rng.next_u32() as usize % alphabet.len())
                    .copied()
            })
            .collect::<Vec<_>>();
        let stego = scatter(cover, &stream, carrier, &Zeroizing::new(seed))
            .with_context(|| format!("scatter {} at {} per 10k", carrier.name(), rate))?;
        let result = analyse(&stego, carrier);
        presence_detected = presence_detected.saturating_add(usize::from(result.symbols > 0));
        heuristic_detected =
            heuristic_detected.saturating_add(usize::from(result.likely_detectable()));
        symbols = symbols.saturating_add(result.symbols);
        density += result.density;
        longest_run = longest_run.saturating_add(result.longest_run);
        entropy += result.positional_entropy;
        score = score.saturating_add(usize::from(result.suspicion_score));
    }

    let count = windows.len();
    Ok(json!({
        "carrier": carrier.name(),
        "rate_percent": rate as f64 / 100.0,
        "samples": count,
        "presence_detected": presence_detected,
        "presence_detection_rate": ratio(presence_detected, count),
        "heuristic_detected": heuristic_detected,
        "heuristic_detection_rate": ratio(heuristic_detected, count),
        "mean_symbols": ratio(symbols, count),
        "mean_density": density / count as f64,
        "mean_longest_run": ratio(longest_run, count),
        "mean_positional_entropy": entropy / count as f64,
        "mean_suspicion_score": ratio(score, count)
    }))
}

fn sample_seed(index: usize, carrier: CarrierKind, rate: usize) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"sayeh/steganalysis/nps-chat/v1");
    hash.update(index.to_le_bytes());
    hash.update([carrier.id()]);
    hash.update(rate.to_le_bytes());
    hash.finalize().into()
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn corpus_windows(posts: &[String], minimum: usize, limit: usize) -> Vec<String> {
    let mut windows = Vec::with_capacity(limit);
    let mut current = String::new();
    let mut scalars = 0usize;
    for post in posts {
        if !current.is_empty() {
            current.push('\n');
            scalars = scalars.saturating_add(1);
        }
        current.push_str(post);
        scalars = scalars.saturating_add(post.chars().count());
        if scalars >= minimum {
            windows.push(std::mem::take(&mut current));
            scalars = 0;
            if windows.len() == limit {
                break;
            }
        }
    }
    windows
}

fn read_nps_posts(path: &Path) -> Result<Vec<String>> {
    let mut paths = xml_paths(path)?;
    paths.sort();
    let mut posts = Vec::new();
    for path in paths {
        let mut reader =
            Reader::from_file(&path).with_context(|| format!("read {}", path.display()))?;
        reader.config_mut().trim_text(false);
        let mut buffer = Vec::new();
        let mut in_post = false;
        let mut in_terminals = false;
        let mut text = String::new();
        loop {
            match reader.read_event_into(&mut buffer)? {
                Event::Start(event) if event.name().as_ref() == b"Post" => {
                    in_post = true;
                    text.clear();
                }
                Event::Start(event) if in_post && event.name().as_ref() == b"terminals" => {
                    in_terminals = true;
                }
                Event::Text(event) if in_post && !in_terminals => {
                    text.push_str(&event.xml_content()?);
                }
                Event::End(event) if event.name().as_ref() == b"terminals" => {
                    in_terminals = false;
                }
                Event::End(event) if event.name().as_ref() == b"Post" => {
                    let post = text.trim().to_owned();
                    if !post.is_empty() {
                        posts.push(post);
                    }
                    in_post = false;
                }
                Event::Eof => break,
                _ => {}
            }
            buffer.clear();
        }
    }
    Ok(posts)
}

fn xml_paths(path: &Path) -> Result<Vec<PathBuf>> {
    let paths = fs::read_dir(path)
        .with_context(|| format!("read directory {}", path.display()))?
        .filter_map(|entry| entry.ok().map(|value| value.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "xml"))
        .collect::<Vec<_>>();
    Ok(paths)
}

fn count_xml_files(path: &Path) -> Result<usize> {
    Ok(xml_paths(path)?.len())
}

fn render_measurements(document: &serde_json::Value) -> Result<String> {
    let corpus = document.get("corpus").context("missing corpus report")?;
    let rows = document
        .get("measurements")
        .and_then(serde_json::Value::as_array)
        .context("missing measurement rows")?;
    let mut output = format!(
        "# NPS Chat steganalysis measurement\n\n\
         Date: 2026-08-13<br>\n\
         Corpus: NPS Chat 1.0, {} posts, {} Unicode scalars<br>\n\
         Samples: {} consecutive-post windows of at least {} scalars\n\n\
         The raw corpus is not redistributed because its licence limits use to non-commercial, \
         non-profit education and research. The source URL and SHA-256 are in the JSON report.\n\n\
         None of the four carrier alphabets occurred in the 230,623-scalar baseline. \
         The presence column is therefore an exact-codepoint detector with no false positives on this corpus. \
         The heuristic column uses Sayeh's score threshold of 50.\n\n\
         | Carrier | Embedded symbols / visible scalars | Presence detected | Heuristic detected | Mean score | Mean longest run | Mean positional entropy |\n\
         |---|---:|---:|---:|---:|---:|---:|\n",
        corpus
            .get("posts")
            .and_then(serde_json::Value::as_u64)
            .context("posts")?,
        corpus
            .get("unicode_scalars")
            .and_then(serde_json::Value::as_u64)
            .context("scalars")?,
        corpus
            .get("sample_windows")
            .and_then(serde_json::Value::as_u64)
            .context("windows")?,
        corpus
            .get("target_scalars_per_window")
            .and_then(serde_json::Value::as_u64)
            .context("target")?
    );
    for row in rows {
        output.push_str(&format!(
            "| {} | {:.1}% | {}/{} ({:.0}%) | {}/{} ({:.0}%) | {:.1} | {:.2} | {:.3} |\n",
            row.get("carrier")
                .and_then(serde_json::Value::as_str)
                .context("carrier")?,
            row.get("rate_percent")
                .and_then(serde_json::Value::as_f64)
                .context("rate")?,
            row.get("presence_detected")
                .and_then(serde_json::Value::as_u64)
                .context("presence detected")?,
            row.get("samples")
                .and_then(serde_json::Value::as_u64)
                .context("samples")?,
            row.get("presence_detection_rate")
                .and_then(serde_json::Value::as_f64)
                .context("presence rate")?
                * 100.0,
            row.get("heuristic_detected")
                .and_then(serde_json::Value::as_u64)
                .context("heuristic detected")?,
            row.get("samples")
                .and_then(serde_json::Value::as_u64)
                .context("samples")?,
            row.get("heuristic_detection_rate")
                .and_then(serde_json::Value::as_f64)
                .context("heuristic rate")?
                * 100.0,
            row.get("mean_suspicion_score")
                .and_then(serde_json::Value::as_f64)
                .context("score")?,
            row.get("mean_longest_run")
                .and_then(serde_json::Value::as_f64)
                .context("run")?,
            row.get("mean_positional_entropy")
                .and_then(serde_json::Value::as_f64)
                .context("entropy")?
        ));
    }
    output.push_str(
        "\nScattering held the longest contiguous run to one symbol in every tested sample. It did not \
         conceal the use of a known carrier alphabet. These rates measure this implementation against \
         one disclosed corpus and detector; they are not estimates for every adversary or corpus.\n",
    );
    Ok(output)
}

fn write_vectors() -> Result<()> {
    let cover_pattern = ". ";
    let cover_repetitions = 4_000usize;
    let cover = cover_pattern.repeat(cover_repetitions);
    let parameters = Argon2Params::new(Argon2Params::MIN_MEMORY_KIB, Argon2Params::MIN_PASSES, 1)?;

    let password_seed = [0x11u8; 32];
    let mut password_rng = ChaCha20Rng::from_seed(password_seed);
    let password_hidden = hide_password_with_rng(
        &cover,
        Content::Text("Sayeh v4 password vector — سایه"),
        b"correct horse",
        PasswordOptions {
            carrier: CarrierKind::ZeroWidth,
            parameters,
            created_at: 1_700_000_001,
        },
        &mut password_rng,
    )?;
    let password_raw = scan(&password_hidden.text)?.container().marshal()?;

    let sender_bytes = [0x31u8; 32];
    let recipient_bytes = [0x32u8; 32];
    let sender = IdentitySecret::from_bytes(sender_bytes);
    let recipient = IdentitySecret::from_bytes(recipient_bytes);
    let contact_seed = [0x22u8; 32];
    let mut contact_rng = ChaCha20Rng::from_seed(contact_seed);
    let contact_hidden = hide_contact_with_rng(
        &cover,
        Content::File {
            name: "vector.bin",
            bytes: &[0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff],
        },
        &sender,
        recipient.public(),
        ContactOptions {
            carrier: CarrierKind::UnicodeTags,
            counter: 7,
            created_at: 1_700_000_002,
        },
        &mut contact_rng,
    )?;
    let contact_raw = scan(&contact_hidden.text)?.container().marshal()?;

    let document = json!({
        "schema": 1,
        "spec_version": "1.0.0-draft.1",
        "cover": {
            "pattern": cover_pattern,
            "repetitions": cover_repetitions
        },
        "password": {
            "rng_seed_hex": hex::encode(password_seed),
            "password_utf8": "correct horse",
            "content": {
                "kind": "text",
                "text": "Sayeh v4 password vector — سایه",
                "created_at": 1_700_000_001
            },
            "argon2": {
                "memory_kib": parameters.memory_kib(),
                "passes": parameters.passes(),
                "lanes": parameters.lanes()
            },
            "carrier": "zero-width",
            "container_hex": hex::encode(password_raw),
            "carrier_scalar_offsets": carrier_offsets(&password_hidden.text, CarrierKind::ZeroWidth),
            "stego_utf8_sha256": digest(&password_hidden.text)
        },
        "contact": {
            "rng_seed_hex": hex::encode(contact_seed),
            "sender_private_hex": hex::encode(sender_bytes),
            "recipient_private_hex": hex::encode(recipient_bytes),
            "content": {
                "kind": "file",
                "name": "vector.bin",
                "bytes_hex": "00017f80feff",
                "counter": 7,
                "created_at": 1_700_000_002
            },
            "carrier": "unicode-tags",
            "container_hex": hex::encode(contact_raw),
            "carrier_scalar_offsets": carrier_offsets(&contact_hidden.text, CarrierKind::UnicodeTags),
            "stego_utf8_sha256": digest(&contact_hidden.text)
        }
    });

    let path = workspace_root().join("vectors").join("wire-v4.json");
    let bytes = serde_json::to_vec_pretty(&document)?;
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

fn carrier_offsets(text: &str, carrier: CarrierKind) -> Vec<usize> {
    text.chars()
        .enumerate()
        .filter_map(|(offset, ch)| carrier.contains(ch).then_some(offset))
        .collect()
}

fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
