#![forbid(unsafe_code)]

//! Browser bindings for Sayeh.

use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sayeh_core::carrier::{CarrierKind, strip_aggressive};
use sayeh_core::container::ModeHeader;
use sayeh_core::frame::Content;
use sayeh_core::pipeline::{
    CapacityMode, HiddenMessage, PasswordOptions, capacity, clean_safe, hide_password,
    reveal_password, scan,
};
use sayeh_core::{probe, steganalysis};
use serde_json::json;
use wasm_bindgen::prelude::*;

/// Hides UTF-8 text with password mode and returns a JSON result.
#[wasm_bindgen(js_name = hidePasswordText)]
pub fn hide_password_text(
    cover: &str,
    secret: &str,
    password: &str,
    carrier: &str,
    created_at: f64,
) -> Result<String, JsValue> {
    let options = options(carrier, created_at)?;
    let hidden = hide_password(cover, Content::Text(secret), password.as_bytes(), options)
        .map_err(js_error)?;
    hidden_json(hidden)
}

/// Hides arbitrary bytes with password mode and returns a JSON result.
#[wasm_bindgen(js_name = hidePasswordFile)]
pub fn hide_password_file(
    cover: &str,
    file_name: &str,
    bytes: &[u8],
    password: &str,
    carrier: &str,
    created_at: f64,
) -> Result<String, JsValue> {
    let options = options(carrier, created_at)?;
    let hidden = hide_password(
        cover,
        Content::File {
            name: file_name,
            bytes,
        },
        password.as_bytes(),
        options,
    )
    .map_err(js_error)?;
    hidden_json(hidden)
}

/// Opens a password-mode payload and returns text or base64 file data as JSON.
#[wasm_bindgen(js_name = revealPassword)]
pub fn reveal_password_json(text: &str, password: &str) -> Result<String, JsValue> {
    let opened = reveal_password(text, password.as_bytes()).map_err(js_error)?;
    let value = if let Some(secret) = opened.text() {
        json!({
            "kind": "text",
            "text": secret,
            "counter": opened.counter(),
            "created_at": opened.created_at()
        })
    } else {
        json!({
            "kind": "file",
            "file_name": opened.file_name(),
            "bytes_base64": BASE64.encode(opened.bytes()),
            "counter": opened.counter(),
            "created_at": opened.created_at()
        })
    };
    to_json(&value)
}

/// Validates public container metadata without decrypting it.
#[wasm_bindgen(js_name = scan)]
pub fn scan_json(text: &str) -> Result<String, JsValue> {
    let scanned = scan(text).map_err(js_error)?;
    let container = scanned.container();
    let (mode, kdf) = match container.header().mode() {
        ModeHeader::Password(header) => (
            "password",
            Some(json!({
                "algorithm": "Argon2id",
                "memory_kib": header.parameters().memory_kib(),
                "passes": header.parameters().passes(),
                "lanes": header.parameters().lanes()
            })),
        ),
        ModeHeader::Contact(_) => ("contact", None),
    };
    let value = json!({
        "wire_version": 4,
        "mode": mode,
        "carrier": scanned.carrier().name(),
        "compressed": container.header().compressed(),
        "error_correction": container.header().error_correction(),
        "container_bytes": container.marshal().map_err(js_error)?.len(),
        "carrier_symbols": scanned.symbols(),
        "kdf": kdf
    });
    to_json(&value)
}

/// Runs the disclosed detector for every carrier alphabet present in the text.
#[wasm_bindgen(js_name = analyse)]
pub fn analyse_json(text: &str) -> Result<String, JsValue> {
    let reports = CarrierKind::ALL
        .iter()
        .map(|carrier| steganalysis::analyse(text, *carrier))
        .filter(|report| report.symbols > 0)
        .map(|report| {
            json!({
                "carrier": report.carrier.name(),
                "symbols": report.symbols,
                "visible_scalars": report.visible_scalars,
                "density": report.density,
                "chi_square": report.chi_square,
                "longest_run": report.longest_run,
                "mean_gap": report.mean_gap,
                "gap_coefficient_of_variation": report.gap_coefficient_of_variation,
                "positional_entropy": report.positional_entropy,
                "suspicion_score": report.suspicion_score,
                "likely_detectable": report.likely_detectable()
            })
        })
        .collect::<Vec<_>>();
    to_json(&reports)
}

/// Estimates incompressible payload capacity for a cover.
#[wasm_bindgen(js_name = capacity)]
pub fn capacity_json(carrier: &str, mode: &str, file_name_bytes: usize) -> Result<String, JsValue> {
    let carrier = parse_carrier(carrier)?;
    let mode = match mode {
        "password" => CapacityMode::Password,
        "contact" => CapacityMode::Contact,
        _ => return Err(JsValue::from_str("mode must be password or contact")),
    };
    let result = capacity(carrier, mode, file_name_bytes).map_err(js_error)?;
    to_json(&json!({
        "carrier": carrier.name(),
        "container_bytes": result.container_bytes,
        "max_payload_bytes": result.content_bytes,
        "carrier_symbols_at_limit": result.carrier_symbols
    }))
}

/// Removes a recognized v4 payload while preserving Persian ZWNJ and emoji ZWJ.
#[wasm_bindgen(js_name = stripSafe)]
pub fn strip_safe(text: &str) -> String {
    clean_safe(text)
}

/// Removes format characters in the explicitly destructive cleaning mode.
#[wasm_bindgen(js_name = stripAggressive)]
pub fn strip_all(text: &str) -> String {
    strip_aggressive(text)
}

/// Generates a transport survival probe.
#[wasm_bindgen(js_name = probeGenerate)]
pub fn probe_generate() -> String {
    probe::generate()
}

/// Compares a returned probe with its visible markers.
#[wasm_bindgen(js_name = probeAnalyse)]
pub fn probe_analyse(text: &str) -> Result<String, JsValue> {
    let report = probe::analyse(text);
    let scalars = report
        .scalars
        .iter()
        .map(|entry| {
            json!({
                "codepoint": format!("U+{:04X}", u32::from(entry.scalar)),
                "survived": entry.survived
            })
        })
        .collect::<Vec<_>>();
    to_json(&json!({
        "recommendation": report.recommendation.map(CarrierKind::name),
        "scalars": scalars
    }))
}

fn options(carrier: &str, created_at: f64) -> Result<PasswordOptions, JsValue> {
    if !created_at.is_finite() || created_at < 0.0 || created_at > u32::MAX as f64 {
        return Err(JsValue::from_str(
            "created_at is outside the supported range",
        ));
    }
    Ok(PasswordOptions {
        carrier: parse_carrier(carrier)?,
        created_at: created_at.trunc() as u64,
        ..PasswordOptions::default()
    })
}

fn parse_carrier(value: &str) -> Result<CarrierKind, JsValue> {
    CarrierKind::from_str(value).map_err(js_error)
}

fn hidden_json(hidden: HiddenMessage) -> Result<String, JsValue> {
    to_json(&json!({
        "text": hidden.text,
        "report": {
            "carrier": hidden.report.carrier.name(),
            "content_bytes": hidden.report.content_bytes,
            "container_bytes": hidden.report.container_bytes,
            "carrier_symbols": hidden.report.carrier_symbols,
            "compressed": hidden.report.compressed
        }
    }))
}

fn to_json(value: &impl serde::Serialize) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
