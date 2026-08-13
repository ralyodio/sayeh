#![forbid(unsafe_code)]

//! Foreign-language bindings for Sayeh application surfaces.

use sayeh_core::carrier::{CarrierKind, strip_aggressive};
use sayeh_core::container::ModeHeader;
use sayeh_core::frame::Content;
use sayeh_core::pipeline::{
    CapacityMode, PasswordOptions, capacity, clean_safe, hide_password, reveal_password, scan,
};
use sayeh_core::{probe, steganalysis};

uniffi::setup_scaffolding!();

/// Carrier alphabets supported by wire v4.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum CarrierChoice {
    ZeroWidth,
    ZeroWidthCompat,
    VariationSelectors,
    UnicodeTags,
}

/// Public mode metadata returned by a scan.
#[derive(Clone, Copy, uniffi::Enum)]
pub enum PayloadMode {
    Password,
    Contact,
}

/// A successful hide operation and non-secret size metadata.
#[derive(uniffi::Record)]
pub struct HiddenMessage {
    pub text: String,
    pub content_bytes: u64,
    pub container_bytes: u64,
    pub carrier_symbols: u64,
    pub compressed: bool,
}

/// Opened text or file bytes.
#[derive(uniffi::Record)]
pub struct OpenedMessage {
    pub is_text: bool,
    pub text: Option<String>,
    pub file_name: Option<String>,
    pub bytes: Vec<u8>,
    pub counter: u64,
    pub created_at: u64,
}

/// Authenticated public container metadata.
#[derive(uniffi::Record)]
pub struct ScanReport {
    pub wire_version: u8,
    pub mode: PayloadMode,
    pub carrier: CarrierChoice,
    pub compressed: bool,
    pub error_correction: bool,
    pub container_bytes: u64,
    pub carrier_symbols: u64,
    pub argon_memory_kib: Option<u32>,
    pub argon_passes: Option<u32>,
    pub argon_lanes: Option<u8>,
}

/// Statistics from one disclosed carrier detector.
#[derive(uniffi::Record)]
pub struct AnalysisReport {
    pub carrier: CarrierChoice,
    pub symbols: u64,
    pub visible_scalars: u64,
    pub density: f64,
    pub chi_square: f64,
    pub longest_run: u64,
    pub mean_gap: f64,
    pub gap_coefficient_of_variation: f64,
    pub positional_entropy: f64,
    pub suspicion_score: u8,
    pub likely_detectable: bool,
}

/// Hard payload ceiling and carrier expansion at that ceiling.
#[derive(uniffi::Record)]
pub struct CapacityReport {
    pub max_payload_bytes: u64,
    pub container_bytes_at_limit: u64,
    pub carrier_symbols_at_limit: u64,
}

/// Exact survival count for one probe scalar.
#[derive(uniffi::Record)]
pub struct ProbeScalar {
    pub codepoint: String,
    pub survived: u8,
}

/// Result of measuring a returned transport probe.
#[derive(uniffi::Record)]
pub struct ProbeReport {
    pub recommendation: Option<CarrierChoice>,
    pub scalars: Vec<ProbeScalar>,
}

/// Stable error boundary for Kotlin and Swift callers.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SayehFfiError {
    #[error("{reason}")]
    Failure { reason: String },
}

#[uniffi::export]
pub fn hide_password_text(
    cover: String,
    secret: String,
    password: String,
    carrier: CarrierChoice,
    created_at: u64,
) -> Result<HiddenMessage, SayehFfiError> {
    hide(
        Content::Text(&secret),
        &cover,
        &password,
        carrier,
        created_at,
    )
}

#[uniffi::export]
pub fn hide_password_file(
    cover: String,
    file_name: String,
    bytes: Vec<u8>,
    password: String,
    carrier: CarrierChoice,
    created_at: u64,
) -> Result<HiddenMessage, SayehFfiError> {
    hide(
        Content::File {
            name: &file_name,
            bytes: &bytes,
        },
        &cover,
        &password,
        carrier,
        created_at,
    )
}

#[uniffi::export]
pub fn reveal_password_message(
    text: String,
    password: String,
) -> Result<OpenedMessage, SayehFfiError> {
    let opened = reveal_password(&text, password.as_bytes()).map_err(ffi_error)?;
    Ok(OpenedMessage {
        is_text: opened.is_text(),
        text: opened.text().map(str::to_owned),
        file_name: opened.file_name().map(str::to_owned),
        bytes: opened.bytes().to_vec(),
        counter: opened.counter(),
        created_at: opened.created_at(),
    })
}

#[uniffi::export]
pub fn scan_message(text: String) -> Result<ScanReport, SayehFfiError> {
    let scanned = scan(&text).map_err(ffi_error)?;
    let (mode, memory, passes, lanes) = match scanned.container().header().mode() {
        ModeHeader::Password(header) => (
            PayloadMode::Password,
            Some(header.parameters().memory_kib()),
            Some(header.parameters().passes()),
            Some(header.parameters().lanes()),
        ),
        ModeHeader::Contact(_) => (PayloadMode::Contact, None, None, None),
    };
    Ok(ScanReport {
        wire_version: sayeh_core::WIRE_VERSION,
        mode,
        carrier: scanned.carrier().into(),
        compressed: scanned.container().header().compressed(),
        error_correction: scanned.container().header().error_correction(),
        container_bytes: as_u64(scanned.container().marshal().map_err(ffi_error)?.len())?,
        carrier_symbols: as_u64(scanned.symbols())?,
        argon_memory_kib: memory,
        argon_passes: passes,
        argon_lanes: lanes,
    })
}

#[uniffi::export]
pub fn strip_message_safe(text: String) -> String {
    clean_safe(&text)
}

#[uniffi::export]
pub fn strip_message_aggressive(text: String) -> String {
    strip_aggressive(&text)
}

#[uniffi::export]
pub fn analyse_message(text: String) -> Result<Vec<AnalysisReport>, SayehFfiError> {
    CarrierKind::ALL
        .iter()
        .map(|carrier| steganalysis::analyse(&text, *carrier))
        .filter(|report| report.symbols > 0)
        .map(|report| {
            Ok(AnalysisReport {
                carrier: report.carrier.into(),
                symbols: as_u64(report.symbols)?,
                visible_scalars: as_u64(report.visible_scalars)?,
                density: report.density,
                chi_square: report.chi_square,
                longest_run: as_u64(report.longest_run)?,
                mean_gap: report.mean_gap,
                gap_coefficient_of_variation: report.gap_coefficient_of_variation,
                positional_entropy: report.positional_entropy,
                suspicion_score: report.suspicion_score,
                likely_detectable: report.likely_detectable(),
            })
        })
        .collect()
}

#[uniffi::export]
pub fn payload_capacity(
    carrier: CarrierChoice,
    contact_mode: bool,
    file_name_bytes: u64,
) -> Result<CapacityReport, SayehFfiError> {
    let name_bytes = usize::try_from(file_name_bytes).map_err(|_| SayehFfiError::Failure {
        reason: "file name length is too large".to_owned(),
    })?;
    let mode = if contact_mode {
        CapacityMode::Contact
    } else {
        CapacityMode::Password
    };
    let result = capacity(carrier.into(), mode, name_bytes).map_err(ffi_error)?;
    Ok(CapacityReport {
        max_payload_bytes: as_u64(result.content_bytes)?,
        container_bytes_at_limit: as_u64(result.container_bytes)?,
        carrier_symbols_at_limit: as_u64(result.carrier_symbols)?,
    })
}

#[uniffi::export]
pub fn generate_transport_probe() -> String {
    probe::generate()
}

#[uniffi::export]
pub fn analyse_transport_probe(text: String) -> ProbeReport {
    let report = probe::analyse(&text);
    ProbeReport {
        recommendation: report.recommendation.map(Into::into),
        scalars: report
            .scalars
            .into_iter()
            .map(|entry| ProbeScalar {
                codepoint: format!("U+{:04X}", u32::from(entry.scalar)),
                survived: entry.survived,
            })
            .collect(),
    }
}

fn hide(
    content: Content<'_>,
    cover: &str,
    password: &str,
    carrier: CarrierChoice,
    created_at: u64,
) -> Result<HiddenMessage, SayehFfiError> {
    let hidden = hide_password(
        cover,
        content,
        password.as_bytes(),
        PasswordOptions {
            carrier: carrier.into(),
            created_at,
            ..PasswordOptions::default()
        },
    )
    .map_err(ffi_error)?;
    Ok(HiddenMessage {
        text: hidden.text,
        content_bytes: as_u64(hidden.report.content_bytes)?,
        container_bytes: as_u64(hidden.report.container_bytes)?,
        carrier_symbols: as_u64(hidden.report.carrier_symbols)?,
        compressed: hidden.report.compressed,
    })
}

fn as_u64(value: usize) -> Result<u64, SayehFfiError> {
    u64::try_from(value).map_err(|_| SayehFfiError::Failure {
        reason: "value is too large for the foreign-language boundary".to_owned(),
    })
}

fn ffi_error(error: impl std::fmt::Display) -> SayehFfiError {
    SayehFfiError::Failure {
        reason: error.to_string(),
    }
}

impl From<CarrierChoice> for CarrierKind {
    fn from(value: CarrierChoice) -> Self {
        match value {
            CarrierChoice::ZeroWidth => Self::ZeroWidth,
            CarrierChoice::ZeroWidthCompat => Self::ZeroWidthCompat,
            CarrierChoice::VariationSelectors => Self::VariationSelectors,
            CarrierChoice::UnicodeTags => Self::UnicodeTags,
        }
    }
}

impl From<CarrierKind> for CarrierChoice {
    fn from(value: CarrierKind) -> Self {
        match value {
            CarrierKind::ZeroWidth => Self::ZeroWidth,
            CarrierKind::ZeroWidthCompat => Self::ZeroWidthCompat,
            CarrierKind::VariationSelectors => Self::VariationSelectors,
            CarrierKind::UnicodeTags => Self::UnicodeTags,
        }
    }
}
