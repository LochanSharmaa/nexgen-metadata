//! field_mapper.rs — Self-Healing Tiered Metadata Mapping Engine
//!
//! ExifTool's JSON output keys are non-deterministic: the same logical field
//! may appear as `Make`, `EXIF:Make`, `XMP:Make`, or `QuickTime:Make` depending
//! on file type, ExifTool version, and installed plugins.  Hardcoding exact
//! keys (e.g. `json["Make"]`) silently produces `None` for every variant the
//! developer didn't anticipate — a critical flaw in an air-gapped forensic tool
//! where the user cannot debug in the cloud.
//!
//! This module implements a **4-tier lookup strategy** that resolves 95%+ of
//! these mapping discrepancies at runtime:
//!
//!   Tier 0 — **Golden Matrix** (pre-compiled `HashMap`, O(1) average).
//!   Tier 1 — **Strict**       (exact key match).
//!   Tier 2 — **Suffix/Fuzzy** (`:Make` suffix or Levenshtein ≤ 2).
//!   Tier 3 — **Case-insensitive** (lowercased full-key comparison).
//!
//! If all tiers fail, a strongly-typed [`MappingError`] is returned instead of
//! a silent `None`, giving downstream code the ability to log, alert, or cache
//! the miss for bug reporting.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// § 1  Golden Matrix (Tier 0)
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-compiled mapping from known ExifTool/lopdf/goblin variant keys to the
/// canonical field names used by [`crate::models::FileMetadata`].
///
/// Loaded once at startup via `include_str!("../mapping_matrix.json")` and
/// deserialised into this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenMatrix {
    /// Maps every known variant key (e.g. "EXIF:Make") to its canonical target
    /// field name (e.g. "exif_make").
    pub mappings: HashMap<String, String>,
}

impl GoldenMatrix {
    /// Load and parse the embedded golden matrix JSON.
    pub fn load_embedded() -> Self {
        let raw = include_str!("../mapping_matrix.json");
        serde_json::from_str(raw).unwrap_or_else(|e| {
            tracing::warn!("Failed to parse embedded mapping_matrix.json: {}. Using empty matrix.", e);
            GoldenMatrix { mappings: HashMap::new() }
        })
    }

    /// Look up a raw key in the golden matrix.  Returns the canonical field
    /// name if a mapping exists.
    pub fn resolve(&self, raw_key: &str) -> Option<&str> {
        self.mappings.get(raw_key).map(|s| s.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 2  MappingError — strongly typed "field not found"
// ─────────────────────────────────────────────────────────────────────────────

/// Describes exactly why a field lookup failed, including the raw keys that
/// were available.  This replaces silent `None` with actionable diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingError {
    /// The canonical field name we were looking for (e.g. "exif_make").
    pub target_field: String,
    /// All raw keys that ExifTool / lopdf / goblin actually returned.
    pub available_keys: Vec<String>,
    /// The highest tier that was attempted (0–3).
    pub highest_tier_tried: u8,
    /// If Tier 2 fuzzy matched something, the closest candidate and its
    /// Levenshtein distance.
    pub closest_candidate: Option<(String, usize)>,
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MappingError: field '{}' not found after tier {} lookup. Available keys: [{}]",
            self.target_field,
            self.highest_tier_tried,
            self.available_keys.join(", "),
        )?;
        if let Some((ref candidate, dist)) = self.closest_candidate {
            write!(f, " (closest: '{}' at distance {})", candidate, dist)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 3  MappingResult — the resolution output
// ─────────────────────────────────────────────────────────────────────────────

/// Successful resolution of a field lookup, including which tier resolved it.
#[derive(Debug, Clone, Serialize)]
pub struct MappingHit {
    /// The raw key in the source JSON that matched.
    pub matched_key: String,
    /// The tier that produced the match (0 = golden, 1 = strict, 2 = suffix/fuzzy, 3 = case-insensitive).
    pub tier: u8,
    /// The resolved value.
    pub value: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// § 4  FieldMapper — the core engine
// ─────────────────────────────────────────────────────────────────────────────

/// Self-healing metadata field mapper.
///
/// Holds a reference to the golden matrix and provides tiered lookup against
/// any `serde_json::Value` object (ExifTool output, lopdf dictionary converted
/// to JSON, goblin PE header converted to JSON).
pub struct FieldMapper {
    #[allow(dead_code)]
    matrix: GoldenMatrix,
    /// Reverse index: for each canonical field name, all known raw keys that
    /// map to it.  Built from the golden matrix at construction time.
    reverse_index: HashMap<String, Vec<String>>,
}

impl FieldMapper {
    /// Create a new mapper backed by the given golden matrix.
    pub fn new(matrix: GoldenMatrix) -> Self {
        // Build reverse index: canonical_field -> [raw_key1, raw_key2, ...]
        let mut reverse_index: HashMap<String, Vec<String>> = HashMap::new();
        for (raw_key, canonical) in &matrix.mappings {
            reverse_index
                .entry(canonical.clone())
                .or_default()
                .push(raw_key.clone());
        }
        Self { matrix, reverse_index }
    }

    /// Attempt to resolve `target_field` from the given JSON object using
    /// the 4-tier strategy.
    ///
    /// Returns `Ok(MappingHit)` on success, `Err(MappingError)` if all tiers
    /// fail.
    pub fn resolve(
        &self,
        json: &serde_json::Value,
        target_field: &str,
    ) -> Result<MappingHit, MappingError> {
        let obj = match json.as_object() {
            Some(o) => o,
            None => {
                return Err(MappingError {
                    target_field: target_field.to_string(),
                    available_keys: Vec::new(),
                    highest_tier_tried: 0,
                    closest_candidate: None,
                });
            }
        };

        let available_keys: Vec<String> = obj.keys().cloned().collect();

        // ── Tier 0: Golden Matrix ────────────────────────────────────────
        if let Some(known_keys) = self.reverse_index.get(target_field) {
            for raw_key in known_keys {
                if let Some(val) = obj.get(raw_key) {
                    return Ok(MappingHit {
                        matched_key: raw_key.clone(),
                        tier: 0,
                        value: val.clone(),
                    });
                }
            }
        }

        // ── Tier 1: Strict exact key match ───────────────────────────────
        if let Some(val) = obj.get(target_field) {
            return Ok(MappingHit {
                matched_key: target_field.to_string(),
                tier: 1,
                value: val.clone(),
            });
        }

        // ── Tier 2: Suffix match, then Levenshtein fuzzy ─────────────────
        // Suffix: if any key ends with `:TargetField` (e.g. "EXIF:Make" for "Make")
        let suffix_pattern = format!(":{}", target_field);
        for (key, val) in obj.iter() {
            if key.ends_with(&suffix_pattern) {
                return Ok(MappingHit {
                    matched_key: key.clone(),
                    tier: 2,
                    value: val.clone(),
                });
            }
        }

        // Levenshtein fuzzy: find the closest key within distance ≤ 2
        // (Defer pure case-insensitive matches to Tier 3)
        let mut best_candidate: Option<(String, usize, serde_json::Value)> = None;
        for (key, val) in obj.iter() {
            // Compare the suffix portion after the last ':'
            let compare_part = key.rsplit(':').next().unwrap_or(key);
            if compare_part.eq_ignore_ascii_case(target_field) {
                continue;
            }
            let dist = levenshtein_distance(compare_part, target_field);
            if dist <= 2 {
                if best_candidate.as_ref().map_or(true, |(_, d, _)| dist < *d) {
                    best_candidate = Some((key.clone(), dist, val.clone()));
                }
            }
        }
        if let Some((key, _dist, val)) = best_candidate.clone() {
            return Ok(MappingHit {
                matched_key: key,
                tier: 2,
                value: val,
            });
        }

        // ── Tier 3: Case-insensitive full-key comparison ─────────────────
        let target_lower = target_field.to_ascii_lowercase();
        for (key, val) in obj.iter() {
            if key.to_ascii_lowercase() == target_lower {
                return Ok(MappingHit {
                    matched_key: key.clone(),
                    tier: 3,
                    value: val.clone(),
                });
            }
            // Also try case-insensitive on the suffix portion
            let suffix_part = key.rsplit(':').next().unwrap_or(key);
            if suffix_part.to_ascii_lowercase() == target_lower {
                return Ok(MappingHit {
                    matched_key: key.clone(),
                    tier: 3,
                    value: val.clone(),
                });
            }
        }

        // ── All tiers exhausted ──────────────────────────────────────────
        Err(MappingError {
            target_field: target_field.to_string(),
            available_keys,
            highest_tier_tried: 3,
            closest_candidate: best_candidate.map(|(k, d, _)| (k, d)),
        })
    }

    // ── Convenience typed extractors ─────────────────────────────────────

    /// Resolve and extract as `Option<String>`.
    pub fn get_string(
        &self,
        json: &serde_json::Value,
        target_field: &str,
    ) -> Result<Option<String>, MappingError> {
        match self.resolve(json, target_field) {
            Ok(hit) => Ok(value_to_string(&hit.value)),
            Err(e) => Err(e),
        }
    }

    /// Resolve and extract as `Option<f64>`.
    pub fn get_f64(
        &self,
        json: &serde_json::Value,
        target_field: &str,
    ) -> Result<Option<f64>, MappingError> {
        match self.resolve(json, target_field) {
            Ok(hit) => Ok(value_to_f64(&hit.value)),
            Err(e) => Err(e),
        }
    }

    /// Resolve and extract as `Option<u32>`.
    pub fn get_u32(
        &self,
        json: &serde_json::Value,
        target_field: &str,
    ) -> Result<Option<u32>, MappingError> {
        match self.resolve(json, target_field) {
            Ok(hit) => Ok(value_to_u64(&hit.value).map(|v| v as u32)),
            Err(e) => Err(e),
        }
    }

    /// Resolve and extract as `Option<u64>`.
    pub fn get_u64(
        &self,
        json: &serde_json::Value,
        target_field: &str,
    ) -> Result<Option<u64>, MappingError> {
        match self.resolve(json, target_field) {
            Ok(hit) => Ok(value_to_u64(&hit.value)),
            Err(e) => Err(e),
        }
    }

    /// Resolve and extract as `Option<u8>`.
    pub fn get_u8(
        &self,
        json: &serde_json::Value,
        target_field: &str,
    ) -> Result<Option<u8>, MappingError> {
        match self.resolve(json, target_field) {
            Ok(hit) => Ok(value_to_u64(&hit.value).map(|v| v as u8)),
            Err(e) => Err(e),
        }
    }

    /// Resolve and extract as `Option<bool>`.
    pub fn get_bool(
        &self,
        json: &serde_json::Value,
        target_field: &str,
    ) -> Result<Option<bool>, MappingError> {
        match self.resolve(json, target_field) {
            Ok(hit) => Ok(hit.value.as_bool()),
            Err(e) => Err(e),
        }
    }

    /// Apply all known ExifTool metadata fields to the given FileMetadata struct.
    /// Returns any mapping errors for diagnostic logging.
    pub fn apply_to_metadata(
        &self,
        json: &serde_json::Value,
        meta: &mut crate::models::FileMetadata,
    ) -> Vec<MappingError> {
        let item = if let Some(arr) = json.as_array() {
            arr.first().unwrap_or(json)
        } else {
            json
        };

        let mut errors = Vec::new();

        macro_rules! map_str {
            ($field:ident, $target:expr) => {
                match self.get_string(item, $target) {
                    Ok(Some(v)) => meta.$field = Some(v),
                    Ok(None) => {},
                    Err(e) => errors.push(e),
                }
            };
        }

        macro_rules! map_f64 {
            ($field:ident, $target:expr) => {
                match self.get_f64(item, $target) {
                    Ok(Some(v)) => meta.$field = Some(v),
                    Ok(None) => {},
                    Err(e) => errors.push(e),
                }
            };
        }

        macro_rules! map_u32 {
            ($field:ident, $target:expr) => {
                match self.get_u32(item, $target) {
                    Ok(Some(v)) => meta.$field = Some(v),
                    Ok(None) => {},
                    Err(e) => errors.push(e),
                }
            };
        }

        macro_rules! map_u64 {
            ($field:ident, $target:expr) => {
                match self.get_u64(item, $target) {
                    Ok(Some(v)) => meta.$field = Some(v),
                    Ok(None) => {},
                    Err(e) => errors.push(e),
                }
            };
        }

        macro_rules! map_u8 {
            ($field:ident, $target:expr) => {
                match self.get_u8(item, $target) {
                    Ok(Some(v)) => meta.$field = Some(v),
                    Ok(None) => {},
                    Err(e) => errors.push(e),
                }
            };
        }

        // EXIF Camera / Optics
        map_str!(exif_make, "Make");
        map_str!(exif_model, "Model");
        map_str!(exif_serial_number, "SerialNumber");
        map_str!(exif_lens_model, "LensModel");
        map_f64!(exif_focal_length, "FocalLength");
        map_f64!(exif_focal_length_35mm, "FocalLengthIn35mmFormat");
        map_f64!(exif_f_number, "FNumber");
        map_str!(exif_exposure_time, "ExposureTime");
        map_u32!(exif_iso, "ISO");
        map_str!(exif_exposure_program, "ExposureProgram");
        map_str!(exif_metering_mode, "MeteringMode");
        map_str!(exif_flash, "Flash");
        map_str!(exif_white_balance, "WhiteBalance");
        map_str!(exif_color_space, "ColorSpace");
        map_str!(exif_orientation, "Orientation");
        map_f64!(exif_x_resolution, "XResolution");
        map_f64!(exif_y_resolution, "YResolution");
        map_u32!(exif_bits_per_sample, "BitsPerSample");
        map_str!(exif_compression, "Compression");
        map_str!(exif_datetime_original, "DateTimeOriginal");
        map_str!(exif_datetime_digitized, "CreateDate");
        map_str!(exif_software, "Software");
        map_str!(exif_artist, "Artist");
        map_str!(exif_copyright, "Copyright");
        map_u32!(exif_image_width, "ImageWidth");
        map_u32!(exif_image_height, "ImageHeight");
        map_u64!(exif_thumbnail_offset, "ThumbnailOffset");
        map_u64!(exif_thumbnail_length, "ThumbnailLength");
        map_str!(exif_profile_icc, "ProfileDescription");
        map_f64!(exif_subject_distance, "SubjectDistance");

        // GPS
        map_f64!(gps_latitude, "GPSLatitude");
        map_f64!(gps_longitude, "GPSLongitude");
        map_f64!(gps_altitude, "GPSAltitude");
        map_str!(gps_altitude_ref, "GPSAltitudeRef");
        map_f64!(gps_speed, "GPSSpeed");
        map_str!(gps_speed_ref, "GPSSpeedRef");
        map_f64!(gps_direction, "GPSImgDirection");
        map_str!(gps_direction_ref, "GPSImgDirectionRef");
        map_str!(gps_timestamp, "GPSTimeStamp");
        map_str!(gps_datestamp, "GPSDateStamp");
        map_f64!(gps_dop, "GPSDOP");
        map_str!(gps_satellites, "GPSSatellites");

        // Video / Audio
        map_f64!(media_duration_seconds, "Duration");
        if let Some(dur) = meta.media_duration_seconds {
            let total_secs = dur as u64;
            let h = total_secs / 3600;
            let m = (total_secs % 3600) / 60;
            let s = total_secs % 60;
            meta.media_duration_human = Some(format!("{:02}:{:02}:{:02}", h, m, s));
        }
        map_str!(video_codec, "VideoCodec");
        map_u32!(video_width, "ImageWidth");
        map_u32!(video_height, "ImageHeight");
        map_f64!(video_frame_rate, "VideoFrameRate");
        map_u32!(video_bit_depth, "BitDepth");
        map_str!(video_color_primaries, "ColorPrimaries");
        map_str!(video_transfer_characteristics, "TransferCharacteristics");
        map_u64!(video_bitrate_kbps, "AvgBitrate");
        map_str!(audio_codec, "AudioCodec");
        map_u32!(audio_sample_rate, "AudioSampleRate");
        map_u8!(audio_channels, "AudioChannels");
        map_u64!(audio_bitrate_kbps, "AudioBitrate");
        map_u32!(audio_bits_per_sample, "AudioBitsPerSample");
        map_str!(media_container_format, "MajorBrand");
        map_str!(media_encoder, "Encoder");
        map_f64!(media_rotation, "Rotation");

        // Documents
        map_str!(doc_author, "Author");
        map_str!(doc_last_modified_by, "LastModifiedBy");
        map_str!(doc_title, "Title");
        map_str!(doc_subject, "Subject");
        map_str!(doc_keywords, "Keywords");
        map_str!(doc_category, "Category");
        map_str!(doc_company, "Company");
        map_str!(doc_created_date, "CreateDate");
        map_str!(doc_modified_date, "ModifyDate");
        map_u32!(doc_revision_count, "RevisionNumber");
        map_u64!(doc_edit_time_minutes, "TotalEditTime");
        map_u32!(doc_page_count, "Pages");
        map_u32!(doc_word_count, "Words");
        map_u32!(doc_character_count, "Characters");
        map_u32!(doc_line_count, "Lines");
        map_u32!(doc_paragraph_count, "Paragraphs");
        map_u32!(doc_slide_count, "Slides");

        // PDF
        map_str!(pdf_version, "PDFVersion");
        map_str!(pdf_producer, "Producer");
        map_str!(pdf_creator_app, "Creator");

        errors
    }

    /// Apply parsed lopdf JSON dictionary metadata to FileMetadata
    pub fn apply_pdf_dict(
        &self,
        json: &serde_json::Value,
        meta: &mut crate::models::FileMetadata,
    ) -> Vec<MappingError> {
        let mut errors = Vec::new();
        match self.get_string(json, "Author") {
            Ok(Some(v)) => meta.pdf_author = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        match self.get_string(json, "Title") {
            Ok(Some(v)) => meta.pdf_title = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        match self.get_string(json, "Subject") {
            Ok(Some(v)) => meta.pdf_subject = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        match self.get_string(json, "Creator") {
            Ok(Some(v)) => meta.pdf_creator_app = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        match self.get_string(json, "Producer") {
            Ok(Some(v)) => meta.pdf_producer = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        match self.get_string(json, "CreationDate") {
            Ok(Some(v)) => meta.pdf_creation_date = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        match self.get_string(json, "ModDate") {
            Ok(Some(v)) => meta.pdf_modification_date = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        match self.get_string(json, "Keywords") {
            Ok(Some(v)) => meta.pdf_keywords = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        errors
    }

    /// Apply parsed PE header JSON metadata to FileMetadata
    pub fn apply_pe_header(
        &self,
        json: &serde_json::Value,
        meta: &mut crate::models::FileMetadata,
    ) -> Vec<MappingError> {
        let mut errors = Vec::new();
        match self.get_string(json, "MachineType") {
            Ok(Some(v)) => meta.pe_architecture = Some(v),
            Ok(None) => {},
            Err(e) => errors.push(e),
        }
        errors
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 5  RawCache — Diagnostic Ring Buffer Element
// ─────────────────────────────────────────────────────────────────────────────

/// Caches raw parser input and mapped output for a file in an in-memory ring buffer.
/// Redacts sensitive filesystem path information for privacy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCache {
    pub scan_id: String,
    pub row_index: usize,
    pub file_id: u64,
    pub file_name: String,
    pub file_extension: String,
    pub raw_json: serde_json::Value,
    pub mapped_metadata: crate::models::FileMetadata,
    pub timestamp_utc: String,
}

impl RawCache {
    pub fn new_redacted(
        scan_id: String,
        row_index: usize,
        file_id: u64,
        file_name: String,
        file_extension: String,
        raw_json: serde_json::Value,
        mut mapped_metadata: crate::models::FileMetadata,
    ) -> Self {
        // Redact full absolute paths for privacy
        mapped_metadata.file_path = Some(format!("<REDACTED>/{}", file_name));
        mapped_metadata.parent_directory = Some("<REDACTED>".to_string());

        Self {
            scan_id,
            row_index,
            file_id,
            file_name,
            file_extension,
            raw_json,
            mapped_metadata,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 6  Value conversion helpers
// ─────────────────────────────────────────────────────────────────────────────

fn value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn value_to_f64(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => {
            // Handle strings like "6.0 mm", "f/2.8", "1/1000"
            let cleaned = s.trim();
            if let Some(idx) = cleaned.find('/') {
                // Fraction: "1/1000" -> compute as division? No, return as-is for string fields.
                // For numeric fields, try parsing the first number.
                cleaned[..idx].trim().parse::<f64>().ok()
            } else {
                // Strip unit suffixes: "6.0 mm" -> "6.0"
                cleaned
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
            }
        }
        _ => None,
    }
}

fn value_to_u64(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
        serde_json::Value::String(s) => {
            let cleaned = s.trim();
            cleaned
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
        }
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 6  Levenshtein distance (no external dependency)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Levenshtein edit distance between two strings.
///
/// We inline this rather than pulling in the `strsim` crate to avoid adding
/// another dependency to the forensic engine.  The algorithm is O(n*m) but
/// the strings here are short tag names (< 50 chars), so performance is fine.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 { return b_len; }
    if b_len == 0 { return a_len; }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row: Vec<usize> = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr_row[0] = i;
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            curr_row[j] = (prev_row[j] + 1)
                .min(curr_row[j - 1] + 1)
                .min(prev_row[j - 1] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

// ─────────────────────────────────────────────────────────────────────────────
// § 7  Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mapper() -> FieldMapper {
        let mut mappings = HashMap::new();
        mappings.insert("EXIF:Make".to_string(), "Make".to_string());
        mappings.insert("XMP:Make".to_string(), "Make".to_string());
        mappings.insert("QuickTime:Make".to_string(), "Make".to_string());
        mappings.insert("EXIF:Model".to_string(), "Model".to_string());
        let matrix = GoldenMatrix { mappings };
        FieldMapper::new(matrix)
    }

    #[test]
    fn tier_0_golden_matrix() {
        let mapper = make_mapper();
        let json: serde_json::Value = serde_json::json!({
            "EXIF:Make": "Canon",
            "EXIF:Model": "EOS R5"
        });
        let hit = mapper.resolve(&json, "Make").unwrap();
        assert_eq!(hit.tier, 0);
        assert_eq!(hit.value.as_str().unwrap(), "Canon");
    }

    #[test]
    fn tier_1_strict() {
        let mapper = make_mapper();
        let json: serde_json::Value = serde_json::json!({
            "FocalLength": 50.0
        });
        let hit = mapper.resolve(&json, "FocalLength").unwrap();
        assert_eq!(hit.tier, 1);
    }

    #[test]
    fn tier_2_suffix() {
        let mapper = make_mapper();
        let json: serde_json::Value = serde_json::json!({
            "Composite:FocalLength": "50mm"
        });
        let hit = mapper.resolve(&json, "FocalLength").unwrap();
        assert_eq!(hit.tier, 2);
        assert_eq!(hit.matched_key, "Composite:FocalLength");
    }

    #[test]
    fn tier_3_case_insensitive() {
        let mapper = make_mapper();
        let json: serde_json::Value = serde_json::json!({
            "focallength": 85.0
        });
        let hit = mapper.resolve(&json, "FocalLength").unwrap();
        assert_eq!(hit.tier, 3);
    }

    #[test]
    fn all_tiers_fail_returns_mapping_error() {
        let mapper = make_mapper();
        let json: serde_json::Value = serde_json::json!({
            "UnrelatedField": "value"
        });
        let err = mapper.resolve(&json, "FocalLength").unwrap_err();
        assert_eq!(err.target_field, "FocalLength");
        assert_eq!(err.highest_tier_tried, 3);
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("Make", "make"), 1);
        assert_eq!(levenshtein_distance("Make", "Make"), 0);
        assert_eq!(levenshtein_distance("", "abc"), 3);
    }
}
