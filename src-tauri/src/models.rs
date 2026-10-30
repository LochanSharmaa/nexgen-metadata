//! models.rs — Core data model definitions for NexGen Metadata forensic tool.
//!
//! This module defines the canonical [`FileMetadata`] struct that is the central
//! unit of work flowing between the scan engine, the analysis pipeline, the
//! SQLite persistence layer, the XLSX export engine, and the Tauri front-end.
//!
//! All types are fully serialisable via [`serde`] so they can be round-tripped
//! through JSON (IPC / front-end), SQLite (via serde_json column storage), and
//! the XLSX writer without any manual conversion.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// § 1  Support enumerations
// ─────────────────────────────────────────────────────────────────────────────

/// Indicates whether a file's MACB timestamps show signs of manual manipulation
/// (timestomping), which is a common anti-forensic technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestompSuspect {
    /// Statistical and logical checks strongly suggest tampering.
    Confirmed,
    /// Some indicators are present but not conclusive.
    Possible,
    /// No timestomping indicators detected.
    Clean,
}

/// Verification state of a PDF digital signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfSignatureStatus {
    /// Signature cryptographically verifies and certificate chain is trusted.
    Valid,
    /// Signature bytes do not match document content.
    Invalid,
    /// Signature was valid but the signing certificate has expired.
    Expired,
    /// Document contains no digital signature.
    Unsigned,
    /// Signature present but could not be evaluated (e.g. missing root cert).
    Unknown,
}

/// Authenticode signature state for a PE (Portable Executable) binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeAuthenticodeStatus {
    /// Signature is cryptographically valid and the chain is trusted.
    Valid,
    /// Hash mismatch — file may have been modified after signing.
    InvalidSignature,
    /// File carries no Authenticode signature.
    Unsigned,
    /// Signature is structurally correct but the root CA is not trusted.
    Untrusted,
}

// ─────────────────────────────────────────────────────────────────────────────
// § 2  MACB Timestamps
// ─────────────────────────────────────────────────────────────────────────────

/// MACB (Modified / Accessed / Changed / Born) filesystem timestamps.
///
/// All values are UTC ISO-8601 strings, e.g. `"2024-03-15T09:42:07.123456Z"`.
/// Using `Option<String>` keeps the representation uniform across NTFS, ext4,
/// APFS, and FAT volumes where some timestamps may not be available.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MacbTimestamps {
    /// File creation time (Born) — `$STANDARD_INFORMATION` on NTFS.
    pub created: Option<String>,
    /// Last access time — updated on read (may be disabled by OS tuning).
    pub accessed: Option<String>,
    /// Last data modification time.
    pub modified: Option<String>,
    /// Metadata-change time (`ctime` on POSIX; `$MFT` record update on NTFS).
    pub changed: Option<String>,
}

impl MacbTimestamps {
    /// Constructs an all-`None` instance as a default placeholder.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            created: None,
            accessed: None,
            modified: None,
            changed: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 3  FileMetadata — the canonical record for one scanned file
// ─────────────────────────────────────────────────────────────────────────────

/// Complete forensic metadata record for a single file.
///
/// Every field except `id` is `Option<T>` to allow partial population:
/// the scan engine fills what it can in the time / permission budget, and
/// callers must treat `None` as "not yet determined" rather than "absent".
///
/// Field ordering within each category matches the order displayed in the
/// XLSX export and the front-end detail panel.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    // ── File System ───────────────────────────────────────────────────────────
    /// Monotonically increasing scan-session row identifier.
    pub id: u64,
    /// Base file name including extension, e.g. `"report.pdf"`.
    pub file_name: Option<String>,
    /// Lower-cased extension without the leading dot, e.g. `"pdf"`.
    pub file_extension: Option<String>,
    /// Full absolute path to the file on the host system.
    pub file_path: Option<String>,
    /// Absolute path of the containing directory.
    pub parent_directory: Option<String>,
    /// File size in bytes as reported by the filesystem.
    pub size_bytes: Option<u64>,
    /// Human-readable file size, e.g. `"4.27 MB"`.
    pub size_human: Option<String>,
    /// Raw Windows `dwFileAttributes` bitmask value.
    pub file_attributes_raw: Option<u32>,
    /// `FILE_ATTRIBUTE_READONLY` is set.
    pub is_readonly: Option<bool>,
    /// `FILE_ATTRIBUTE_HIDDEN` is set.
    pub is_hidden: Option<bool>,
    /// `FILE_ATTRIBUTE_SYSTEM` is set.
    pub is_system: Option<bool>,
    /// `FILE_ATTRIBUTE_ARCHIVE` is set.
    pub is_archive: Option<bool>,
    /// `FILE_ATTRIBUTE_TEMPORARY` is set.
    pub is_temporary: Option<bool>,
    /// `FILE_ATTRIBUTE_COMPRESSED` is set (NTFS compression).
    pub is_compressed: Option<bool>,
    /// `FILE_ATTRIBUTE_ENCRYPTED` is set (EFS encryption).
    pub is_encrypted_flag: Option<bool>,

    // ── NTFS & Forensics ──────────────────────────────────────────────────────
    /// MACB timestamps harvested from `$STANDARD_INFORMATION` / `$FILE_NAME`.
    pub macb: Option<MacbTimestamps>,
    /// Assessment of whether timestamps appear to have been manipulated.
    pub timestomp_suspect: Option<TimestompSuspect>,
    /// NTFS Master File Table record number (inode equivalent).
    pub inode_number: Option<u64>,
    /// Number of hard links pointing at this file's MFT record.
    pub link_count: Option<u32>,
    /// Zone.Identifier ADS `ZoneId` field (0=local, 3=internet, 4=restricted).
    pub ads_zone_id: Option<u32>,
    /// Zone.Identifier `HostUrl` field.
    pub ads_host_url: Option<String>,
    /// Zone.Identifier `ReferrerUrl` field.
    pub ads_referrer_url: Option<String>,
    /// Names of all Alternate Data Streams attached to this file.
    pub ads_names: Option<Vec<String>>,
    /// Raw MFT record number (may differ from `inode_number` on multi-volume scans).
    pub mft_record_number: Option<u64>,
    /// USN Journal record identifier at time of last change.
    pub usn_journal_id: Option<u64>,
    /// NTFS volume serial number of the hosting volume.
    pub volume_serial: Option<u64>,
    /// Reparse point tag (e.g. `IO_REPARSE_TAG_SYMLINK = 0xA000000C`).
    pub reparse_tag: Option<u32>,

    // ── Hashes & Checksums ────────────────────────────────────────────────────
    /// MD5 hex digest (128-bit / 32 hex chars).  Legacy; prefer SHA-256+.
    pub hash_md5: Option<String>,
    /// SHA-1 hex digest (160-bit / 40 hex chars).  Legacy; prefer SHA-256+.
    pub hash_sha1: Option<String>,
    /// SHA-256 hex digest (256-bit / 64 hex chars).  Primary identification hash.
    pub hash_sha256: Option<String>,
    /// SHA-512 hex digest (512-bit / 128 hex chars).
    pub hash_sha512: Option<String>,
    /// CRC-32 hex value (32-bit / 8 hex chars).  Fast integrity check.
    pub hash_crc32: Option<String>,
    /// XXH3 (128-bit) hex digest — extremely fast non-cryptographic hash.
    pub hash_xxhash3: Option<String>,
    /// BLAKE3 hex digest (256-bit / 64 hex chars).
    pub hash_blake3: Option<String>,

    // ── Entropy & Magic ───────────────────────────────────────────────────────
    /// Shannon entropy of the file content (range 0.0–8.0 bits per byte).
    pub shannon_entropy: Option<f64>,
    /// Human-readable entropy classification produced by [`entropy_class`].
    pub entropy_classification: Option<String>,
    /// First 16 bytes of the file as an upper-case hex string.
    pub magic_bytes_hex: Option<String>,
    /// MIME type inferred from magic bytes, e.g. `"application/pdf"`.
    pub magic_mime_type: Option<String>,
    /// Textual description from magic database, e.g. `"PDF document, version 1.7"`.
    pub magic_description: Option<String>,
    /// Heuristic flag: `true` when entropy ≥ 7.2 or known packer signatures found.
    pub is_packed_or_encrypted: Option<bool>,

    // ── EXIF / Image ──────────────────────────────────────────────────────────
    /// Camera/scanner manufacturer (EXIF tag 0x010F Make).
    pub exif_make: Option<String>,
    /// Camera/scanner model name (EXIF tag 0x0110 Model).
    pub exif_model: Option<String>,
    /// Camera body serial number if stored (EXIF tag 0xA431 BodySerialNumber).
    pub exif_serial_number: Option<String>,
    /// Lens model description (EXIF tag 0xA434 LensModel).
    pub exif_lens_model: Option<String>,
    /// Focal length in millimetres (EXIF tag 0x920A FocalLength).
    pub exif_focal_length: Option<f64>,
    /// 35 mm-equivalent focal length (EXIF tag 0xA405 FocalLengthIn35mmFilm).
    pub exif_focal_length_35mm: Option<f64>,
    /// Aperture as F-number (EXIF tag 0x829D FNumber).
    pub exif_f_number: Option<f64>,
    /// Exposure time as a fraction string, e.g. `"1/1000"` (EXIF tag 0x829A).
    pub exif_exposure_time: Option<String>,
    /// ISO sensitivity value (EXIF tag 0x8827 ISOSpeedRatings).
    pub exif_iso: Option<u32>,
    /// Exposure program descriptor, e.g. `"Aperture priority"`.
    pub exif_exposure_program: Option<String>,
    /// Metering mode, e.g. `"Multi-segment"`.
    pub exif_metering_mode: Option<String>,
    /// Flash status descriptor.
    pub exif_flash: Option<String>,
    /// White balance mode (`"Auto"` / `"Manual"`).
    pub exif_white_balance: Option<String>,
    /// Colour space tag, e.g. `"sRGB"`.
    pub exif_color_space: Option<String>,
    /// Image orientation descriptor, e.g. `"Horizontal (normal)"`.
    pub exif_orientation: Option<String>,
    /// Horizontal resolution in dots-per-unit (EXIF tag 0x011A XResolution).
    pub exif_x_resolution: Option<f64>,
    /// Vertical resolution in dots-per-unit (EXIF tag 0x011B YResolution).
    pub exif_y_resolution: Option<f64>,
    /// Bits per sample / colour channel (EXIF tag 0x0102 BitsPerSample).
    pub exif_bits_per_sample: Option<u32>,
    /// Compression scheme descriptor, e.g. `"JPEG"`.
    pub exif_compression: Option<String>,
    /// Original capture date-time (EXIF tag 0x9003 DateTimeOriginal), UTC ISO-8601.
    pub exif_datetime_original: Option<String>,
    /// Digitisation date-time (EXIF tag 0x9004 DateTimeDigitized), UTC ISO-8601.
    pub exif_datetime_digitized: Option<String>,
    /// Software used to create/edit the image (EXIF tag 0x0131 Software).
    pub exif_software: Option<String>,
    /// Artist/creator name (EXIF tag 0x013B Artist).
    pub exif_artist: Option<String>,
    /// Copyright notice (EXIF tag 0x8298 Copyright).
    pub exif_copyright: Option<String>,
    /// Image pixel width (EXIF tag 0xA002 PixelXDimension).
    pub exif_image_width: Option<u32>,
    /// Image pixel height (EXIF tag 0xA003 PixelYDimension).
    pub exif_image_height: Option<u32>,
    /// Byte offset of the embedded JPEG thumbnail within the EXIF blob.
    pub exif_thumbnail_offset: Option<u64>,
    /// Length in bytes of the embedded JPEG thumbnail.
    pub exif_thumbnail_length: Option<u64>,
    /// ICC colour profile description extracted from the image.
    pub exif_profile_icc: Option<String>,
    /// Subject distance in metres (EXIF tag 0x9206 SubjectDistance).
    pub exif_subject_distance: Option<f64>,

    // ── GPS ───────────────────────────────────────────────────────────────────
    /// WGS-84 decimal latitude (positive = North).
    pub gps_latitude: Option<f64>,
    /// WGS-84 decimal longitude (positive = East).
    pub gps_longitude: Option<f64>,
    /// GPS altitude in metres above/below sea level.
    pub gps_altitude: Option<f64>,
    /// GPS altitude reference: `"Above sea level"` or `"Below sea level"`.
    pub gps_altitude_ref: Option<String>,
    /// GPS ground speed value.
    pub gps_speed: Option<f64>,
    /// GPS speed unit reference: `"K"` (km/h), `"M"` (mph), `"N"` (knots).
    pub gps_speed_ref: Option<String>,
    /// Image direction in degrees from reference.
    pub gps_direction: Option<f64>,
    /// Image direction reference: `"T"` (true north) or `"M"` (magnetic).
    pub gps_direction_ref: Option<String>,
    /// GPS fix time as UTC string `"HH:MM:SS"`.
    pub gps_timestamp: Option<String>,
    /// GPS fix date as `"YYYY:MM:DD"`.
    pub gps_datestamp: Option<String>,
    /// Dilution of precision (lower = more accurate).
    pub gps_dop: Option<f64>,
    /// Satellite constellation description string.
    pub gps_satellites: Option<String>,

    // ── PDF Specific ──────────────────────────────────────────────────────────
    /// PDF specification version string, e.g. `"1.7"`.
    pub pdf_version: Option<String>,
    /// `/Producer` metadata field — the library/tool that wrote the PDF.
    pub pdf_producer: Option<String>,
    /// `/Creator` metadata field — the application that created the source document.
    pub pdf_creator_app: Option<String>,
    /// Document creation date from PDF info dictionary, UTC ISO-8601.
    pub pdf_creation_date: Option<String>,
    /// Document last-modification date, UTC ISO-8601.
    pub pdf_modification_date: Option<String>,
    /// `/Author` metadata field.
    pub pdf_author: Option<String>,
    /// `/Title` metadata field.
    pub pdf_title: Option<String>,
    /// `/Subject` metadata field.
    pub pdf_subject: Option<String>,
    /// `/Keywords` metadata field.
    pub pdf_keywords: Option<String>,
    /// Number of pages in the document.
    pub pdf_page_count: Option<u32>,
    /// Whether the PDF is encrypted with a user or owner password.
    pub pdf_is_encrypted: Option<bool>,
    /// Whether the PDF contains interactive AcroForm or XFA form fields.
    pub pdf_has_forms: Option<bool>,
    /// Whether the PDF contains annotation objects.
    pub pdf_has_annotations: Option<bool>,
    /// Whether the PDF has embedded file attachments (`/EmbeddedFiles`).
    pub pdf_has_embedded_files: Option<bool>,
    /// Status of the PDF's digital signature(s).
    pub pdf_signature_status: Option<PdfSignatureStatus>,

    // ── PE / Executable ───────────────────────────────────────────────────────
    /// Human-readable CPU architecture, e.g. `"x86_64"`, `"ARM64"`.
    pub pe_architecture: Option<String>,
    /// Raw `IMAGE_FILE_HEADER.Machine` value (e.g. `0x8664` for AMD64).
    pub pe_machine_type: Option<u16>,
    /// `TimeDateStamp` from the PE COFF header, formatted as UTC ISO-8601.
    pub pe_compile_timestamp: Option<String>,
    /// Raw `TimeDateStamp` as a Unix epoch `u32`.
    pub pe_compile_timestamp_raw: Option<u32>,
    /// Number of section headers in the PE (`IMAGE_FILE_HEADER.NumberOfSections`).
    pub pe_section_count: Option<String>,
    /// Number of imported functions across all import descriptor entries.
    pub pe_import_count: Option<String>,
    /// Number of entries in the export directory.
    pub pe_export_count: Option<String>,
    /// Subsystem string, e.g. `"Windows GUI"`, `"Windows CUI"`, `"EFI"`.
    pub pe_subsystem: Option<String>,
    /// Whether `IMAGE_FILE_DLL` characteristic flag is set.
    pub pe_is_dll: Option<bool>,
    /// Heuristic: subsystem is `Native` and imports from `ntoskrnl` / `hal`.
    pub pe_is_driver: Option<bool>,
    /// Virtual address of the entry point (`AddressOfEntryPoint`).
    pub pe_entry_point: Option<u64>,
    /// Preferred load address (`ImageBase`).
    pub pe_image_base: Option<u64>,
    /// Linker version string (`MajorLinkerVersion.MinorLinkerVersion`).
    pub pe_linker_version: Option<String>,
    /// Required OS version (`MajorOperatingSystemVersion.MinorOperatingSystemVersion`).
    pub pe_os_version: Option<String>,
    /// PE optional-header checksum field value.
    pub pe_checksum: Option<u32>,
    /// Authenticode code-signing status.
    pub pe_authenticode_status: Option<PeAuthenticodeStatus>,
    /// Common Name from the signing certificate's Subject field.
    pub pe_signer_name: Option<String>,
    /// SHA-1 thumbprint of the signing certificate (hex, 40 chars).
    pub pe_signer_thumbprint: Option<String>,
    /// Import-hash (MD5 of the normalised import table), used for threat intel.
    pub pe_imphash: Option<String>,
    /// Highest Shannon entropy value among all PE sections (0.0–8.0).
    pub pe_section_max_entropy: Option<f64>,

    // ── Video & Audio ─────────────────────────────────────────────────────────
    /// Total media duration in fractional seconds.
    pub media_duration_seconds: Option<f64>,
    /// Human-readable duration, e.g. `"1:23:45"`.
    pub media_duration_human: Option<String>,
    /// Video codec identifier, e.g. `"H.264"`, `"HEVC"`, `"AV1"`.
    pub video_codec: Option<String>,
    /// Video frame width in pixels.
    pub video_width: Option<u32>,
    /// Video frame height in pixels.
    pub video_height: Option<u32>,
    /// Video frame rate in frames per second.
    pub video_frame_rate: Option<f64>,
    /// Colour bit depth per channel (e.g. 8, 10, 12).
    pub video_bit_depth: Option<u32>,
    /// Colour primaries descriptor (e.g. `"BT.709"`, `"BT.2020"`).
    pub video_color_primaries: Option<String>,
    /// OETF / transfer characteristics (e.g. `"BT.709"`, `"PQ"`, `"HLG"`).
    pub video_transfer_characteristics: Option<String>,
    /// Average video stream bitrate in kilobits per second.
    pub video_bitrate_kbps: Option<u64>,
    /// Audio codec identifier, e.g. `"AAC"`, `"MP3"`, `"FLAC"`, `"PCM"`.
    pub audio_codec: Option<String>,
    /// Audio sampling rate in Hz, e.g. `44100`, `48000`.
    pub audio_sample_rate: Option<u32>,
    /// Number of audio channels (1=mono, 2=stereo, 6=5.1, …).
    pub audio_channels: Option<u8>,
    /// Average audio stream bitrate in kilobits per second.
    pub audio_bitrate_kbps: Option<u64>,
    /// Audio quantisation depth per sample, e.g. 16, 24, 32.
    pub audio_bits_per_sample: Option<u32>,
    /// Number of distinct audio tracks in the container.
    pub audio_track_count: Option<u32>,
    /// Container format descriptor, e.g. `"MP4"`, `"MKV"`, `"MOV"`.
    pub media_container_format: Option<String>,
    /// Encoder tool string stored in container metadata.
    pub media_encoder: Option<String>,
    /// Clockwise rotation in degrees stored in container rotation matrix.
    pub media_rotation: Option<f64>,
    /// Whether the video stream uses an HDR transfer function (PQ or HLG).
    pub media_is_hdr: Option<bool>,

    // ── Office Documents ──────────────────────────────────────────────────────
    /// Document author from core properties (`dc:creator`).
    pub doc_author: Option<String>,
    /// Name of the user who last saved the document (`cp:lastModifiedBy`).
    pub doc_last_modified_by: Option<String>,
    /// Document title (`dc:title`).
    pub doc_title: Option<String>,
    /// Document subject (`dc:subject`).
    pub doc_subject: Option<String>,
    /// Document description / comments (`dc:description`).
    pub doc_description: Option<String>,
    /// Comma-separated keyword list (`cp:keywords`).
    pub doc_keywords: Option<String>,
    /// Content category (`cp:category`).
    pub doc_category: Option<String>,
    /// Authoring organisation (`app:Company`).
    pub doc_company: Option<String>,
    /// Document creation timestamp, UTC ISO-8601 (`dcterms:created`).
    pub doc_created_date: Option<String>,
    /// Last-modified timestamp, UTC ISO-8601 (`dcterms:modified`).
    pub doc_modified_date: Option<String>,
    /// Timestamp of last print job, UTC ISO-8601 (`cp:lastPrinted`).
    pub doc_last_printed_date: Option<String>,
    /// Cumulative revision / save count (`cp:revision`).
    pub doc_revision_count: Option<u32>,
    /// Total accumulated editing duration in minutes (`cp:totalEditingTime`).
    pub doc_edit_time_minutes: Option<u64>,
    /// Number of pages (`Pages` or `Slides` extended property).
    pub doc_page_count: Option<u32>,
    /// Word count from extended properties.
    pub doc_word_count: Option<u32>,
    /// Character count (without spaces) from extended properties.
    pub doc_character_count: Option<u32>,
    /// Line count from extended properties.
    pub doc_line_count: Option<u32>,
    /// Paragraph count from extended properties.
    pub doc_paragraph_count: Option<u32>,
    /// Number of slides (PowerPoint).
    pub doc_slide_count: Option<u32>,
    /// Number of sheets (Excel).
    pub doc_sheet_count: Option<u32>,

    // ── Forensic Conclusions ──────────────────────────────────────────────────
    /// Free-text forensic observations generated by analysis passes.
    pub forensic_notes: Option<Vec<String>>,
    /// Aggregate suspect flag: `true` if any heuristic fired.
    pub is_suspect: Option<bool>,
    /// UTC ISO-8601 timestamp of when this record was created by the scanner.
    pub scan_timestamp_utc: Option<String>,
    /// Semver string of the parser module that produced this record.
    pub parser_version: Option<String>,
    /// Non-fatal errors encountered while parsing this file.
    pub parse_errors: Option<Vec<String>>,
    /// Wall-clock time in milliseconds taken to fully parse this file.
    pub parse_duration_ms: Option<u64>,
    /// Top-level file category, e.g. `"Image"`, `"Document"`, `"Executable"`.
    pub file_type_category: Option<String>,
    /// More specific sub-type, e.g. `"JPEG"`, `"PDF 1.7"`, `"PE64"`.
    pub file_type_subcategory: Option<String>,
    /// Arbitrary key-value annotations added by plugins or the analyst.
    pub custom_tags: Option<HashMap<String, String>>,
    /// SHA-256 hash of a canonical JSON serialisation of this record, used to
    /// detect accidental or malicious post-scan tampering of the database.
    // ── 174 Legacy Parity Fields ──────────────────────────────────────────
    /// Legacy 174 Parity: File Size (Bytes) (File System)
    pub file_size_bytes: Option<String>,
    /// Legacy 174 Parity: File Size (Human) (File System)
    pub file_size_human: Option<String>,
    /// Legacy 174 Parity: Creation Date (File System)
    pub creation_date: Option<String>,
    /// Legacy 174 Parity: Modification Date (File System)
    pub modification_date: Option<String>,
    /// Legacy 174 Parity: Access Date (File System)
    pub access_date: Option<String>,
    /// Legacy 174 Parity: MIME Type (File System)
    pub mime_type: Option<String>,
    /// Legacy 174 Parity: File Permissions (File System)
    pub file_permissions: Option<String>,
    /// Legacy 174 Parity: Is Read-Only (File System)
    pub is_read_only: Option<String>,
    /// Legacy 174 Parity: Is Symlink (File System)
    pub is_symlink: Option<String>,
    /// Legacy 174 Parity: Owner (Windows) (File System)
    pub owner_windows: Option<String>,
    /// Legacy 174 Parity: MD5 Hash (Hashes & Checksums)
    pub md5_hash: Option<String>,
    /// Legacy 174 Parity: SHA1 Hash (Hashes & Checksums)
    pub sha1_hash: Option<String>,
    /// Legacy 174 Parity: SHA224 Hash (Hashes & Checksums)
    pub sha224_hash: Option<String>,
    /// Legacy 174 Parity: SHA256 Hash (Hashes & Checksums)
    pub sha256_hash: Option<String>,
    /// Legacy 174 Parity: SHA384 Hash (Hashes & Checksums)
    pub sha384_hash: Option<String>,
    /// Legacy 174 Parity: SHA512 Hash (Hashes & Checksums)
    pub sha512_hash: Option<String>,
    /// Legacy 174 Parity: SHA3-224 Hash (Hashes & Checksums)
    pub sha3_224_hash: Option<String>,
    /// Legacy 174 Parity: SHA3-256 Hash (Hashes & Checksums)
    pub sha3_256_hash: Option<String>,
    /// Legacy 174 Parity: SHA3-384 Hash (Hashes & Checksums)
    pub sha3_384_hash: Option<String>,
    /// Legacy 174 Parity: SHA3-512 Hash (Hashes & Checksums)
    pub sha3_512_hash: Option<String>,
    /// Legacy 174 Parity: BLAKE2b Hash (Hashes & Checksums)
    pub blake2b_hash: Option<String>,
    /// Legacy 174 Parity: BLAKE2s Hash (Hashes & Checksums)
    pub blake2s_hash: Option<String>,
    /// Legacy 174 Parity: CRC32 (Hashes & Checksums)
    pub crc32: Option<String>,
    /// Legacy 174 Parity: Adler32 (Hashes & Checksums)
    pub adler32: Option<String>,
    /// Legacy 174 Parity: xxHash64 (Hashes & Checksums)
    pub xxhash64: Option<String>,
    /// Legacy 174 Parity: Image Width (Image / EXIF)
    pub image_width: Option<String>,
    /// Legacy 174 Parity: Image Height (Image / EXIF)
    pub image_height: Option<String>,
    /// Legacy 174 Parity: Resolution (DPI) (Image / EXIF)
    pub resolution_dpi: Option<String>,
    /// Legacy 174 Parity: Bit Depth (Image / EXIF)
    pub bit_depth: Option<String>,
    /// Legacy 174 Parity: Color Space (Image / EXIF)
    pub color_space: Option<String>,
    /// Legacy 174 Parity: Color Profile (Image / EXIF)
    pub color_profile: Option<String>,
    /// Legacy 174 Parity: Orientation (Image / EXIF)
    pub orientation: Option<String>,
    /// Legacy 174 Parity: Compression (Image / EXIF)
    pub compression: Option<String>,
    /// Legacy 174 Parity: Has Alpha Channel (Image / EXIF)
    pub has_alpha_channel: Option<String>,
    /// Legacy 174 Parity: Megapixels (Image / EXIF)
    pub megapixels: Option<String>,
    /// Legacy 174 Parity: EXIF Version (Image / EXIF)
    pub exif_version: Option<String>,
    /// Legacy 174 Parity: Date Taken (Original) (Image / EXIF)
    pub date_taken_original: Option<String>,
    /// Legacy 174 Parity: Date Digitized (Image / EXIF)
    pub date_digitized: Option<String>,
    /// Legacy 174 Parity: Software (Image / EXIF)
    pub software: Option<String>,
    /// Legacy 174 Parity: Host Computer (Image / EXIF)
    pub host_computer: Option<String>,
    /// Legacy 174 Parity: Description / Caption (Image / EXIF)
    pub description_caption: Option<String>,
    /// Legacy 174 Parity: User Comment (Image / EXIF)
    pub user_comment: Option<String>,
    /// Legacy 174 Parity: Copyright (Image / EXIF)
    pub copyright: Option<String>,
    /// Legacy 174 Parity: Artist / Author (Image / EXIF)
    pub artist_author: Option<String>,
    /// Legacy 174 Parity: Rating (Image / EXIF)
    pub rating: Option<String>,
    /// Legacy 174 Parity: Camera Make (Camera / Lens)
    pub camera_make: Option<String>,
    /// Legacy 174 Parity: Camera Model (Camera / Lens)
    pub camera_model: Option<String>,
    /// Legacy 174 Parity: Camera Serial (Camera / Lens)
    pub camera_serial: Option<String>,
    /// Legacy 174 Parity: Lens Model (Camera / Lens)
    pub lens_model: Option<String>,
    /// Legacy 174 Parity: Lens Make (Camera / Lens)
    pub lens_make: Option<String>,
    /// Legacy 174 Parity: Lens Serial (Camera / Lens)
    pub lens_serial: Option<String>,
    /// Legacy 174 Parity: Lens Focal Length (Camera / Lens)
    pub lens_focal_length: Option<String>,
    /// Legacy 174 Parity: Lens Max Aperture (Camera / Lens)
    pub lens_max_aperture: Option<String>,
    /// Legacy 174 Parity: ISO (Camera / Lens)
    pub iso: Option<String>,
    /// Legacy 174 Parity: Exposure Time (Camera / Lens)
    pub exposure_time: Option<String>,
    /// Legacy 174 Parity: F-Stop (Camera / Lens)
    pub f_stop: Option<String>,
    /// Legacy 174 Parity: Exposure Program (Camera / Lens)
    pub exposure_program: Option<String>,
    /// Legacy 174 Parity: Exposure Mode (Camera / Lens)
    pub exposure_mode: Option<String>,
    /// Legacy 174 Parity: Exposure Compensation (Camera / Lens)
    pub exposure_compensation: Option<String>,
    /// Legacy 174 Parity: Metering Mode (Camera / Lens)
    pub metering_mode: Option<String>,
    /// Legacy 174 Parity: Flash (Camera / Lens)
    pub flash: Option<String>,
    /// Legacy 174 Parity: Flash Mode (Camera / Lens)
    pub flash_mode: Option<String>,
    /// Legacy 174 Parity: White Balance (Camera / Lens)
    pub white_balance: Option<String>,
    /// Legacy 174 Parity: Focus Mode (Camera / Lens)
    pub focus_mode: Option<String>,
    /// Legacy 174 Parity: Focus Distance (Camera / Lens)
    pub focus_distance: Option<String>,
    /// Legacy 174 Parity: Scene Type (Camera / Lens)
    pub scene_type: Option<String>,
    /// Legacy 174 Parity: Shutter Count (Camera / Lens)
    pub shutter_count: Option<String>,
    /// Legacy 174 Parity: Digital Zoom Ratio (Camera / Lens)
    pub digital_zoom_ratio: Option<String>,
    /// Legacy 174 Parity: GPS Latitude Ref (GPS / Location)
    pub gps_latitude_ref: Option<String>,
    /// Legacy 174 Parity: GPS Longitude Ref (GPS / Location)
    pub gps_longitude_ref: Option<String>,
    /// Legacy 174 Parity: GPS Date (GPS / Location)
    pub gps_date: Option<String>,
    /// Legacy 174 Parity: GPS Map Datum (GPS / Location)
    pub gps_map_datum: Option<String>,
    /// Legacy 174 Parity: GPS Coordinates (DMS) (GPS / Location)
    pub gps_coordinates_dms: Option<String>,
    /// Legacy 174 Parity: Video Bitrate (Video)
    pub video_bitrate: Option<String>,
    /// Legacy 174 Parity: Video Duration (Video)
    pub video_duration: Option<String>,
    /// Legacy 174 Parity: Aspect Ratio (Video)
    pub aspect_ratio: Option<String>,
    /// Legacy 174 Parity: Rotation (Video)
    pub rotation: Option<String>,
    /// Legacy 174 Parity: Audio Codec (Video) (Video)
    pub audio_codec_video: Option<String>,
    /// Legacy 174 Parity: Audio Channels (Video) (Video)
    pub audio_channels_video: Option<String>,
    /// Legacy 174 Parity: Audio Sample Rate (Video) (Video)
    pub audio_sample_rate_video: Option<String>,
    /// Legacy 174 Parity: Audio Bitrate (Video) (Video)
    pub audio_bitrate_video: Option<String>,
    /// Legacy 174 Parity: Total Bitrate (Video)
    pub total_bitrate: Option<String>,
    /// Legacy 174 Parity: Container Format (Video)
    pub container_format: Option<String>,
    /// Legacy 174 Parity: Encoder (Video)
    pub encoder: Option<String>,
    /// Legacy 174 Parity: Video Creation Date (Video)
    pub video_creation_date: Option<String>,
    /// Legacy 174 Parity: Video Track Count (Video)
    pub video_track_count: Option<String>,
    /// Legacy 174 Parity: Subtitle Track Count (Video)
    pub subtitle_track_count: Option<String>,
    /// Legacy 174 Parity: Chapter Count (Video)
    pub chapter_count: Option<String>,
    /// Legacy 174 Parity: Audio Title (Audio)
    pub audio_title: Option<String>,
    /// Legacy 174 Parity: Audio Artist (Audio)
    pub audio_artist: Option<String>,
    /// Legacy 174 Parity: Audio Album (Audio)
    pub audio_album: Option<String>,
    /// Legacy 174 Parity: Audio Album Artist (Audio)
    pub audio_album_artist: Option<String>,
    /// Legacy 174 Parity: Audio Genre (Audio)
    pub audio_genre: Option<String>,
    /// Legacy 174 Parity: Audio Year (Audio)
    pub audio_year: Option<String>,
    /// Legacy 174 Parity: Audio Track Number (Audio)
    pub audio_track_number: Option<String>,
    /// Legacy 174 Parity: Audio Disc Number (Audio)
    pub audio_disc_number: Option<String>,
    /// Legacy 174 Parity: Audio Composer (Audio)
    pub audio_composer: Option<String>,
    /// Legacy 174 Parity: Audio Duration (Audio)
    pub audio_duration: Option<String>,
    /// Legacy 174 Parity: Audio Bitrate (Audio)
    pub audio_bitrate: Option<String>,
    /// Legacy 174 Parity: Audio Bit Depth (Audio)
    pub audio_bit_depth: Option<String>,
    /// Legacy 174 Parity: Audio BPM (Audio)
    pub audio_bpm: Option<String>,
    /// Legacy 174 Parity: Audio Comment (Audio)
    pub audio_comment: Option<String>,
    /// Legacy 174 Parity: Audio Lyrics (Audio)
    pub audio_lyrics: Option<String>,
    /// Legacy 174 Parity: Audio Publisher / Label (Audio)
    pub audio_publisher_label: Option<String>,
    /// Legacy 174 Parity: Audio Encoder (Audio)
    pub audio_encoder: Option<String>,
    /// Legacy 174 Parity: Has Album Art (Audio)
    pub has_album_art: Option<String>,
    /// Legacy 174 Parity: Album Art Size (Audio)
    pub album_art_size: Option<String>,
    /// Legacy 174 Parity: Audio ReplayGain (Audio)
    pub audio_replaygain: Option<String>,
    /// Legacy 174 Parity: Document Title (Documents)
    pub document_title: Option<String>,
    /// Legacy 174 Parity: Document Author (Documents)
    pub document_author: Option<String>,
    /// Legacy 174 Parity: Document Subject (Documents)
    pub document_subject: Option<String>,
    /// Legacy 174 Parity: Document Keywords (Documents)
    pub document_keywords: Option<String>,
    /// Legacy 174 Parity: Document Creator App (Documents)
    pub document_creator_app: Option<String>,
    /// Legacy 174 Parity: Document Producer (Documents)
    pub document_producer: Option<String>,
    /// Legacy 174 Parity: Document Creation Date (Documents)
    pub document_creation_date: Option<String>,
    /// Legacy 174 Parity: Document Modification Date (Documents)
    pub document_modification_date: Option<String>,
    /// Legacy 174 Parity: Document Page Count (Documents)
    pub document_page_count: Option<String>,
    /// Legacy 174 Parity: Document Word Count (Documents)
    pub document_word_count: Option<String>,
    /// Legacy 174 Parity: Document Character Count (Documents)
    pub document_character_count: Option<String>,
    /// Legacy 174 Parity: Document Line Count (Documents)
    pub document_line_count: Option<String>,
    /// Legacy 174 Parity: Document Paragraph Count (Documents)
    pub document_paragraph_count: Option<String>,
    /// Legacy 174 Parity: Document Slide Count (Documents)
    pub document_slide_count: Option<String>,
    /// Legacy 174 Parity: Document Sheet Count (Documents)
    pub document_sheet_count: Option<String>,
    /// Legacy 174 Parity: Document Revision (Documents)
    pub document_revision: Option<String>,
    /// Legacy 174 Parity: Document Last Author (Documents)
    pub document_last_author: Option<String>,
    /// Legacy 174 Parity: Document Company (Documents)
    pub document_company: Option<String>,
    /// Legacy 174 Parity: Document Manager (Documents)
    pub document_manager: Option<String>,
    /// Legacy 174 Parity: Document Category (Documents)
    pub document_category: Option<String>,
    /// Legacy 174 Parity: Document Language (Documents)
    pub document_language: Option<String>,
    /// Legacy 174 Parity: Document Template (Documents)
    pub document_template: Option<String>,
    /// Legacy 174 Parity: Document Comments (Documents)
    pub document_comments: Option<String>,
    /// Legacy 174 Parity: PDF Encrypted (PDF Specific)
    pub pdf_encrypted: Option<String>,
    /// Legacy 174 Parity: PDF Has Signatures (PDF Specific)
    pub pdf_has_signatures: Option<String>,
    /// Legacy 174 Parity: PDF Page Size (PDF Specific)
    pub pdf_page_size: Option<String>,
    /// Legacy 174 Parity: PDF Creator (PDF Specific)
    pub pdf_creator: Option<String>,
    /// Legacy 174 Parity: PDF Linearized (PDF Specific)
    pub pdf_linearized: Option<String>,
    /// Legacy 174 Parity: PDF Tagged (PDF Specific)
    pub pdf_tagged: Option<String>,
    /// Legacy 174 Parity: File Entropy (Forensics / PE)
    pub file_entropy: Option<String>,
    /// Legacy 174 Parity: Magic Bytes (Header) (Forensics / PE)
    pub magic_bytes_header: Option<String>,
    /// Legacy 174 Parity: PE Compile Date (Forensics / PE)
    pub pe_compile_date: Option<String>,
    /// Legacy 174 Parity: PE Signed (Forensics / PE)
    pub pe_signed: Option<String>,
    /// Legacy 174 Parity: PE Original Filename (Forensics / PE)
    pub pe_original_filename: Option<String>,
    /// Legacy 174 Parity: PE Product Name (Forensics / PE)
    pub pe_product_name: Option<String>,
    /// Legacy 174 Parity: PE Product Version (Forensics / PE)
    pub pe_product_version: Option<String>,
    /// Legacy 174 Parity: PE Company Name (Forensics / PE)
    pub pe_company_name: Option<String>,
    /// Legacy 174 Parity: PE File Version (Forensics / PE)
    pub pe_file_version: Option<String>,
    /// Legacy 174 Parity: PE Description (Forensics / PE)
    pub pe_description: Option<String>,
    pub row_hash: Option<String>,
}

impl FileMetadata {
    /// Construct a new `FileMetadata` with `id` set and every other field `None`.
    ///
    /// The caller is expected to populate fields incrementally as each analysis
    /// pass completes.  Using `None` rather than a sentinel value (e.g. `""`)
    /// makes it unambiguous whether a field was simply not computed.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            file_name: None,
            file_extension: None,
            file_path: None,
            parent_directory: None,
            size_bytes: None,
            size_human: None,
            file_attributes_raw: None,
            is_readonly: None,
            is_hidden: None,
            is_system: None,
            is_archive: None,
            is_temporary: None,
            is_compressed: None,
            is_encrypted_flag: None,
            macb: None,
            timestomp_suspect: None,
            inode_number: None,
            link_count: None,
            ads_zone_id: None,
            ads_host_url: None,
            ads_referrer_url: None,
            ads_names: None,
            mft_record_number: None,
            usn_journal_id: None,
            volume_serial: None,
            reparse_tag: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            hash_sha512: None,
            hash_crc32: None,
            hash_xxhash3: None,
            hash_blake3: None,
            shannon_entropy: None,
            entropy_classification: None,
            magic_bytes_hex: None,
            magic_mime_type: None,
            magic_description: None,
            is_packed_or_encrypted: None,
            exif_make: None,
            exif_model: None,
            exif_serial_number: None,
            exif_lens_model: None,
            exif_focal_length: None,
            exif_focal_length_35mm: None,
            exif_f_number: None,
            exif_exposure_time: None,
            exif_iso: None,
            exif_exposure_program: None,
            exif_metering_mode: None,
            exif_flash: None,
            exif_white_balance: None,
            exif_color_space: None,
            exif_orientation: None,
            exif_x_resolution: None,
            exif_y_resolution: None,
            exif_bits_per_sample: None,
            exif_compression: None,
            exif_datetime_original: None,
            exif_datetime_digitized: None,
            exif_software: None,
            exif_artist: None,
            exif_copyright: None,
            exif_image_width: None,
            exif_image_height: None,
            exif_thumbnail_offset: None,
            exif_thumbnail_length: None,
            exif_profile_icc: None,
            exif_subject_distance: None,
            gps_latitude: None,
            gps_longitude: None,
            gps_altitude: None,
            gps_altitude_ref: None,
            gps_speed: None,
            gps_speed_ref: None,
            gps_direction: None,
            gps_direction_ref: None,
            gps_timestamp: None,
            gps_datestamp: None,
            gps_dop: None,
            gps_satellites: None,
            pdf_version: None,
            pdf_producer: None,
            pdf_creator_app: None,
            pdf_creation_date: None,
            pdf_modification_date: None,
            pdf_author: None,
            pdf_title: None,
            pdf_subject: None,
            pdf_keywords: None,
            pdf_page_count: None,
            pdf_is_encrypted: None,
            pdf_has_forms: None,
            pdf_has_annotations: None,
            pdf_has_embedded_files: None,
            pdf_signature_status: None,
            pe_architecture: None,
            pe_machine_type: None,
            pe_compile_timestamp: None,
            pe_compile_timestamp_raw: None,
            pe_section_count: None,
            pe_import_count: None,
            pe_export_count: None,
            pe_subsystem: None,
            pe_is_dll: None,
            pe_is_driver: None,
            pe_entry_point: None,
            pe_image_base: None,
            pe_linker_version: None,
            pe_os_version: None,
            pe_checksum: None,
            pe_authenticode_status: None,
            pe_signer_name: None,
            pe_signer_thumbprint: None,
            pe_imphash: None,
            pe_section_max_entropy: None,
            media_duration_seconds: None,
            media_duration_human: None,
            video_codec: None,
            video_width: None,
            video_height: None,
            video_frame_rate: None,
            video_bit_depth: None,
            video_color_primaries: None,
            video_transfer_characteristics: None,
            video_bitrate_kbps: None,
            audio_codec: None,
            audio_sample_rate: None,
            audio_channels: None,
            audio_bitrate_kbps: None,
            audio_bits_per_sample: None,
            audio_track_count: None,
            media_container_format: None,
            media_encoder: None,
            media_rotation: None,
            media_is_hdr: None,
            doc_author: None,
            doc_last_modified_by: None,
            doc_title: None,
            doc_subject: None,
            doc_description: None,
            doc_keywords: None,
            doc_category: None,
            doc_company: None,
            doc_created_date: None,
            doc_modified_date: None,
            doc_last_printed_date: None,
            doc_revision_count: None,
            doc_edit_time_minutes: None,
            doc_page_count: None,
            doc_word_count: None,
            doc_character_count: None,
            doc_line_count: None,
            doc_paragraph_count: None,
            doc_slide_count: None,
            doc_sheet_count: None,
            forensic_notes: None,
            is_suspect: None,
            scan_timestamp_utc: None,
            parser_version: None,
            parse_errors: None,
            parse_duration_ms: None,
            file_type_category: None,
            file_type_subcategory: None,
            custom_tags: None,
            // 174 Legacy Parity Initializers
            file_size_bytes: None,
            file_size_human: None,
            creation_date: None,
            modification_date: None,
            access_date: None,
            mime_type: None,
            file_permissions: None,
            is_read_only: None,
            is_symlink: None,
            owner_windows: None,
            md5_hash: None,
            sha1_hash: None,
            sha224_hash: None,
            sha256_hash: None,
            sha384_hash: None,
            sha512_hash: None,
            sha3_224_hash: None,
            sha3_256_hash: None,
            sha3_384_hash: None,
            sha3_512_hash: None,
            blake2b_hash: None,
            blake2s_hash: None,
            crc32: None,
            adler32: None,
            xxhash64: None,
            image_width: None,
            image_height: None,
            resolution_dpi: None,
            bit_depth: None,
            color_space: None,
            color_profile: None,
            orientation: None,
            compression: None,
            has_alpha_channel: None,
            megapixels: None,
            exif_version: None,
            date_taken_original: None,
            date_digitized: None,
            software: None,
            host_computer: None,
            description_caption: None,
            user_comment: None,
            copyright: None,
            artist_author: None,
            rating: None,
            camera_make: None,
            camera_model: None,
            camera_serial: None,
            lens_model: None,
            lens_make: None,
            lens_serial: None,
            lens_focal_length: None,
            lens_max_aperture: None,
            iso: None,
            exposure_time: None,
            f_stop: None,
            exposure_program: None,
            exposure_mode: None,
            exposure_compensation: None,
            metering_mode: None,
            flash: None,
            flash_mode: None,
            white_balance: None,
            focus_mode: None,
            focus_distance: None,
            scene_type: None,
            shutter_count: None,
            digital_zoom_ratio: None,
            gps_latitude_ref: None,
            gps_longitude_ref: None,
            gps_date: None,
            gps_map_datum: None,
            gps_coordinates_dms: None,
            video_bitrate: None,
            video_duration: None,
            aspect_ratio: None,
            rotation: None,
            audio_codec_video: None,
            audio_channels_video: None,
            audio_sample_rate_video: None,
            audio_bitrate_video: None,
            total_bitrate: None,
            container_format: None,
            encoder: None,
            video_creation_date: None,
            video_track_count: None,
            subtitle_track_count: None,
            chapter_count: None,
            audio_title: None,
            audio_artist: None,
            audio_album: None,
            audio_album_artist: None,
            audio_genre: None,
            audio_year: None,
            audio_track_number: None,
            audio_disc_number: None,
            audio_composer: None,
            audio_duration: None,
            audio_bitrate: None,
            audio_bit_depth: None,
            audio_bpm: None,
            audio_comment: None,
            audio_lyrics: None,
            audio_publisher_label: None,
            audio_encoder: None,
            has_album_art: None,
            album_art_size: None,
            audio_replaygain: None,
            document_title: None,
            document_author: None,
            document_subject: None,
            document_keywords: None,
            document_creator_app: None,
            document_producer: None,
            document_creation_date: None,
            document_modification_date: None,
            document_page_count: None,
            document_word_count: None,
            document_character_count: None,
            document_line_count: None,
            document_paragraph_count: None,
            document_slide_count: None,
            document_sheet_count: None,
            document_revision: None,
            document_last_author: None,
            document_company: None,
            document_manager: None,
            document_category: None,
            document_language: None,
            document_template: None,
            document_comments: None,
            pdf_encrypted: None,
            pdf_has_signatures: None,
            pdf_page_size: None,
            pdf_creator: None,
            pdf_linearized: None,
            pdf_tagged: None,
            file_entropy: None,
            magic_bytes_header: None,
            pe_compile_date: None,
            pe_signed: None,
            pe_original_filename: None,
            pe_product_name: None,
            pe_product_version: None,
            pe_company_name: None,
            pe_file_version: None,
            pe_description: None,
            row_hash: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 4  Helper functions
// ─────────────────────────────────────────────────────────────────────────────

/// Format a raw byte count into a human-readable string with an appropriate
/// binary-prefixed unit (B, KB, MB, GB, TB).
///
/// Uses 1024-based division.  Values are rounded to two decimal places except
/// plain bytes, which are shown as a whole number.
///
/// # Examples
/// ```rust
/// # use nexgen_metadata_lib::models::human_size;
/// assert_eq!(human_size(0),              "0 B");
/// assert_eq!(human_size(1023),           "1023 B");
/// assert_eq!(human_size(1024),           "1.00 KB");
/// assert_eq!(human_size(1_572_864),      "1.50 MB");
/// assert_eq!(human_size(5_368_709_120),  "5.00 GB");
/// ```
#[must_use]
pub fn human_size(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = KB * 1_024;
    const GB: u64 = MB * 1_024;
    const TB: u64 = GB * 1_024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Classify a Shannon entropy value (0.0–8.0 bits per byte) into a forensically
/// meaningful category string.
///
/// | Range        | Classification               | Typical content                    |
/// |--------------|------------------------------|------------------------------------|
/// | 0.0 – 1.0    | Plaintext (0-1)              | Sparse binary, null-padded buffers  |
/// | 1.0 – 5.0    | Text/Compressed (1-5)        | Text, source code, XML, HTML        |
/// | 5.0 – 7.5    | High Entropy (5-7.5)         | Compressed archives, media files    |
/// | 7.5 – 8.0    | Encrypted/Packed (7.5-8)     | Encrypted blobs, packed executables |
///
/// # Examples
/// ```rust
/// # use nexgen_metadata_lib::models::entropy_class;
/// assert_eq!(entropy_class(0.0),  "Plaintext (0-1)");
/// assert_eq!(entropy_class(3.5),  "Text/Compressed (1-5)");
/// assert_eq!(entropy_class(6.0),  "High Entropy (5-7.5)");
/// assert_eq!(entropy_class(7.9),  "Encrypted/Packed (7.5-8)");
/// ```
#[must_use]
pub fn entropy_class(entropy: f64) -> &'static str {
    if entropy < 1.0 {
        "Plaintext (0-1)"
    } else if entropy < 5.0 {
        "Text/Compressed (1-5)"
    } else if entropy < 7.5 {
        "High Entropy (5-7.5)"
    } else {
        "Encrypted/Packed (7.5-8)"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 5  Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_metadata_new_sets_id() {
        let m = FileMetadata::new(42);
        assert_eq!(m.id, 42);
        assert!(m.file_name.is_none());
        assert!(m.hash_sha256.is_none());
        assert!(m.pe_authenticode_status.is_none());
        assert!(m.custom_tags.is_none());
    }

    #[test]
    fn human_size_boundaries() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1_023), "1023 B");
        assert_eq!(human_size(1_024), "1.00 KB");
        assert_eq!(human_size(1_048_576), "1.00 MB");
        assert_eq!(human_size(1_073_741_824), "1.00 GB");
        assert_eq!(human_size(1_099_511_627_776), "1.00 TB");
        assert_eq!(human_size(1_572_864), "1.50 MB");
    }

    #[test]
    fn entropy_class_boundaries() {
        assert_eq!(entropy_class(0.0), "Plaintext (0-1)");
        assert_eq!(entropy_class(0.999), "Plaintext (0-1)");
        assert_eq!(entropy_class(1.0), "Text/Compressed (1-5)");
        assert_eq!(entropy_class(4.999), "Text/Compressed (1-5)");
        assert_eq!(entropy_class(5.0), "High Entropy (5-7.5)");
        assert_eq!(entropy_class(7.499), "High Entropy (5-7.5)");
        assert_eq!(entropy_class(7.5), "Encrypted/Packed (7.5-8)");
        assert_eq!(entropy_class(8.0), "Encrypted/Packed (7.5-8)");
    }

    #[test]
    fn timestomp_suspect_serde_roundtrip() {
        let variants = [
            TimestompSuspect::Confirmed,
            TimestompSuspect::Possible,
            TimestompSuspect::Clean,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialise");
            let back: TimestompSuspect = serde_json::from_str(&json).expect("deserialise");
            assert_eq!(v, &back);
        }
    }

    #[test]
    fn pdf_signature_status_serde_roundtrip() {
        let variants = [
            PdfSignatureStatus::Valid,
            PdfSignatureStatus::Invalid,
            PdfSignatureStatus::Expired,
            PdfSignatureStatus::Unsigned,
            PdfSignatureStatus::Unknown,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialise");
            let back: PdfSignatureStatus = serde_json::from_str(&json).expect("deserialise");
            assert_eq!(v, &back);
        }
    }

    #[test]
    fn pe_authenticode_status_serde_roundtrip() {
        let variants = [
            PeAuthenticodeStatus::Valid,
            PeAuthenticodeStatus::InvalidSignature,
            PeAuthenticodeStatus::Unsigned,
            PeAuthenticodeStatus::Untrusted,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialise");
            let back: PeAuthenticodeStatus = serde_json::from_str(&json).expect("deserialise");
            assert_eq!(v, &back);
        }
    }

    #[test]
    fn macb_timestamps_empty_all_none() {
        let macb = MacbTimestamps::empty();
        assert!(macb.created.is_none());
        assert!(macb.accessed.is_none());
        assert!(macb.modified.is_none());
        assert!(macb.changed.is_none());
    }

    #[test]
    fn file_metadata_full_serde_roundtrip() {
        let mut m = FileMetadata::new(1);
        m.file_name = Some("test.exe".to_owned());
        m.hash_sha256 = Some("abc123".to_owned());
        m.shannon_entropy = Some(7.8);
        m.entropy_classification = Some(entropy_class(7.8).to_owned());
        m.pe_authenticode_status = Some(PeAuthenticodeStatus::Valid);
        m.pdf_signature_status = Some(PdfSignatureStatus::Unsigned);
        m.timestomp_suspect = Some(TimestompSuspect::Possible);
        m.macb = Some(MacbTimestamps {
            created: Some("2024-01-01T00:00:00Z".to_owned()),
            accessed: None,
            modified: Some("2024-06-15T12:00:00Z".to_owned()),
            changed: None,
        });
        m.custom_tags = Some({
            let mut h = HashMap::new();
            h.insert("analyst".to_owned(), "alice".to_owned());
            h
        });

        let json = serde_json::to_string(&m).expect("serialise FileMetadata");
        let back: FileMetadata = serde_json::from_str(&json).expect("deserialise FileMetadata");

        assert_eq!(back.id, 1);
        assert_eq!(back.file_name.as_deref(), Some("test.exe"));
        assert_eq!(back.shannon_entropy, Some(7.8));
        assert!(matches!(
            back.pe_authenticode_status,
            Some(PeAuthenticodeStatus::Valid)
        ));
        assert!(matches!(
            back.timestomp_suspect,
            Some(TimestompSuspect::Possible)
        ));
    }
}
