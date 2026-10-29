//! test_mapping.rs — Developer Pre-Flight CI/CD Mapping Validator
//!
//! Validates that the FieldMapper correctly resolves 100% of required fields
//! across diverse real-world metadata fixtures (Canon, Sony, Nikon, iPhone,
//! PDF, PE executable).
//!
//! CI Pipeline Contract:
//!   - If any required field yields a `MappingError`, exits with code 1 and
//!     generates `MAPPING_AUDIT.md` with full diagnostic details.
//!   - If all fields resolve successfully, generates `MAPPING_AUDIT.md` with
//!     status PASSED and exits with code 0.

use nexgen_metadata::field_mapper::{FieldMapper, GoldenMatrix, MappingError};
use nexgen_metadata::models::FileMetadata;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

struct TestCase {
    name: &'static str,
    file_type: &'static str,
    raw_json: serde_json::Value,
    required_fields: Vec<&'static str>,
}

fn build_golden_dataset() -> Vec<TestCase> {
    vec![
        // ── Case 1: Canon EOS DSLR with EXIF prefixes ───────────────────────
        TestCase {
            name: "Canon_EOS_R5_Raw_Exif",
            file_type: "Image (CR3/JPEG)",
            raw_json: json!({
                "EXIF:Make": "Canon",
                "EXIF:Model": "Canon EOS R5",
                "EXIF:SerialNumber": "082024001928",
                "EXIF:LensModel": "RF24-70mm F2.8 L IS USM",
                "EXIF:FocalLength": 50.0,
                "EXIF:FocalLengthIn35mmFormat": 50.0,
                "EXIF:FNumber": 2.8,
                "EXIF:ExposureTime": "1/500",
                "EXIF:ISO": 100,
                "EXIF:DateTimeOriginal": "2024:06:15 14:23:10",
                "EXIF:ImageWidth": 8192,
                "EXIF:ImageHeight": 5464,
                "Composite:GPSLatitude": 37.7749,
                "Composite:GPSLongitude": -122.4194,
                "EXIF:GPSAltitude": 45.2
            }),
            required_fields: vec![
                "Make", "Model", "SerialNumber", "LensModel", "FocalLength",
                "FNumber", "ExposureTime", "ISO", "DateTimeOriginal",
                "ImageWidth", "ImageHeight", "GPSLatitude", "GPSLongitude", "GPSAltitude"
            ],
        },

        // ── Case 2: Apple iPhone HEIC with XMP & QuickTime tags ─────────────
        TestCase {
            name: "Apple_iPhone_15_Pro_HEIC",
            file_type: "Image (HEIC)",
            raw_json: json!({
                "QuickTime:Make": "Apple",
                "QuickTime:Model": "iPhone 15 Pro",
                "XMP:LensModel": "iPhone 15 Pro back triple camera 6.78mm f/1.78",
                "Composite:FocalLength": 6.8,
                "Composite:Aperture": 1.78,
                "Composite:ShutterSpeed": "1/120",
                "XMP:ISO": 64,
                "XMP:DateCreated": "2024:08:20 09:12:44",
                "QuickTime:ImageWidth": 4032,
                "QuickTime:ImageHeight": 3024,
                "GPS:GPSLatitude": 40.7128,
                "GPS:GPSLongitude": -74.0060,
                "GPS:GPSAltitude": 12.0
            }),
            required_fields: vec![
                "Make", "Model", "LensModel", "FocalLength", "FNumber",
                "ExposureTime", "ISO", "DateTimeOriginal", "ImageWidth",
                "ImageHeight", "GPSLatitude", "GPSLongitude", "GPSAltitude"
            ],
        },

        // ── Case 3: Sony Alpha Mirrorless with MakerNotes variants ───────────
        TestCase {
            name: "Sony_Alpha_A7IV",
            file_type: "Image (ARW)",
            raw_json: json!({
                "IFD0:Make": "SONY",
                "IFD0:Model": "ILCE-7M4",
                "MakerNotes:InternalSerialNumber": "3498127",
                "MakerNotes:LensType": "FE 24-105mm F4 G OSS",
                "FocalLength": 85.0,
                "FNumber": 4.0,
                "ExposureTime": "1/250",
                "ISOSpeedRatings": 400,
                "DateTimeOriginal": "2024:04:10 18:05:22",
                "File:ImageWidth": 7008,
                "File:ImageHeight": 4672
            }),
            required_fields: vec![
                "Make", "Model", "SerialNumber", "LensModel", "FocalLength",
                "FNumber", "ExposureTime", "ISO", "DateTimeOriginal",
                "ImageWidth", "ImageHeight"
            ],
        },

        // ── Case 4: MP4 / Video Container with QuickTime track tags ──────────
        TestCase {
            name: "DJI_Mavic_3_Pro_Video",
            file_type: "Video (MP4)",
            raw_json: json!({
                "QuickTime:MajorBrand": "mp42",
                "QuickTime:Duration": 124.5,
                "QuickTime:CompressorID": "hvc1",
                "QuickTime:ImageWidth": 3840,
                "QuickTime:ImageHeight": 2160,
                "QuickTime:VideoFrameRate": 59.94,
                "QuickTime:AudioFormat": "mp4a",
                "QuickTime:AudioSampleRate": 48000,
                "QuickTime:AudioChannels": 2,
                "QuickTime:AvgBitrate": 120000
            }),
            required_fields: vec![
                "Duration", "VideoCodec", "ImageWidth", "ImageHeight",
                "VideoFrameRate", "AudioCodec", "AudioSampleRate", "AudioChannels"
            ],
        },

        // ── Case 5: PDF Document with Adobe / lopdf Info Dict tags ───────────
        TestCase {
            name: "Forensic_Audit_Report_PDF",
            file_type: "Document (PDF)",
            raw_json: json!({
                "PDF:PDFVersion": "1.7",
                "PDF:Producer": "Adobe PDF Library 21.1",
                "XMP:CreatorTool": "InDesign CC 2024",
                "PDF_Linearized": "Yes",
                "XMP:Author": "Special Agent J. Vance",
                "XMP:Title": "Chain of Custody Report #4029",
                "PDF:PageCount": 42
            }),
            required_fields: vec![
                "PDFVersion", "Producer", "Creator", "Linearized",
                "Author", "Title", "Pages"
            ],
        },

        // ── Case 6: Windows PE Binary Header ─────────────────────────────────
        TestCase {
            name: "KernelDriver_Sys_PE",
            file_type: "Executable (PE)",
            raw_json: json!({
                "EXE:MachineType": "AMD64",
                "Machine": "x86_64",
                "Subsystem": "Native"
            }),
            required_fields: vec![
                "MachineType"
            ],
        },
    ]
}

fn main() {
    println!("============================================================");
    println!("🧪 NexGen Metadata Pre-Flight Mapping Validator");
    println!("============================================================");

    let matrix = GoldenMatrix::load_embedded();
    let mapper = FieldMapper::new(matrix);

    let test_cases = build_golden_dataset();
    let mut audit_log: Vec<String> = Vec::new();
    let mut failures: Vec<(String, String, MappingError)> = Vec::new();
    let mut total_checks = 0;
    let mut passed_checks = 0;

    audit_log.push("# NexGen Metadata Mapping Audit Report".to_string());
    audit_log.push(format!("Generated: {}", chrono::Utc::now().to_rfc3339()));
    audit_log.push("".to_string());
    audit_log.push("| Test Case | File Type | Target Field | Matched Key | Tier | Status |".to_string());
    audit_log.push("|-----------|-----------|--------------|-------------|------|--------|".to_string());

    for case in &test_cases {
        println!("\n🔍 Auditing fixture: {} [{}]", case.name, case.file_type);
        let mut meta = FileMetadata::new(1);

        for &field in &case.required_fields {
            total_checks += 1;
            match mapper.resolve(&case.raw_json, field) {
                Ok(hit) => {
                    passed_checks += 1;
                    println!(
                        "   ✓ {:<20} -> {:<30} (Tier {})",
                        field, hit.matched_key, hit.tier
                    );
                    audit_log.push(format!(
                        "| {} | {} | {} | `{}` | Tier {} | ✅ RESOLVED |",
                        case.name, case.file_type, field, hit.matched_key, hit.tier
                    ));
                }
                Err(err) => {
                    println!("   ❌ FAILED to resolve '{}': {}", field, err);
                    failures.push((case.name.to_string(), field.to_string(), err.clone()));
                    audit_log.push(format!(
                        "| {} | {} | {} | *NONE* | N/A | ❌ FAILED |",
                        case.name, case.file_type, field
                    ));
                }
            }
        }

        // Test comprehensive apply_to_metadata
        let mapping_errors = mapper.apply_to_metadata(&case.raw_json, &mut meta);
        if !mapping_errors.is_empty() {
            println!("   ℹ️ Diagnostic warnings during apply_to_metadata: {} unmapped fields", mapping_errors.len());
        }
    }

    audit_log.push("".to_string());
    audit_log.push("## Summary".to_string());
    audit_log.push(format!("- **Total Field Assertions:** {}", total_checks));
    audit_log.push(format!("- **Passed Assertions:** {}", passed_checks));
    audit_log.push(format!("- **Failed Assertions:** {}", failures.len()));
    let pass_rate = if total_checks > 0 {
        (passed_checks as f64 / total_checks as f64) * 100.0
    } else {
        0.0
    };
    audit_log.push(format!("- **Resolution Rate:** {:.2}%", pass_rate));

    if !failures.is_empty() {
        audit_log.push("".to_string());
        audit_log.push("## Mapping Discrepancy Failure Details".to_string());
        for (case_name, field, err) in &failures {
            audit_log.push(format!("### Case: `{}` - Field: `{}`", case_name, field));
            audit_log.push(format!("- **Available Keys:** `{:?}`", err.available_keys));
            audit_log.push(format!("- **Highest Tier Tried:** {}", err.highest_tier_tried));
            if let Some((cand, dist)) = &err.closest_candidate {
                audit_log.push(format!("- **Closest Candidate:** `{}` (Levenshtein distance: {})", cand, dist));
            }
            audit_log.push("".to_string());
        }
    }

    // Write MAPPING_AUDIT.md in current directory and src-tauri
    let audit_content = audit_log.join("\n");
    let out_paths = vec![
        PathBuf::from("MAPPING_AUDIT.md"),
        PathBuf::from("src-tauri/MAPPING_AUDIT.md"),
        PathBuf::from("../MAPPING_AUDIT.md"),
    ];
    for p in out_paths {
        if let Ok(mut f) = File::create(&p) {
            let _ = f.write_all(audit_content.as_bytes());
            println!("📄 Saved audit report to {}", p.display());
            break;
        }
    }

    println!("\n============================================================");
    if failures.is_empty() {
        println!("✅ PRE-FLIGHT CHECK PASSED: {:.2}% field resolution rate", pass_rate);
        println!("============================================================");
        std::process::exit(0);
    } else {
        eprintln!("❌ PRE-FLIGHT CHECK FAILED: {} mapping errors encountered", failures.len());
        eprintln!("   See MAPPING_AUDIT.md for exact raw JSON keys and failure diagnostics.");
        println!("============================================================");
        std::process::exit(1);
    }
}
