//! export.rs — Multi-Format Export Engine & Chain-of-Custody Cryptographic Manifest

use crate::errors::NexGenError;
use crate::models::FileMetadata;
use blake3::Hasher as Blake3Hasher;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rust_xlsxwriter::{Format, Workbook};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;

/// Prevent formula injection (CSV/XLSX Injection / SEC-12).
/// Prefix a single quote (') to any string value starting with '=', '+', '-', '@', '\t', '\r'.
pub fn sanitize_cell(value: &str) -> String {
    let sanitized = if value.starts_with('=')
        || value.starts_with('+')
        || value.starts_with('-')
        || value.starts_with('@')
        || value.starts_with('\t')
        || value.starts_with('\r')
    {
        format!("'{}", value)
    } else {
        value.to_string()
    };
    sanitized.replace('"', "\"\"")
}

/// Cryptographic chain of custody manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub company: String,
    pub scan_id: String,
    pub timestamp_utc: String,
    pub file_count: u64,
    pub export_path: String,
    pub blake3_hash: String,
    pub ed25519_signature: String,
    pub ed25519_public_key: String,
}

pub fn export_csv(records: &[FileMetadata], path: &Path) -> Result<(), NexGenError> {
    let file = File::create(path).map_err(|e| NexGenError::ExportWrite(e.to_string()))?;
    let mut writer = BufWriter::new(file);

    // CSV Headers
    writeln!(
        writer,
        "ID,File Name,Extension,File Path,Parent Dir,Size Bytes,Human Size,BLAKE3,SHA256,MD5,Entropy,Classification,Magic Bytes,Timestomp Suspect,Created UTC,Accessed UTC,Modified UTC,Changed UTC,Zone ID,Host URL"
    )
    .map_err(|e| NexGenError::ExportWrite(e.to_string()))?;

    for r in records {
        let macb = r.macb.as_ref();
        let created = macb.and_then(|m| m.created.as_deref()).unwrap_or("");
        let accessed = macb.and_then(|m| m.accessed.as_deref()).unwrap_or("");
        let modified = macb.and_then(|m| m.modified.as_deref()).unwrap_or("");
        let changed = macb.and_then(|m| m.changed.as_deref()).unwrap_or("");
        let timestomp = r
            .timestomp_suspect
            .as_ref()
            .map(|t| format!("{:?}", t))
            .unwrap_or_default();

        let line = format!(
            "{},\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\"",
            r.id,
            sanitize_cell(r.file_name.as_deref().unwrap_or("")),
            sanitize_cell(r.file_extension.as_deref().unwrap_or("")),
            sanitize_cell(r.file_path.as_deref().unwrap_or("")),
            sanitize_cell(r.parent_directory.as_deref().unwrap_or("")),
            r.size_bytes.unwrap_or(0),
            sanitize_cell(r.size_human.as_deref().unwrap_or("")),
            sanitize_cell(r.hash_blake3.as_deref().unwrap_or("")),
            sanitize_cell(r.hash_sha256.as_deref().unwrap_or("")),
            sanitize_cell(r.hash_md5.as_deref().unwrap_or("")),
            r.shannon_entropy.unwrap_or(0.0),
            sanitize_cell(r.entropy_classification.as_deref().unwrap_or("")),
            sanitize_cell(r.magic_bytes_hex.as_deref().unwrap_or("")),
            sanitize_cell(&timestomp),
            sanitize_cell(created),
            sanitize_cell(accessed),
            sanitize_cell(modified),
            sanitize_cell(changed),
            r.ads_zone_id.unwrap_or(0),
            sanitize_cell(r.ads_host_url.as_deref().unwrap_or(""))
        );
        writeln!(writer, "{}", line).map_err(|e| NexGenError::ExportWrite(e.to_string()))?;
    }

    writer.flush().map_err(|e| NexGenError::ExportWrite(e.to_string()))?;
    Ok(())
}

pub fn export_json(records: &[FileMetadata], path: &Path) -> Result<(), NexGenError> {
    let file = File::create(path).map_err(|e| NexGenError::ExportWrite(e.to_string()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, records)
        .map_err(|e| NexGenError::ExportWrite(e.to_string()))?;
    Ok(())
}

pub fn export_xlsx(records: &[FileMetadata], path: &Path) -> Result<(), NexGenError> {
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    worksheet
        .set_name("NexGen Metadata")
        .map_err(|e| NexGenError::ExportWrite(e.to_string()))?;

    let header_format = Format::new().set_bold();

    let headers = [
        "ID",
        "File Name",
        "Extension",
        "File Path",
        "Parent Directory",
        "Size (Bytes)",
        "Size (Human)",
        "BLAKE3",
        "SHA256",
        "MD5",
        "Shannon Entropy",
        "Entropy Class",
        "Magic Bytes",
        "Timestomp Suspect",
        "MACB Created",
        "MACB Accessed",
        "MACB Modified",
        "MACB Changed",
        "ADS Zone ID",
        "ADS Host URL",
    ];

    for (col_idx, &h) in headers.iter().enumerate() {
        worksheet
            .write_string_with_format(0, col_idx as u16, h, &header_format)
            .map_err(|e| NexGenError::ExportWrite(e.to_string()))?;
    }

    worksheet
        .set_freeze_panes(1, 0)
        .map_err(|e| NexGenError::ExportWrite(e.to_string()))?;

    for (row_idx, r) in records.iter().enumerate() {
        let row = (row_idx + 1) as u32;
        let macb = r.macb.as_ref();
        let created = macb.and_then(|m| m.created.as_deref()).unwrap_or("");
        let accessed = macb.and_then(|m| m.accessed.as_deref()).unwrap_or("");
        let modified = macb.and_then(|m| m.modified.as_deref()).unwrap_or("");
        let changed = macb.and_then(|m| m.changed.as_deref()).unwrap_or("");
        let timestomp = r
            .timestomp_suspect
            .as_ref()
            .map(|t| format!("{:?}", t))
            .unwrap_or_default();

        let _ = worksheet.write_number(row, 0, r.id as f64);
        let _ = worksheet.write_string(row, 1, &sanitize_cell(r.file_name.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 2, &sanitize_cell(r.file_extension.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 3, &sanitize_cell(r.file_path.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 4, &sanitize_cell(r.parent_directory.as_deref().unwrap_or("")));
        let _ = worksheet.write_number(row, 5, r.size_bytes.unwrap_or(0) as f64);
        let _ = worksheet.write_string(row, 6, &sanitize_cell(r.size_human.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 7, &sanitize_cell(r.hash_blake3.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 8, &sanitize_cell(r.hash_sha256.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 9, &sanitize_cell(r.hash_md5.as_deref().unwrap_or("")));
        let _ = worksheet.write_number(row, 10, r.shannon_entropy.unwrap_or(0.0));
        let _ = worksheet.write_string(row, 11, &sanitize_cell(r.entropy_classification.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 12, &sanitize_cell(r.magic_bytes_hex.as_deref().unwrap_or("")));
        let _ = worksheet.write_string(row, 13, &sanitize_cell(&timestomp));
        let _ = worksheet.write_string(row, 14, &sanitize_cell(created));
        let _ = worksheet.write_string(row, 15, &sanitize_cell(accessed));
        let _ = worksheet.write_string(row, 16, &sanitize_cell(modified));
        let _ = worksheet.write_string(row, 17, &sanitize_cell(changed));
        let _ = worksheet.write_number(row, 18, r.ads_zone_id.unwrap_or(0) as f64);
        let _ = worksheet.write_string(row, 19, &sanitize_cell(r.ads_host_url.as_deref().unwrap_or("")));
    }

    workbook
        .save(path)
        .map_err(|e| NexGenError::ExportWrite(e.to_string()))?;
    Ok(())
}

pub fn generate_manifest(
    export_path: &Path,
    file_count: u64,
    scan_id: &str,
) -> Result<Manifest, NexGenError> {
    let mut file = File::open(export_path).map_err(|e| NexGenError::Io(e))?;
    let mut hasher = Blake3Hasher::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(NexGenError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let blake3_hex = hasher.finalize().to_hex().to_string();

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let signature = signing_key.sign(blake3_hex.as_bytes());
    let pubkey = signing_key.verifying_key();

    let manifest = Manifest {
        company: "NexGen Forensics".to_string(),
        scan_id: scan_id.to_string(),
        timestamp_utc: Utc::now().to_rfc3339(),
        file_count,
        export_path: export_path.to_string_lossy().to_string(),
        blake3_hash: blake3_hex,
        ed25519_signature: hex::encode(signature.to_bytes()),
        ed25519_public_key: hex::encode(pubkey.to_bytes()),
    };

    let manifest_path = export_path.with_extension("manifest.json");
    let manifest_file = File::create(&manifest_path).map_err(NexGenError::Io)?;
    serde_json::to_writer_pretty(manifest_file, &manifest)
        .map_err(|e| NexGenError::ExportWrite(e.to_string()))?;

    Ok(manifest)
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}
