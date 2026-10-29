//! scanner.rs — Multi-Threaded Parallel Disk Scanner Engine.
//!
//! Orchestrates jwalk filesystem walking, Rayon CPU pool, DynamicReader,
//! NTFS forensics, binary parsers, ExifTool daemon pool, and SQLite writes.

use crate::database::DatabaseWriter;
use crate::errors::NexGenError;
use crate::exiftool_pool::ExiftoolPool;
use crate::forensics::{get_ads_info, get_ntfs_metadata};
use crate::models::{human_size, FileMetadata};
use crate::parsers::{pdf, pe};
use crate::reader::DynamicReader;
use jwalk::WalkDir;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scanned_files: u64,
    pub total_files: u64,
    pub current_file: String,
    pub percentage: f64,
    pub status: String,
    pub errors: u64,
    pub elapsed_ms: u64,
}

pub async fn start_scan(
    folder_path: String,
    recursive: bool,
    include_hidden: bool,
    selected_fields: Vec<String>,
    cancel_token: CancellationToken,
    progress_tx: broadcast::Sender<ScanProgress>,
    exiftool_pool: Arc<ExiftoolPool>,
    db_writer: DatabaseWriter,
    results_store: Arc<Mutex<Vec<FileMetadata>>>,
) -> Result<u64, NexGenError> {
    let root_path = PathBuf::from(&folder_path);
    info!("Starting scan on target directory: {:?}", root_path);
    let start_time = Instant::now();

    // 1. Walk directory tree using jwalk
    let mut walker = WalkDir::new(&root_path).follow_links(false);
    if !recursive {
        walker = walker.max_depth(1);
    }

    let mut candidate_paths: Vec<PathBuf> = Vec::new();
    for entry in walker {
        if cancel_token.is_cancelled() {
            info!("Scan cancelled during directory discovery");
            let _ = progress_tx.send(ScanProgress {
                scanned_files: 0,
                total_files: 0,
                current_file: "Discovery Cancelled".to_string(),
                percentage: 0.0,
                status: "Cancelled".to_string(),
                errors: 0,
                elapsed_ms: start_time.elapsed().as_millis() as u64,
            });
            return Ok(0);
        }

        match entry {
            Ok(dir_entry) => {
                if dir_entry.file_type().is_file() {
                    let path = dir_entry.path();
                    candidate_paths.push(path);
                }
            }
            Err(e) => {
                warn!("Directory traversal error: {}", e);
            }
        }
    }

    let total_files = candidate_paths.len() as u64;
    info!("Discovered {} files. Beginning parallel analysis...", total_files);

    if total_files == 0 {
        let _ = progress_tx.send(ScanProgress {
            scanned_files: 0,
            total_files: 0,
            current_file: "No files found".to_string(),
            percentage: 100.0,
            status: "Completed".to_string(),
            errors: 0,
            elapsed_ms: start_time.elapsed().as_millis() as u64,
        });
        db_writer.flush().await?;
        db_writer.shutdown().await?;
        return Ok(0);
    }

    let scanned_counter = Arc::new(AtomicU64::new(0));
    let error_counter = Arc::new(AtomicU64::new(0));
    let id_generator = Arc::new(AtomicU64::new(1));

    // Batch files in 100-file slices for balanced CPU concurrency and UI streaming
    let batch_size = 100;
    let chunks: Vec<Vec<PathBuf>> = candidate_paths
        .chunks(batch_size)
        .map(|c| c.to_vec())
        .collect();

    for chunk in chunks {
        // Strict Cancellation Check: Stop immediately if cancel_token is triggered
        if cancel_token.is_cancelled() {
            info!("Cancellation signal detected. Halting scan immediately.");
            let _ = progress_tx.send(ScanProgress {
                scanned_files: scanned_counter.load(Ordering::Relaxed),
                total_files,
                current_file: "Scan Cancelled by User".to_string(),
                percentage: (scanned_counter.load(Ordering::Relaxed) as f64 / total_files as f64) * 100.0,
                status: "Cancelled".to_string(),
                errors: error_counter.load(Ordering::Relaxed),
                elapsed_ms: start_time.elapsed().as_millis() as u64,
            });
            break;
        }

        let exiftool_ref = Arc::clone(&exiftool_pool);
        let id_gen_ref = Arc::clone(&id_generator);
        let err_ref = Arc::clone(&error_counter);
        let cancel_ref = cancel_token.clone();

        // Process batch in parallel using Rayon
        let processed_records: Vec<FileMetadata> = chunk
            .into_par_iter()
            .filter_map(|path| {
                if cancel_ref.is_cancelled() {
                    return None;
                }
                match process_single_file(&path, &exiftool_ref, &id_gen_ref) {
                    Ok(meta) => Some(meta),
                    Err(e) => {
                        err_ref.fetch_add(1, Ordering::Relaxed);
                        warn!("Error parsing {:?}: {}", path, e);
                        None
                    }
                }
            })
            .collect();

        let count = processed_records.len() as u64;
        let current_count = scanned_counter.fetch_add(count, Ordering::Relaxed) + count;
        let last_file_name = processed_records
            .last()
            .and_then(|r| r.file_name.clone())
            .unwrap_or_else(|| "Analyzing...".to_string());

        // Ingest into RAM results store for real-time table queries
        results_store.lock().await.extend(processed_records.clone());

        // Flush batch into SQLite Write-Ahead Logging buffer
        for record in &processed_records {
            let _ = db_writer.send(record.clone()).await;
        }

        let pct = if total_files > 0 {
            ((current_count as f64 / total_files as f64) * 100.0).min(100.0)
        } else {
            100.0
        };

        // Broadcast progress update to SSE subscribers
        let _ = progress_tx.send(ScanProgress {
            scanned_files: current_count,
            total_files,
            current_file: last_file_name,
            percentage: pct,
            status: "Scanning".to_string(),
            errors: error_counter.load(Ordering::Relaxed),
            elapsed_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    db_writer.flush().await?;
    db_writer.shutdown().await?;

    let final_scanned = scanned_counter.load(Ordering::Relaxed);
    let final_status = if cancel_token.is_cancelled() {
        "Cancelled"
    } else {
        "Completed"
    };

    info!(
        "Scan finished ({}) with {} files processed in {:.2?}",
        final_status,
        final_scanned,
        start_time.elapsed()
    );

    let _ = progress_tx.send(ScanProgress {
        scanned_files: final_scanned,
        total_files,
        current_file: format!("Scan {}", final_status),
        percentage: 100.0,
        status: final_status.to_string(),
        errors: error_counter.load(Ordering::Relaxed),
        elapsed_ms: start_time.elapsed().as_millis() as u64,
    });

    Ok(final_scanned)
}

fn process_single_file(
    path: &PathBuf,
    exiftool_pool: &Arc<ExiftoolPool>,
    id_gen: &Arc<AtomicU64>,
) -> Result<FileMetadata, NexGenError> {
    let id = id_gen.fetch_add(1, Ordering::Relaxed);
    let mut meta = FileMetadata::new(id);

    // Basic filesystem details
    meta.file_path = Some(path.to_string_lossy().to_string());
    meta.file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string());
    meta.file_extension = path
        .extension()
        .map(|s| s.to_string_lossy().to_string().to_lowercase());
    meta.parent_directory = path
        .parent()
        .map(|s| s.to_string_lossy().to_string());

    if let Ok(fs_meta) = std::fs::metadata(path) {
        meta.size_bytes = Some(fs_meta.len());
        meta.size_human = Some(human_size(fs_meta.len()));
        meta.is_readonly = Some(fs_meta.permissions().readonly());
    }

    // 1. Single-Pass Streaming Read & Hashing Engine
    let reader = DynamicReader::new(path.clone())?;
    let read_result = reader.read_and_analyze()?;

    meta.hash_blake3 = Some(read_result.blake3_hex);
    meta.hash_sha256 = Some(read_result.sha256_hex);
    meta.hash_sha1 = Some(read_result.sha1_hex);
    meta.hash_md5 = Some(read_result.md5_hex);
    meta.hash_sha512 = Some(read_result.sha512_hex);
    meta.hash_crc32 = Some(read_result.crc32_hex);
    meta.hash_xxhash3 = Some(read_result.xxhash3_hex);
    meta.shannon_entropy = Some(read_result.shannon_entropy);
    meta.entropy_classification = Some(crate::models::entropy_class(read_result.shannon_entropy).to_string());
    meta.magic_bytes_hex = Some(
        read_result
            .magic_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" "),
    );

    // 2. Windows Forensics: NTFS MACB & Alternate Data Streams (ADS)
    #[cfg(target_os = "windows")]
    {
        if let Ok(ntfs) = get_ntfs_metadata(path) {
            meta.macb = Some(crate::models::MacbTimestamps {
                created: ntfs.macb_created,
                accessed: ntfs.macb_accessed,
                modified: ntfs.macb_modified,
                changed: ntfs.macb_changed,
            });
            meta.timestomp_suspect = Some(if ntfs.timestomp_suspect {
                crate::models::TimestompSuspect::Confirmed
            } else {
                crate::models::TimestompSuspect::Clean
            });
            meta.inode_number = ntfs.inode_number;
            meta.volume_serial = ntfs.volume_serial;
            meta.link_count = ntfs.link_count;
        }

        if let Ok(ads) = get_ads_info(path) {
            meta.ads_zone_id = ads.zone_id;
            meta.ads_host_url = ads.host_url;
            meta.ads_referrer_url = ads.referrer_url;
            meta.ads_names = Some(ads.ads_names);
        }
    }

    // 3. Format-Specific Deep Parsing (PE, PDF)
    let magic = &read_result.magic_bytes;
    if magic.len() >= 2 && magic[0] == 0x4D && magic[1] == 0x5A {
        // Windows Executable (MZ)
        if let Ok(bytes) = std::fs::read(path) {
            let _ = pe::parse_pe(&bytes, &mut meta);
            meta.file_type_category = Some("Executable / PE".to_string());
        }
    } else if magic.len() >= 4 && &magic[0..4] == b"%PDF" {
        // PDF Document
        if let Ok(bytes) = std::fs::read(path) {
            let _ = pdf::parse_pdf(&bytes, &mut meta);
            meta.file_type_category = Some("Document / PDF".to_string());
        }
    }

    // 4. ExifTool Daemon Pool Query for Media Formats
    let ext = meta.file_extension.as_deref().unwrap_or("");
    let media_extensions = [
        "jpg", "jpeg", "png", "tiff", "cr2", "cr3", "nef", "arw", "dng",
        "mp4", "mkv", "mov", "avi", "mp3", "wav", "flac", "m4a",
    ];
    if media_extensions.contains(&ext) {
        if let Ok(json_data) = exiftool_pool.query(path) {
            apply_exiftool_metadata(&mut meta, &json_data);
        }
    }

    Ok(meta)
}

fn apply_exiftool_metadata(meta: &mut FileMetadata, json: &serde_json::Value) {
    let item = if let Some(arr) = json.as_array() {
        arr.first().unwrap_or(json)
    } else {
        json
    };

    if let Some(make) = item.get("Make").and_then(|v| v.as_str()) {
        meta.exif_make = Some(make.to_string());
    }
    if let Some(model) = item.get("Model").and_then(|v| v.as_str()) {
        meta.exif_model = Some(model.to_string());
    }
    if let Some(lens) = item.get("LensModel").and_then(|v| v.as_str()) {
        meta.exif_lens_model = Some(lens.to_string());
    }
    if let Some(focal) = item.get("FocalLength").and_then(|v| v.as_f64()) {
        meta.exif_focal_length = Some(focal);
    }
    if let Some(iso) = item.get("ISO").and_then(|v| v.as_u64()) {
        meta.exif_iso = Some(iso as u32);
    }
    if let Some(lat) = item.get("GPSLatitude").and_then(|v| v.as_f64()) {
        meta.gps_latitude = Some(lat);
    }
    if let Some(lon) = item.get("GPSLongitude").and_then(|v| v.as_f64()) {
        meta.gps_longitude = Some(lon);
    }
    if let Some(alt) = item.get("GPSAltitude").and_then(|v| v.as_f64()) {
        meta.gps_altitude = Some(alt);
    }
}
