//! scanner.rs — Multi-Threaded Parallel Disk Scanner Engine.
//!
//! Orchestrates jwalk filesystem walking, Rayon CPU pool, DynamicReader,
//! NTFS forensics, binary parsers, ExifTool daemon pool, and SQLite writes.

use crate::database::DatabaseWriter;
use crate::errors::NexGenError;
use crate::exiftool_pool::ExiftoolPool;
use crate::field_mapper::{FieldMapper, GoldenMatrix, RawCache};
use crate::forensics::{get_ads_info, get_ntfs_metadata};
use crate::models::{human_size, FileMetadata};
use crate::parsers::{pdf, pe};
use crate::reader::DynamicReader;
use jwalk::WalkDir;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub root_path: PathBuf,
    pub recursive: bool,
    pub include_hidden: bool,
    pub selected_fields: Vec<String>,
}

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
    scan_id: String,
    folder_path: String,
    recursive: bool,
    include_hidden: bool,
    selected_fields: Vec<String>,
    cancel_token: CancellationToken,
    progress_tx: broadcast::Sender<ScanProgress>,
    exiftool_pool: Arc<ExiftoolPool>,
    db_writer: DatabaseWriter,
    results_store: Arc<Mutex<Vec<FileMetadata>>>,
    raw_cache: Arc<Mutex<VecDeque<RawCache>>>,
) -> Result<u64, NexGenError> {
    let root_path = PathBuf::from(&folder_path);
    info!("Starting scan {} on target directory: {:?}", scan_id, root_path);
    let start_time = Instant::now();

    // Initialize the Tier 0 Self-Healing Field Mapper with the Golden Matrix
    let field_mapper = Arc::new(FieldMapper::new(GoldenMatrix::load_embedded()));

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
        let mapper_ref = Arc::clone(&field_mapper);

        // Process batch in parallel using Rayon
        let batch_results: Vec<(FileMetadata, serde_json::Value)> = chunk
            .into_par_iter()
            .filter_map(|path| {
                if cancel_ref.is_cancelled() {
                    return None;
                }
                match process_single_file(&path, &exiftool_ref, &id_gen_ref, &mapper_ref) {
                    Ok(res) => Some(res),
                    Err(e) => {
                        err_ref.fetch_add(1, Ordering::Relaxed);
                        warn!("Error parsing {:?}: {}", path, e);
                        None
                    }
                }
            })
            .collect();

        let count = batch_results.len() as u64;
        let prev_count = scanned_counter.fetch_add(count, Ordering::Relaxed);
        let current_count = prev_count + count;

        let processed_records: Vec<FileMetadata> = batch_results.iter().map(|(m, _)| m.clone()).collect();
        let last_file_name = processed_records
            .last()
            .and_then(|r| r.file_name.clone())
            .unwrap_or_else(|| "Analyzing...".to_string());

        // Ingest into RAM results store for real-time table queries
        results_store.lock().await.extend(processed_records.clone());

        // Cache raw parser output in 100-file ring buffer for one-click encrypted bug reporting
        {
            let mut cache = raw_cache.lock().await;
            for (idx, (record, raw_json)) in batch_results.into_iter().enumerate() {
                if cache.len() >= 100 {
                    cache.pop_front();
                }
                let row_idx = prev_count as usize + idx;
                cache.push_back(RawCache::new_redacted(
                    scan_id.clone(),
                    row_idx,
                    record.id,
                    record.file_name.clone().unwrap_or_default(),
                    record.file_extension.clone().unwrap_or_default(),
                    raw_json,
                    record,
                ));
            }
        }

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
    mapper: &Arc<FieldMapper>,
) -> Result<(FileMetadata, serde_json::Value), NexGenError> {
    let id = id_gen.fetch_add(1, Ordering::Relaxed);
    let mut meta = FileMetadata::new(id);
    let mut raw_json = serde_json::Value::Null;

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

    // 4. ExifTool Daemon Pool Query for Media Formats with Tiered Self-Healing Mapping
    let ext = meta.file_extension.as_deref().unwrap_or("");
    let media_extensions = [
        "jpg", "jpeg", "png", "tiff", "cr2", "cr3", "nef", "arw", "dng",
        "mp4", "mkv", "mov", "avi", "mp3", "wav", "flac", "m4a",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    ];
    if media_extensions.contains(&ext) {
        if let Ok(json_data) = exiftool_pool.query_blocking(path) {
            let _mapping_errors = mapper.apply_to_metadata(&json_data, &mut meta);
            raw_json = json_data;
        }
    }

    // If no external parser ran, synthesize raw JSON snapshot of extracted attributes
    if raw_json.is_null() {
        raw_json = serde_json::to_value(&meta).unwrap_or(serde_json::Value::Null);
    }

    Ok((meta, raw_json))
}
