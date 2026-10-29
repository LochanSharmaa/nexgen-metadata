//! database.rs — SQLite Write-Ahead Logging (WAL) Buffered Persistence Layer
//!
//! Handles buffering records in memory and flushing them to SQLite in bulk
//! transactions of 5,000 items to avoid disk saturation and maintain sub-100MB footprint.

use crate::errors::NexGenError;
use crate::models::FileMetadata;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

pub enum DatabaseMessage {
    Record(Box<FileMetadata>),
    Flush,
    Shutdown,
}

pub struct DatabaseWriter {
    sender: mpsc::Sender<DatabaseMessage>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl DatabaseWriter {
    pub async fn send(&self, record: FileMetadata) -> Result<(), NexGenError> {
        self.sender
            .send(DatabaseMessage::Record(Box::new(record)))
            .await
            .map_err(|e| NexGenError::Database(format!("Channel send error: {}", e)))
    }

    pub async fn flush(&self) -> Result<(), NexGenError> {
        self.sender
            .send(DatabaseMessage::Flush)
            .await
            .map_err(|e| NexGenError::Database(format!("Flush signal error: {}", e)))
    }

    pub async fn shutdown(mut self) -> Result<(), NexGenError> {
        let _ = self.sender.send(DatabaseMessage::Shutdown).await;
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
        Ok(())
    }
}

pub async fn create_database(db_path: &Path) -> Result<DatabaseWriter, NexGenError> {
    let path_buf = db_path.to_path_buf();
    let conn = Connection::open(&path_buf)
        .map_err(|e| NexGenError::Database(format!("Failed to open DB: {}", e)))?;

    // Execute performance PRAGMAs for extreme write throughput
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=OFF;
         PRAGMA cache_size=-64000;
         PRAGMA temp_store=MEMORY;",
    )
    .map_err(|e| NexGenError::Database(format!("PRAGMA init failed: {}", e)))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS file_metadata (
            id INTEGER PRIMARY KEY,
            file_name TEXT,
            extension TEXT,
            path TEXT UNIQUE,
            parent_directory TEXT,
            size_bytes INTEGER,
            size_human TEXT,
            hash_blake3 TEXT,
            hash_sha256 TEXT,
            hash_md5 TEXT,
            shannon_entropy REAL,
            entropy_classification TEXT,
            magic_bytes_hex TEXT,
            timestomp_suspect TEXT,
            macb_created TEXT,
            macb_accessed TEXT,
            macb_modified TEXT,
            macb_changed TEXT,
            ads_zone_id INTEGER,
            ads_host_url TEXT,
            raw_metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_file_path ON file_metadata(path);
        CREATE INDEX IF NOT EXISTS idx_blake3 ON file_metadata(hash_blake3);",
    )
    .map_err(|e| NexGenError::Database(format!("Schema initialization failed: {}", e)))?;

    let (tx, rx) = mpsc::channel::<DatabaseMessage>(5000);

    let join_handle = tokio::task::spawn_blocking(move || {
        writer_loop(rx, conn, path_buf);
    });

    Ok(DatabaseWriter {
        sender: tx,
        join_handle: Some(join_handle),
    })
}

fn writer_loop(
    mut rx: mpsc::Receiver<DatabaseMessage>,
    mut conn: Connection,
    db_path: PathBuf,
) {
    let mut buffer: Vec<FileMetadata> = Vec::with_capacity(5000);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while let Some(msg) = rx.blocking_recv() {
            match msg {
                DatabaseMessage::Record(rec) => {
                    buffer.push(*rec);
                    if buffer.len() >= 5000 {
                        if let Err(e) = flush_to_db(&mut conn, &mut buffer) {
                            error!("Database batch flush error: {:?}", e);
                            emergency_dump(&buffer);
                        }
                    }
                }
                DatabaseMessage::Flush => {
                    if !buffer.is_empty() {
                        if let Err(e) = flush_to_db(&mut conn, &mut buffer) {
                            error!("Database flush error: {:?}", e);
                            emergency_dump(&buffer);
                        }
                    }
                }
                DatabaseMessage::Shutdown => {
                    if !buffer.is_empty() {
                        let _ = flush_to_db(&mut conn, &mut buffer);
                    }
                    break;
                }
            }
        }
    }));

    if result.is_err() {
        error!("Database worker thread panicked! Emergency dumping active memory buffer...");
        emergency_dump(&buffer);
    }
}

fn flush_to_db(
    conn: &mut Connection,
    buffer: &mut Vec<FileMetadata>,
) -> Result<(), NexGenError> {
    if buffer.is_empty() {
        return Ok(());
    }

    let tx = conn
        .transaction()
        .map_err(|e| NexGenError::Database(format!("Failed to begin tx: {}", e)))?;

    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT OR REPLACE INTO file_metadata (
                    id, file_name, extension, path, parent_directory, size_bytes, size_human,
                    hash_blake3, hash_sha256, hash_md5, shannon_entropy, entropy_classification,
                    magic_bytes_hex, timestomp_suspect, macb_created, macb_accessed, macb_modified,
                    macb_changed, ads_zone_id, ads_host_url, raw_metadata_json
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
                )",
            )
            .map_err(|e| NexGenError::Database(format!("Prepare statement error: {}", e)))?;

        for item in buffer.iter() {
            let timestomp_str = item.timestomp_suspect.as_ref().map(|t| format!("{:?}", t));
            let raw_json = serde_json::to_string(item).unwrap_or_default();

            let macb = item.macb.as_ref();
            let macb_created = macb.and_then(|m| m.created.as_deref());
            let macb_accessed = macb.and_then(|m| m.accessed.as_deref());
            let macb_modified = macb.and_then(|m| m.modified.as_deref());
            let macb_changed = macb.and_then(|m| m.changed.as_deref());

            stmt.execute(params![
                item.id as i64,
                item.file_name,
                item.file_extension,
                item.file_path,
                item.parent_directory,
                item.size_bytes.map(|s| s as i64),
                item.size_human,
                item.hash_blake3,
                item.hash_sha256,
                item.hash_md5,
                item.shannon_entropy,
                item.entropy_classification,
                item.magic_bytes_hex,
                timestomp_str,
                macb_created,
                macb_accessed,
                macb_modified,
                macb_changed,
                item.ads_zone_id,
                item.ads_host_url,
                raw_json,
            ])
            .map_err(|e| NexGenError::Database(format!("Insert row failure: {}", e)))?;
        }
    }

    tx.commit()
        .map_err(|e| NexGenError::Database(format!("Commit failure: {}", e)))?;

    info!("Flushed {} records to SQLite WAL store", buffer.len());
    buffer.clear();
    Ok(())
}

fn emergency_dump(buffer: &[FileMetadata]) {
    if buffer.is_empty() {
        return;
    }
    let dump_file = PathBuf::from("emergency_dump.json");
    if let Ok(serialized) = serde_json::to_string_pretty(buffer) {
        let _ = std::fs::write(&dump_file, serialized);
        error!("Emergency dump successfully written to {:?}", dump_file);
    }
}
