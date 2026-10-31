//! database.rs — SQLite WAL Buffered Persistence Layer using standard std::thread & crossbeam-channel

use crate::errors::NexGenError;
use crate::models::FileMetadata;
use crossbeam::channel::{unbounded, Receiver, Sender};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tracing::{error, info};

pub enum DatabaseMessage {
    Record(Box<FileMetadata>),
    Flush,
    Shutdown,
}

#[derive(Clone)]
pub struct DatabaseWriter {
    sender: Sender<DatabaseMessage>,
}

impl DatabaseWriter {
    pub fn send_sync(&self, record: FileMetadata) -> Result<(), NexGenError> {
        self.sender
            .send(DatabaseMessage::Record(Box::new(record)))
            .map_err(|e| NexGenError::Database(format!("Channel send error: {}", e)))
    }

    pub async fn send(&self, record: FileMetadata) -> Result<(), NexGenError> {
        self.send_sync(record)
    }

    pub fn flush_sync(&self) -> Result<(), NexGenError> {
        self.sender
            .send(DatabaseMessage::Flush)
            .map_err(|e| NexGenError::Database(format!("Flush signal error: {}", e)))
    }

    pub async fn flush(&self) -> Result<(), NexGenError> {
        self.flush_sync()
    }

    pub fn shutdown_sync(&self) -> Result<(), NexGenError> {
        let _ = self.sender.send(DatabaseMessage::Shutdown);
        Ok(())
    }

    pub async fn shutdown(self) -> Result<(), NexGenError> {
        self.shutdown_sync()
    }
}

pub fn create_database_sync(db_path: &Path) -> Result<DatabaseWriter, NexGenError> {
    let path_buf = db_path.to_path_buf();
    let conn = Connection::open(&path_buf)
        .map_err(|e| NexGenError::Database(format!("Failed to open DB: {}", e)))?;

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

    let (tx, rx) = unbounded::<DatabaseMessage>();

    std::thread::Builder::new()
        .name("sqlite-wal-writer".to_string())
        .spawn(move || {
            writer_loop(rx, conn);
        })
        .map_err(|e| NexGenError::Database(format!("Failed to spawn SQLite writer thread: {}", e)))?;

    Ok(DatabaseWriter { sender: tx })
}

pub async fn create_database(db_path: &Path) -> Result<DatabaseWriter, NexGenError> {
    create_database_sync(db_path)
}

fn writer_loop(rx: Receiver<DatabaseMessage>, mut conn: Connection) {
    let mut buffer: Vec<FileMetadata> = Vec::with_capacity(5000);

    while let Ok(msg) = rx.recv() {
        match msg {
            DatabaseMessage::Record(rec) => {
                buffer.push(*rec);
                if buffer.len() >= 5000 {
                    if let Err(e) = flush_to_db(&mut conn, &mut buffer) {
                        error!("Database batch flush error: {:?}", e);
                    }
                }
            }
            DatabaseMessage::Flush => {
                if !buffer.is_empty() {
                    if let Err(e) = flush_to_db(&mut conn, &mut buffer) {
                        error!("Database flush error: {:?}", e);
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
}

fn flush_to_db(conn: &mut Connection, buffer: &mut Vec<FileMetadata>) -> Result<(), NexGenError> {
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
            .map_err(|e| NexGenError::Database(format!("Failed to prepare statement: {}", e)))?;

        for record in buffer.iter() {
            let timestomp_str = record.timestomp_suspect.as_ref().map(|s| format!("{:?}", s));
            let raw_json_str = serde_json::to_string(record).unwrap_or_default();

            let _ = stmt.execute(rusqlite::params![
                record.id as i64,
                record.file_name,
                record.file_extension,
                record.file_path,
                record.parent_directory,
                record.size_bytes.map(|s| s as i64),
                record.size_human,
                record.hash_blake3,
                record.hash_sha256,
                record.hash_md5,
                record.shannon_entropy,
                record.entropy_classification,
                record.magic_bytes_hex,
                timestomp_str,
                record.macb.as_ref().and_then(|m| m.created.clone()),
                record.macb.as_ref().and_then(|m| m.accessed.clone()),
                record.macb.as_ref().and_then(|m| m.modified.clone()),
                record.macb.as_ref().and_then(|m| m.changed.clone()),
                record.ads_zone_id.map(|z| z as i64),
                record.ads_host_url,
                raw_json_str,
            ]);
        }
    }

    tx.commit()
        .map_err(|e| NexGenError::Database(format!("Failed to commit batch: {}", e)))?;

    buffer.clear();
    Ok(())
}
