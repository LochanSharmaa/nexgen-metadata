//! state.rs — Centralized, Thread-Safe Shared Application State for Axum.

use crate::exiftool_pool::ExiftoolPool;
use crate::models::FileMetadata;
use crate::scanner::ScanProgress;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;

/// Handle tracking an active running scan process.
#[derive(Clone)]
pub struct ScanHandle {
    pub scan_id: String,
    pub target_folder: PathBuf,
    pub cancel_token: CancellationToken,
    pub progress_tx: broadcast::Sender<ScanProgress>,
    pub results: Arc<Mutex<Vec<FileMetadata>>>,
}

/// Global Application State passed to Axum routers using State(app_state).
#[derive(Clone)]
pub struct AppState {
    pub exiftool_pool: Arc<ExiftoolPool>,
    pub active_scans: Arc<Mutex<HashMap<String, ScanHandle>>>,
    pub default_results: Arc<Mutex<Vec<FileMetadata>>>,
}

impl AppState {
    pub fn new(exiftool_pool: Arc<ExiftoolPool>) -> Self {
        Self {
            exiftool_pool,
            active_scans: Arc::new(Mutex::new(HashMap::new())),
            default_results: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
