//! api.rs — HTTP & SSE Route Handlers for NexGen Metadata.
//!
//! Exposes:
//!   - POST /api/scan/start
//!   - POST /api/scan/cancel
//!   - GET  /api/scan/status/:scan_id (Server-Sent Events)
//!   - GET  /api/scan/export/:scan_id (Direct File Download Stream)
//!   - GET  /api/scan/records/:scan_id (Paginated Table View)

use crate::auth::{mint_jwt, validate_jwt, ActivationRequest, ActivationResponse, Claims};
use crate::database::create_database;
use crate::export::{export_csv, export_json, export_xlsx, generate_manifest};
use crate::models::FileMetadata;
use crate::scanner::{start_scan, ScanProgress};
use crate::state::{AppState, ScanHandle};
use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;
use tokio_util::io::ReaderStream;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct StartScanRequest {
    pub folder_path: String,
    pub recursive: Option<bool>,
    pub include_hidden: Option<bool>,
    pub fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CancelScanRequest {
    pub scan_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    pub page: Option<usize>,
    pub page_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub format: Option<String>,
}

pub fn create_api_router() -> Router<AppState> {
    Router::new()
        .route("/api/scan/start", post(handle_start_scan))
        .route("/api/scan/cancel", post(handle_cancel_scan))
        .route("/api/scan/status/{scan_id}", get(handle_scan_status_sse))
        .route("/api/scan/export/{scan_id}", get(handle_export_download))
        .route("/api/scan/records/{scan_id}", get(handle_get_records))
        // Backwards-compatible routes
        .route("/api/scan", post(handle_start_scan_compat))
        .route("/api/cancel", post(handle_cancel_scan_compat))
        .route("/api/status", get(handle_status_compat))
        .route("/api/records", get(handle_records_compat))
        .route("/api/export", post(handle_export_compat))
}

/// POST /api/scan/start — Initializes a unique scan session
pub async fn handle_start_scan(
    State(state): State<AppState>,
    Json(payload): Json<StartScanRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if payload.folder_path.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Target folder path cannot be empty." })),
        ));
    }

    let scan_id = Uuid::new_v4().to_string();
    let cancel_token = CancellationToken::new();
    let (progress_tx, _progress_rx) = broadcast::channel::<ScanProgress>(1000);
    let results_store = Arc::new(Mutex::new(Vec::new()));

    let target_folder = PathBuf::from(&payload.folder_path);

    // Prepare SQLite database file for this specific scan
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("nexgen_{}.db", scan_id));
    let db_writer = create_database(&db_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Failed to create SQLite database: {}", e) })),
        )
    })?;

    let scan_handle = ScanHandle {
        scan_id: scan_id.clone(),
        target_folder: target_folder.clone(),
        cancel_token: cancel_token.clone(),
        progress_tx: progress_tx.clone(),
        results: Arc::clone(&results_store),
    };

    // Register active scan handle in global state
    state
        .active_scans
        .lock()
        .await
        .insert(scan_id.clone(), scan_handle);

    let exiftool_pool = Arc::clone(&state.exiftool_pool);
    let recursive = payload.recursive.unwrap_or(true);
    let include_hidden = payload.include_hidden.unwrap_or(false);
    let selected_fields = payload.fields.unwrap_or_default();
    let folder_str = payload.folder_path.clone();

    // Spawn async worker pipeline
    tokio::spawn(async move {
        let _ = start_scan(
            folder_str,
            recursive,
            include_hidden,
            selected_fields,
            cancel_token,
            progress_tx,
            exiftool_pool,
            db_writer,
            results_store,
        )
        .await;
    });

    info!("Spawned background scan pipeline. Scan ID: {}", scan_id);
    Ok(Json(serde_json::json!({
        "scan_id": scan_id,
        "status": "started"
    })))
}

/// POST /api/scan/cancel — Cancels an in-flight scan
pub async fn handle_cancel_scan(
    State(state): State<AppState>,
    Json(payload): Json<CancelScanRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let active = state.active_scans.lock().await;
    if let Some(handle) = active.get(&payload.scan_id) {
        handle.cancel_token.cancel();
        info!("Issued cancellation token for scan: {}", payload.scan_id);
        Ok(Json(serde_json::json!({
            "scan_id": payload.scan_id,
            "status": "cancelled"
        })))
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Active scan ID not found" })),
        ))
    }
}

/// GET /api/scan/status/:scan_id — SSE Stream yielding progress every 100ms
pub async fn handle_scan_status_sse(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let active = state.active_scans.lock().await;
    let handle = active.get(&scan_id).ok_or(StatusCode::NOT_FOUND)?;
    let mut rx = handle.progress_tx.subscribe();

    let stream = async_stream::stream! {
        while let Ok(progress) = rx.recv().await {
            let is_terminal = progress.status == "Completed" || progress.status == "Cancelled";
            if let Ok(json_str) = serde_json::to_string(&progress) {
                yield Ok(Event::default().data(json_str));
            }
            if is_terminal {
                break;
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// GET /api/scan/export/:scan_id — Direct file download stream
pub async fn handle_export_download(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<String>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let format = query.format.unwrap_or_else(|| "csv".to_string()).to_lowercase();
    let active = state.active_scans.lock().await;
    let handle = active.get(&scan_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Scan session not found" })),
        )
    })?;

    let records = handle.results.lock().await.clone();
    if records.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Cannot export empty scan dataset: no records found." })),
        ));
    }
    let temp_dir = std::env::temp_dir();
    let filename = format!("nexgen_scan_{}.{}", scan_id, format);
    let export_path = temp_dir.join(&filename);

    match format.as_str() {
        "csv" => export_csv(&records, &export_path).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?,
        "json" => export_json(&records, &export_path).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?,
        "xlsx" => export_xlsx(&records, &export_path).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        })?,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Unsupported format: {}", other) })),
            ))
        }
    }

    // Cryptographic Chain of Custody Manifest
    let _ = generate_manifest(&export_path, records.len() as u64, &scan_id);

    let file = tokio::fs::File::open(&export_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Cannot open export file: {}", e) })),
        )
    })?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let content_type = match format.as_str() {
        "csv" => "text/csv; charset=utf-8",
        "json" => "application/json",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename)).unwrap(),
    );

    Ok((headers, body).into_response())
}

/// GET /api/scan/records/:scan_id — Paginated table viewport
pub async fn handle_get_records(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<String>,
    Query(query): Query<RecordsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let page = query.page.unwrap_or(0);
    let page_size = query.page_size.unwrap_or(100);

    let active = state.active_scans.lock().await;
    let handle = active.get(&scan_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Scan session not found" })),
        )
    })?;

    let records = handle.results.lock().await;
    let total = records.len();
    let start = page * page_size;

    let items: Vec<FileMetadata> = if start >= total {
        Vec::new()
    } else {
        let end = (start + page_size).min(total);
        records[start..end].to_vec()
    };

    Ok(Json(serde_json::json!({
        "scan_id": scan_id,
        "records": items,
        "total": total,
        "page": page,
        "page_size": page_size
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// Compatibility Handlers for General Endpoints
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_start_scan_compat(
    State(state): State<AppState>,
    Json(payload): Json<crate::scanner::ScanConfig>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let req = StartScanRequest {
        folder_path: payload.root_path.to_string_lossy().to_string(),
        recursive: Some(payload.recursive),
        include_hidden: Some(payload.include_hidden),
        fields: Some(payload.selected_fields),
    };
    handle_start_scan(State(state), Json(req)).await
}

async fn handle_cancel_scan_compat(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let active = state.active_scans.lock().await;
    for handle in active.values() {
        handle.cancel_token.cancel();
    }
    Json(serde_json::json!({ "status": "cancelling_all" }))
}

async fn handle_status_compat(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let active = state.active_scans.lock().await;
    let rx = if let Some(first) = active.values().next() {
        first.progress_tx.subscribe()
    } else {
        let (tx, rx) = broadcast::channel(1);
        let _ = tx.send(ScanProgress {
            scanned_files: 0,
            total_files: 0,
            current_file: "IDLE".to_string(),
            percentage: 0.0,
            status: "Idle".to_string(),
            errors: 0,
            elapsed_ms: 0,
        });
        rx
    };

    let mut rx_stream = rx;
    let stream = async_stream::stream! {
        while let Ok(progress) = rx_stream.recv().await {
            if let Ok(json_str) = serde_json::to_string(&progress) {
                yield Ok(Event::default().data(json_str));
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn handle_records_compat(
    State(state): State<AppState>,
    Query(query): Query<RecordsQuery>,
) -> Json<serde_json::Value> {
    let active = state.active_scans.lock().await;
    let page = query.page.unwrap_or(0);
    let page_size = query.page_size.unwrap_or(100);

    if let Some(first) = active.values().next() {
        let records = first.results.lock().await;
        let total = records.len();
        let start = page * page_size;
        let items = if start >= total {
            Vec::new()
        } else {
            let end = (start + page_size).min(total);
            records[start..end].to_vec()
        };
        Json(serde_json::json!({
            "records": items,
            "total": total,
            "page": page,
            "page_size": page_size
        }))
    } else {
        Json(serde_json::json!({
            "records": [],
            "total": 0,
            "page": page,
            "page_size": page_size
        }))
    }
}

#[derive(Deserialize)]
struct ExportCompatReq {
    format: String,
    output_path: Option<String>,
}

async fn handle_export_compat(
    State(state): State<AppState>,
    Json(payload): Json<ExportCompatReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let active = state.active_scans.lock().await;
    if let Some(first) = active.values().next() {
        let scan_id = first.scan_id.clone();
        let records = first.results.lock().await.clone();
        let format = payload.format.to_lowercase();
        let out_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let filename = format!("{}_export.{}", scan_id, format);
        let output_path = payload
            .output_path
            .map(PathBuf::from)
            .unwrap_or_else(|| out_dir.join(&filename));

        match format.as_str() {
            "csv" => export_csv(&records, &output_path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))))?,
            "json" => export_json(&records, &output_path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))))?,
            "xlsx" => export_xlsx(&records, &output_path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))))?,
            other => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": format!("Unsupported format: {}", other) })))),
        }

        let manifest = generate_manifest(&output_path, records.len() as u64, &scan_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))))?;

        Ok(Json(serde_json::json!({
            "status": "success",
            "file_path": output_path.to_string_lossy(),
            "manifest": manifest
        })))
    } else {
        Err((StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "No active scan" }))))
    }
}
