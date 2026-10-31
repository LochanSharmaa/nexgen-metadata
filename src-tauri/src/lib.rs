//! lib.rs — NexGen Metadata Core Engine Library
//!
//! Exposes the Axum HTTP server as a callable async function so it can be
//! spawned as a background task from either:
//!   - The standalone `nexgen-server` binary (headless / server mode), or
//!   - The Tauri desktop wrapper (windowed native desktop app mode).

pub mod api;
pub mod auth;
pub mod database;
pub mod errors;
pub mod exiftool_pool;
pub mod export;
pub mod field_mapper;
pub mod forensics;
pub mod models;
pub mod parsers;
pub mod reader;
pub mod scanner;
pub mod state;

use api::create_api_router;
use auth::{auth_middleware, mint_jwt, validate_jwt, ActivationRequest, ActivationResponse, Claims};
use axum::{
    http::{header, Method, StatusCode},
    middleware,
    routing::{get, post},
    Json, Router,
};
use exiftool_pool::ExiftoolPool;
use state::AppState;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

#[derive(rust_embed::RustEmbed)]
#[folder = "../dist"]
struct DistAssets;

async fn static_handler(uri: axum::http::Uri) -> axum::response::Response {
    let path = uri.path().trim_start_matches('/');
    let target = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = DistAssets::get(target) {
        let mime = get_mime_type(target);
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .header(header::PRAGMA, "no-cache")
            .header(header::EXPIRES, "0")
            .body(axum::body::Body::from(file.data))
            .unwrap();
    }

    // SPA fallback: return index.html for all non-matching routes
    if let Some(index) = DistAssets::get("index.html") {
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
            .header(header::PRAGMA, "no-cache")
            .header(header::EXPIRES, "0")
            .body(axum::body::Body::from(index.data))
            .unwrap();
    }

    axum::response::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(axum::body::Body::from("404 Not Found"))
        .unwrap()
}

fn get_mime_type(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else {
        "application/octet-stream"
    }
}

/// Build and return the fully configured Axum router bound to the shared AppState.
/// Used by both the standalone server and the Tauri desktop wrapper.
pub fn build_router(app_state: AppState) -> Router {
    use tower_http::cors::{Any, CorsLayer};

    let cors_layer = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    // Public API routes (no auth required)
    let public_routes = Router::new()
        .route("/api/activate", post(handle_activate))
        .route("/api/verify", get(handle_verify_token))
        .route("/api/health", get(|| async { "OK" }));

    // Protected forensic API routes (JWT required)
    let protected_routes = create_api_router()
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .fallback(static_handler)
        .layer(cors_layer)
        .with_state(app_state)
}

/// Initialise ExifTool pool, construct AppState, build the router and start
/// the Axum listener on `127.0.0.1:8080`.
///
/// This is `pub` so the Tauri wrapper can `tokio::spawn` it as a background task.
pub async fn run_axum_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Safe persistent extraction: resolve %LOCALAPPDATA%\NexGen\bin and unpack embedded suite if needed
    let exiftool_path = exiftool_pool::ensure_exiftool_provisioned()
        .unwrap_or_else(|e| {
            tracing::warn!("Embedded safe extraction warning: {}. Checking executable dir/PATH.", e);
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("exiftool.exe")))
                .filter(|p| p.exists())
                .unwrap_or_else(|| PathBuf::from("exiftool.exe"))
        });

    let exiftool_pool = ExiftoolPool::new(exiftool_path)
        .expect("Failed to initialize ExifTool worker daemon pool");

    let app_state = AppState::new(exiftool_pool);
    let app = build_router(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("============================================================");
    info!("🚀 NexGen Metadata engine active at http://{}", addr);
    info!("============================================================");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth Route Handlers (shared by both binary modes)
// ─────────────────────────────────────────────────────────────────────────────

/// POST /api/activate — Verifies Ed25519 license key and issues a 72h JWT
pub async fn handle_activate(
    Json(payload): Json<ActivationRequest>,
) -> Result<Json<ActivationResponse>, (StatusCode, Json<serde_json::Value>)> {
    match auth::verify_license_key(&payload.license_key) {
        Ok(lic) => {
            let token = mint_jwt(&lic).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e })),
                )
            })?;
            Ok(Json(ActivationResponse {
                token,
                customer: lic.customer_id,
                plan: lic.plan,
                expires_at: lic.expires_at,
            }))
        }
        Err(err) => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Invalid License Key", "details": err })),
        )),
    }
}

/// GET /api/verify — Quick validation of an existing session JWT
pub async fn handle_verify_token(
    req: axum::extract::Request,
) -> Result<Json<Claims>, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "valid": false })))),
    };

    match validate_jwt(token) {
        Ok(claims) => Ok(Json(claims)),
        Err(_) => Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "valid": false })))),
    }
}
