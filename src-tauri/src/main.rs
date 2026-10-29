//! main.rs — NexGen Metadata Local Web Server (Axum + Tokio + SSE)
//!
//! Replaces native desktop windowing with a strictly local web service:
//!   - Binds strictly to `127.0.0.1:8080` (rejects 0.0.0.0 to prevent LAN snooping).
//!   - Serves React SPA static assets from `./dist` with SPA fallback.
//!   - Real-time Server-Sent Events (SSE) progress streaming via Tokio broadcast channels.
//!   - Cryptographic Ed25519 License Gate and JWT middleware protection on all `/api/*` routes.

mod api;
mod auth;
mod database;
mod errors;
mod exiftool_pool;
mod export;
mod forensics;
mod models;
mod parsers;
mod reader;
mod scanner;
mod state;

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
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!("Initializing NexGen Metadata Local Web Server...");

    // Locate or bundle exiftool daemon
    let exiftool_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("exiftool.exe")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("exiftool.exe"));

    let exiftool_pool = ExiftoolPool::new(exiftool_path)
        .expect("Failed to initialize ExifTool worker daemon pool");

    let app_state = AppState::new(exiftool_pool);

    // Permissive CORS for local Vite dev server testing (localhost:5173)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    // Public API routes
    let public_routes = Router::new()
        .route("/api/activate", post(handle_activate))
        .route("/api/verify", get(handle_verify_token))
        .route("/api/health", get(|| async { "OK" }));

    // Protected API routes
    let protected_routes = create_api_router()
        .layer(middleware::from_fn(auth_middleware));

    // Serve static files from ./dist with SPA fallback to index.html
    let dist_dir = PathBuf::from("./dist");
    let static_service = ServeDir::new(&dist_dir)
        .fallback(tower_http::services::ServeFile::new(dist_dir.join("index.html")));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .nest_service("/", static_service)
        .layer(cors)
        .with_state(app_state);

    // STRICT CONSTRAINT: Bind exclusively to 127.0.0.1 (Never 0.0.0.0)
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("============================================================");
    info!("🚀 NexGen Metadata Local Web Server active!");
    info!("   Access URL: http://{}", addr);
    info!("   Binding:    127.0.0.1 (STRICT LOCALHOST ONLY)");
    info!("============================================================");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// POST /api/activate — Verifies Ed25519 license key and issues a 72-hour session JWT
async fn handle_activate(
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

/// GET /api/verify — Quick verification that an existing stored JWT is still valid
async fn handle_verify_token(
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
