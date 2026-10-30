#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! nexgen-desktop.rs — NexGen Metadata Tauri v2 Desktop Application Entry Point
//!
//! This binary wraps the existing Axum forensic engine and React SPA inside a
//! native Tauri WebView window. Architecture:
//!
//!   1. Tauri `setup` hook spawns the Axum server as a background Tokio task.
//!   2. The Tauri WebView window is configured to load `http://127.0.0.1:8080`.
//!   3. All forensic API logic, license verification, and file scanning happens
//!      entirely in the Axum layer — Tauri is purely the native window frame.
//!
//! This approach means:
//!   - Zero IPC overhead (WebView talks HTTP to the local Axum server directly).
//!   - The React UI is identical between the browser and desktop modes.
//!   - Tauri handles OS-native menus, window chrome, tray icon, and lifecycle.

use nexgen_metadata::run_axum_server;
use tauri::Emitter;
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize structured logging (respects RUST_LOG env var).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Safe persistent extraction to %LOCALAPPDATA%\NexGen\bin (avoiding %TEMP%)
            match nexgen_metadata::exiftool_pool::ensure_exiftool_provisioned() {
                Ok(path) => tracing::info!("✓ ExifTool verified in persistent safe directory: {}", path.display()),
                Err(err) => tracing::warn!("ExifTool safe provisioning note: {}", err),
            }

            let app_handle = app.handle().clone();

            // ─── Spawn the Axum forensic engine in the background ───────────
            // We use tokio::spawn so the Tauri event loop remains responsive.
            // The Axum server runs for the lifetime of the app; if it exits
            // unexpectedly, we log the error (the window will show a net error).
            tauri::async_runtime::spawn(async move {
                tracing::info!("NexGen Metadata forensic engine starting...");
                if let Err(e) = run_axum_server().await {
                    tracing::error!("Axum server terminated unexpectedly: {}", e);
                    // Emit an event so the frontend can show an error state
                    let _ = app_handle.emit("server-error", e.to_string());
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Error while running NexGen Metadata desktop application");
}
