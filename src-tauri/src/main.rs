//! main.rs — NexGen Metadata Standalone Headless Server Binary
//!
//! This binary is for running NexGen as a pure local web server without a
//! native desktop window (e.g. for server deployments, batch automation, or CI).
//!
//! For the full native desktop app experience with a WebView window,
//! use the `nexgen-desktop` binary built by the Tauri target instead.

use nexgen_metadata::run_axum_server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("NexGen Metadata — Standalone Server Mode");

    // Safe extraction: verify or unpack ExifTool to %LOCALAPPDATA%\NexGen\bin at boot
    match nexgen_metadata::exiftool_pool::ensure_exiftool_provisioned() {
        Ok(path) => tracing::info!("✓ ExifTool verified in persistent safe directory: {}", path.display()),
        Err(err) => tracing::warn!("ExifTool provisioning note: {}", err),
    }

    run_axum_server().await.map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())) as Box<dyn std::error::Error>)
}
