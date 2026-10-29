// errors.rs — NexGen Metadata unified error type
//
// Every error variant carries enough context for a forensic audit trail:
// file paths, exit codes, and free-form messages are preserved verbatim so
// they can be written to the case log without additional formatting.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Primary error enum
// ---------------------------------------------------------------------------

/// Unified error type used throughout the NexGen Metadata application.
///
/// All public APIs return `Result<T, NexGenError>`. Variants that wrap
/// lower-level library errors use `#[from]` where the conversion is
/// unambiguous; others are constructed explicitly so callers are forced to
/// include diagnostic context.
#[derive(Debug, Error)]
pub enum NexGenError {
    /// A standard I/O error propagated from the operating system or standard
    /// library. The `#[from]` attribute enables the `?` operator to convert
    /// `std::io::Error` automatically.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A SQLite / rusqlite operation failed. The inner string is the
    /// `rusqlite::Error` rendered to its `Display` form so that the database
    /// layer does not leak into the public API.
    #[error("Database error: {0}")]
    Database(String),

    /// A metadata parser encountered a malformed or unsupported file format.
    /// Both the offending `file` path and a human-readable `reason` are
    /// preserved so that triage reports can pinpoint the exact failure.
    #[error("Parse error in '{file}': {reason}")]
    Parser { file: String, reason: String },

    /// ExifTool exited with a non-zero status or produced content on stderr
    /// that indicates a hard failure. `code` is `None` when the process was
    /// killed before it could produce an exit status (e.g. after a timeout).
    #[error("ExifTool failed (exit code {code:?}): {stderr}")]
    Exiftool { code: Option<i32>, stderr: String },

    /// ExifTool did not respond within the configured deadline (30 s). The
    /// pool will kill the daemon and respawn a replacement automatically.
    #[error("ExifTool daemon timed out and was terminated")]
    ExiftoolTimeout,

    /// Writing an export artefact (CSV, JSON, PDF …) to disk failed. The
    /// inner string carries the destination path and OS error text.
    #[error("Export write failed: {0}")]
    ExportWrite(String),

    /// A cryptographic signing or verification step failed. This covers both
    /// case-package integrity signing and chain-of-custody certificate errors.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// A caller supplied a path that, after canonicalisation, would escape the
    /// configured evidence root. `attempted` is the raw (un-canonicalised)
    /// path string supplied by the caller.
    #[error("Path traversal detected: attempted path '{attempted}'")]
    PathTraversal { attempted: String },

    /// A forensic invariant was violated at runtime — e.g. a file was read
    /// more than once, a hash mismatch was detected, or a chain-of-custody
    /// record could not be written. Investigation must stop when this is
    /// raised.
    #[error("Forensic integrity error: {0}")]
    Forensic(String),
}

// ---------------------------------------------------------------------------
// Manual `From` implementations
// ---------------------------------------------------------------------------

/// Convert a `rusqlite::Error` into `NexGenError::Database`.
///
/// A manual implementation is required because `rusqlite::Error` does not
/// implement `std::error::Error` in a way that is compatible with the blanket
/// `#[from]` mechanism used by thiserror for this variant.
impl From<rusqlite::Error> for NexGenError {
    fn from(err: rusqlite::Error) -> Self {
        NexGenError::Database(err.to_string())
    }
}

/// Convert a `serde_json::Error` into `NexGenError::Parser`.
///
/// JSON parse failures always originate from a specific file, but
/// `serde_json::Error` does not carry a path. Callers that need to attach a
/// path should construct `NexGenError::Parser` directly; this blanket
/// conversion uses `"<json>"` as a sentinel file name so the `?` operator
/// remains usable in generic JSON-handling helpers.
impl From<serde_json::Error> for NexGenError {
    fn from(err: serde_json::Error) -> Self {
        NexGenError::Parser {
            file: "<json>".to_owned(),
            reason: err.to_string(),
        }
    }
}
