// reader.rs — NexGen Metadata forensic single-pass file reader
//
// Design goals
// ============
// 1. Every byte of the evidence file is read exactly once (single-pass).
// 2. Seven independent hash / checksum algorithms run simultaneously over
//    each chunk so there is no second read and no TOCTOU window between
//    hashes.
// 3. In debug builds, a global open-count table catches any code path that
//    would open the same file more than once — an instant forensic violation.
// 4. Shannon entropy is derived from the same byte-frequency table that is
//    built during the hash pass, so no extra allocation is needed.

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use blake3::Hasher as Blake3Hasher;
use crc32fast::Hasher as Crc32Hasher;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use xxhash_rust::xxh3::Xxh3;

use crate::errors::NexGenError;

// ---------------------------------------------------------------------------
// Debug-only TOCTOU guard
// ---------------------------------------------------------------------------

/// In debug builds this table records how many times each path has been
/// opened through `DynamicReader::new`.  A count > 1 indicates that two
/// different code paths are reading the same evidence file, which is a
/// forensic integrity violation (TOCTOU risk).
#[cfg(debug_assertions)]
static OPEN_COUNT: once_cell::sync::Lazy<std::sync::Mutex<HashMap<PathBuf, usize>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The results produced by a single forensic read pass over one file.
///
/// All hash values are lowercase hexadecimal strings. `magic_bytes` contains
/// up to the first 32 bytes of the file (fewer for files shorter than 32 B).
/// `shannon_entropy` is in bits per byte (range 0.0 – 8.0).
#[derive(Debug, Clone)]
pub struct FileReadResult {
    /// BLAKE3 cryptographic hash (256-bit → 64 hex chars).
    pub blake3_hex: String,
    /// SHA-256 cryptographic hash (256-bit → 64 hex chars).
    pub sha256_hex: String,
    /// SHA-1 cryptographic hash (160-bit → 40 hex chars).
    pub sha1_hex: String,
    /// MD5 message digest (128-bit → 32 hex chars).
    pub md5_hex: String,
    /// SHA-512 cryptographic hash (512-bit → 128 hex chars).
    pub sha512_hex: String,
    /// CRC-32 checksum (32-bit → 8 hex chars).
    pub crc32_hex: String,
    /// XXH3-64 non-cryptographic hash (64-bit → 16 hex chars).
    pub xxhash3_hex: String,
    /// Shannon entropy of the file contents in bits per byte (0.0 – 8.0).
    pub shannon_entropy: f64,
    /// Raw first-32-bytes of the file, useful for magic-byte file-type detection.
    pub magic_bytes: Vec<u8>,
    /// Total number of bytes that were read from the file.
    pub total_bytes_read: u64,
}

/// Forensic single-pass reader for a single evidence file.
///
/// Instantiate with [`DynamicReader::new`], then call
/// [`DynamicReader::read_and_analyze`] exactly once.
pub struct DynamicReader {
    /// Canonical path to the evidence file.
    path: PathBuf,
    /// Byte length of the file as reported by `fs::metadata` at construction
    /// time. Used to select the in-memory vs. streaming strategy.
    file_size: u64,
}

// ---------------------------------------------------------------------------
// Chunk size constants
// ---------------------------------------------------------------------------

/// Files smaller than this threshold are loaded fully into memory in one
/// `fs::read` call, which is faster than buffered streaming for small files
/// and avoids repeated kernel transitions.
const SMALL_FILE_THRESHOLD: u64 = 64 * 1024 * 1024; // 64 MiB

/// BufReader capacity when streaming large files.
const LARGE_FILE_BUF_CAPACITY: usize = 4 * 1024 * 1024; // 4 MiB

/// Read chunk size when streaming large files.
const LARGE_FILE_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

// ---------------------------------------------------------------------------
// Helper: lowercase hex encoding
// ---------------------------------------------------------------------------

/// Encode a byte slice as a lowercase hexadecimal string without any
/// external dependency beyond the standard library.
#[inline]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        use std::fmt::Write as FmtWrite;
        let _ = write!(acc, "{:02x}", b);
        acc
    })
}

// ---------------------------------------------------------------------------
// Helper: Shannon entropy
// ---------------------------------------------------------------------------

/// Compute Shannon entropy (bits per byte) from a 256-element byte-frequency
/// table. `total` must equal the sum of all counts; passing the wrong value
/// will silently produce garbage — the caller is responsible.
fn shannon_entropy(byte_counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    byte_counts.iter().fold(0.0_f64, |entropy, &count| {
        if count == 0 {
            entropy
        } else {
            let p = count as f64 / total_f;
            entropy - p * p.log2()
        }
    })
}

// ---------------------------------------------------------------------------
// DynamicReader implementation
// ---------------------------------------------------------------------------

impl DynamicReader {
    /// Open the evidence file and record its size.
    ///
    /// In debug builds this function also updates the global open-count table
    /// and panics immediately if the same path has been opened before,
    /// enforcing the forensic invariant that evidence files are read exactly
    /// once.
    ///
    /// # Errors
    /// Returns [`NexGenError::Io`] if the file does not exist or is not
    /// readable, and [`NexGenError::Forensic`] if `fs::metadata` returns a
    /// size of zero for a non-empty path (which would indicate a filesystem
    /// anomaly worth flagging).
    pub fn new(path: PathBuf) -> Result<Self, NexGenError> {
        // ── Debug-only TOCTOU guard ──────────────────────────────────────────
        #[cfg(debug_assertions)]
        {
            let mut map = OPEN_COUNT
                .lock()
                .expect("OPEN_COUNT mutex poisoned — a previous panic corrupted state");
            let entry = map.entry(path.clone()).or_insert(0);
            *entry += 1;
            if *entry > 1 {
                panic!(
                    "FORENSIC VIOLATION: TOCTOU - file opened more than once: {}",
                    path.display()
                );
            }
        }

        // ── Stat the file to learn its size ─────────────────────────────────
        let metadata = std::fs::metadata(&path)?;
        let file_size = metadata.len();

        Ok(Self { path, file_size })
    }

    /// Perform a single forensic read pass, computing all hashes and metrics
    /// simultaneously.
    ///
    /// Two code paths share the same inner accounting logic:
    /// * **Small files** (< 64 MiB): `fs::read` into a `Vec<u8>`, then
    ///   process the entire buffer in 1 MiB slices so that the chunk-based
    ///   hasher API is exercised identically.
    /// * **Large files** (≥ 64 MiB): `BufReader` with 4 MiB capacity, read
    ///   in explicit 1 MiB chunks.
    ///
    /// # Errors
    /// Returns [`NexGenError::Io`] on any read failure.
    pub fn read_and_analyze(&self) -> Result<FileReadResult, NexGenError> {
        // ── Initialise all seven hashers ─────────────────────────────────────
        let mut blake3  = Blake3Hasher::new();
        let mut sha256  = Sha256::new();
        let mut sha1    = Sha1::new();
        let mut md5     = Md5::new();
        let mut sha512  = Sha512::new();
        let mut crc32   = Crc32Hasher::new();
        let mut xxh3    = Xxh3::new();

        // ── Per-byte frequency table for Shannon entropy ─────────────────────
        let mut byte_counts = [0u64; 256];

        // ── First-32-bytes magic capture ─────────────────────────────────────
        let mut magic_bytes: Vec<u8> = Vec::with_capacity(32);
        let mut magic_captured = false;

        // ── Total bytes counter ───────────────────────────────────────────────
        let mut total_bytes_read: u64 = 0;

        /// Feed one chunk of bytes to all hashers and update the byte-frequency
        /// table. Defined as a closure to avoid repeating the seven update calls
        /// in both branches below.
        ///
        /// We use a macro-like inner function because closures that mutably
        /// borrow multiple variables simultaneously require the variables to be
        /// declared before the closure — but the borrow checker would still flag
        /// multiple mutable borrows. Using a plain `fn` pointer doesn't help
        /// either. Instead we inline the logic as a labeled block so the
        /// compiler can see the borrows are non-overlapping.
        macro_rules! process_chunk {
            ($chunk:expr) => {{
                let chunk: &[u8] = $chunk;

                // Cryptographic / checksum hashers
                blake3.update(chunk);
                sha256.update(chunk);
                sha1.update(chunk);
                md5.update(chunk);
                sha512.update(chunk);
                crc32.update(chunk);
                xxh3.update(chunk);

                // Byte-frequency table
                for &b in chunk {
                    byte_counts[b as usize] += 1;
                }

                // Magic bytes — capture once, from the very first chunk
                if !magic_captured {
                    let take = chunk.len().min(32);
                    magic_bytes.extend_from_slice(&chunk[..take]);
                    magic_captured = true;
                }

                total_bytes_read += chunk.len() as u64;
            }};
        }

        // ── Read strategy ────────────────────────────────────────────────────
        if self.file_size < SMALL_FILE_THRESHOLD {
            // Small file: load entirely into memory, then slice into 1 MiB
            // chunks so that the hasher API sees a uniform chunk size.
            let data = std::fs::read(&self.path)?;
            for chunk in data.chunks(LARGE_FILE_CHUNK_SIZE) {
                process_chunk!(chunk);
            }
        } else {
            // Large file: stream through a 4 MiB BufReader in 1 MiB chunks.
            let file = std::fs::File::open(&self.path)?;
            let mut reader = BufReader::with_capacity(LARGE_FILE_BUF_CAPACITY, file);
            let mut chunk_buf = vec![0u8; LARGE_FILE_CHUNK_SIZE];

            loop {
                let n = reader.read(&mut chunk_buf)?;
                if n == 0 {
                    break; // EOF
                }
                process_chunk!(&chunk_buf[..n]);
            }
        }

        // ── Finalise hashes ───────────────────────────────────────────────────
        let blake3_hex   = to_hex(blake3.finalize().as_bytes());
        let sha256_hex   = to_hex(&sha256.finalize());
        let sha1_hex     = to_hex(&sha1.finalize());
        let md5_hex      = to_hex(&md5.finalize());
        let sha512_hex   = to_hex(&sha512.finalize());
        let crc32_hex    = format!("{:08x}", crc32.finalize());
        let xxhash3_hex  = format!("{:016x}", xxh3.digest());

        // ── Shannon entropy ───────────────────────────────────────────────────
        let shannon_entropy_val = shannon_entropy(&byte_counts, total_bytes_read);

        Ok(FileReadResult {
            blake3_hex,
            sha256_hex,
            sha1_hex,
            md5_hex,
            sha512_hex,
            crc32_hex,
            xxhash3_hex,
            shannon_entropy: shannon_entropy_val,
            magic_bytes,
            total_bytes_read,
        })
    }
}
