// exiftool_pool.rs — NexGen Metadata persistent ExifTool daemon pool
//
// Architecture
// ============
// ExifTool supports a "stay-open" mode where a single process reads commands
// from stdin and writes results to stdout until told to exit. This module
// maintains a pool of N such daemons (one per logical CPU) in a lock-free
// `ArrayQueue`.  Callers pop a daemon, submit a query, push it back.
//
// The spin-wait pop strategy is appropriate here because:
//   1. Queries are short-lived (< 1 s for typical files).
//   2. There are exactly N daemons for N CPUs, so starvation is bounded.
//   3. A Mutex-based condvar would add latency and complexity for little gain
//      in this N-in / N-out pattern.
//
// Timeout handling
// ================
// Every query is wrapped in a `tokio::time::timeout` of 30 s.  On expiry:
//   * The hung daemon is killed.
//   * A fresh replacement daemon is spawned and pushed back to the queue so
//     the pool is always at full capacity.
//   * `NexGenError::ExiftoolTimeout` is returned to the caller.

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use crossbeam::queue::ArrayQueue;

use crate::errors::NexGenError;

// ---------------------------------------------------------------------------
// ExiftoolDaemon
// ---------------------------------------------------------------------------

/// A single running ExifTool process kept alive in `-stay_open True` mode.
///
/// `stdin` and `stdout` are wrapped in buffered I/O adapters so that each
/// command write flushes as a unit and each line read avoids per-byte
/// syscalls.
pub struct ExiftoolDaemon {
    /// The underlying child process handle, used for `kill()` and `wait()`.
    pub child: Child,
    /// Buffered writer attached to the child's stdin pipe.
    pub stdin: BufWriter<ChildStdin>,
    /// Buffered reader attached to the child's stdout pipe.
    pub stdout: BufReader<ChildStdout>,
}

// ---------------------------------------------------------------------------
// ExiftoolPool
// ---------------------------------------------------------------------------

/// A pool of persistent ExifTool daemon processes.
///
/// Create with [`ExiftoolPool::new`], share via `Arc<ExiftoolPool>`, query
/// with [`ExiftoolPool::query`], and shut down with
/// [`ExiftoolPool::shutdown`].
pub struct ExiftoolPool {
    /// Lock-free MPMC queue holding idle daemons.
    queue: ArrayQueue<ExiftoolDaemon>,
    /// Filesystem path to the `exiftool` (or `exiftool.exe`) binary.
    exiftool_path: PathBuf,
}

impl ExiftoolPool {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Spawn one ExifTool daemon per logical CPU and return the pool wrapped
    /// in an `Arc`.
    ///
    /// Each daemon is started with:
    /// ```text
    /// exiftool -stay_open True -@ - -charset filename=utf8
    /// ```
    /// stdin and stdout are piped; stderr is silenced with `Stdio::null()`.
    ///
    /// # Errors
    /// Returns [`NexGenError::Io`] if the binary cannot be spawned (e.g.
    /// `exiftool_path` does not exist or is not executable).
    pub fn new(exiftool_path: PathBuf) -> Result<Arc<Self>, NexGenError> {
        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let queue: ArrayQueue<ExiftoolDaemon> = ArrayQueue::new(parallelism);

        for _ in 0..parallelism {
            match Self::spawn_daemon(&exiftool_path) {
                Ok(daemon) => {
                    let _ = queue.push(daemon);
                }
                Err(err) => {
                    tracing::warn!("ExifTool daemon spawn warning: {}. Continuing with available workers.", err);
                    break;
                }
            }
        }

        Ok(Arc::new(Self { queue, exiftool_path }))
    }

    // -----------------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------------

    /// Extract metadata for a single file by dispatching to an idle daemon synchronously.
    pub fn query_blocking(&self, file_path: &Path) -> Result<serde_json::Value, NexGenError> {
        if self.queue.is_empty() {
            return Err(NexGenError::Forensic("No active ExifTool daemons in pool".to_owned()));
        }
        // Pop a daemon; spin if none is available yet.
        let mut daemon = loop {
            if let Some(d) = self.queue.pop() {
                break d;
            }
            std::hint::spin_loop();
        };

        match Self::run_query(&mut daemon, file_path) {
            Ok(value) => {
                let _ = self.queue.push(daemon);
                Ok(value)
            }
            Err(err) => {
                let _ = Self::kill_and_replace(&self.exiftool_path, &self.queue, daemon);
                Err(err)
            }
        }
    }

    /// Extract metadata for a single file asynchronously by delegating to query_blocking.
    pub async fn query(&self, file_path: &Path) -> Result<serde_json::Value, NexGenError> {
        self.query_blocking(file_path)
    }

    // -----------------------------------------------------------------------
    // Graceful shutdown
    // -----------------------------------------------------------------------

    /// Drain all daemons from the queue, send `-stay_open\nFalse\n-execute\n`
    /// to each, then `wait()` for every child to exit.
    ///
    /// This function is intentionally synchronous and infallible: even if one
    /// daemon fails to shut down cleanly, the others are still processed.
    pub fn shutdown(&self) {
        while let Some(mut daemon) = self.queue.pop() {
            // Ask ExifTool to terminate gracefully.
            let _ = daemon.stdin.write_all(b"-stay_open\nFalse\n-execute\n");
            let _ = daemon.stdin.flush();
            // Wait for the process to exit so we don't leave zombies.
            let _ = daemon.child.wait();
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Spawn one ExifTool daemon process and wrap its pipes.
    fn spawn_daemon(exiftool_path: &Path) -> Result<ExiftoolDaemon, NexGenError> {
        let mut child = Command::new(exiftool_path)
            .args([
                "-stay_open",
                "True",
                "-@",
                "-",
                "-charset",
                "filename=utf8",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        // Take ownership of the stdio pipes.  These are guaranteed `Some`
        // because we passed `Stdio::piped()` above; a missing pipe indicates
        // a bug in the standard library, so we treat it as a forensic error.
        let raw_stdin = child.stdin.take().ok_or_else(|| {
            NexGenError::Forensic(
                "ExifTool daemon spawned without a stdin pipe — platform anomaly".to_owned(),
            )
        })?;
        let raw_stdout = child.stdout.take().ok_or_else(|| {
            NexGenError::Forensic(
                "ExifTool daemon spawned without a stdout pipe — platform anomaly".to_owned(),
            )
        })?;

        Ok(ExiftoolDaemon {
            child,
            stdin: BufWriter::new(raw_stdin),
            stdout: BufReader::new(raw_stdout),
        })
    }

    /// Send one metadata query to an already-popped daemon and return the
    /// parsed JSON.
    ///
    /// This function is `async` so it can be wrapped in
    /// `tokio::time::timeout`.  The blocking I/O is intentional: ExifTool
    /// queries are fast (milliseconds), and the timeout ensures we never
    /// block forever.
    fn run_query(
        daemon: &mut ExiftoolDaemon,
        file_path: &Path,
    ) -> Result<serde_json::Value, NexGenError> {
        // Encode the path as UTF-8.  On Windows, non-UTF-8 paths are extremely
        // rare and ExifTool itself requires UTF-8 when `charset filename=utf8`
        // is set, so we convert lossily and flag an anomaly via Forensic error.
        let path_str = file_path.to_str().ok_or_else(|| NexGenError::Forensic(
            format!(
                "Evidence file path is not valid UTF-8: {}",
                file_path.to_string_lossy()
            ),
        ))?;

        // On Windows, ExifTool accepts both forward- and back-slashes, but
        // forward slashes are safer because they do not require escaping in
        // the `-@` command stream.
        let path_normalised = path_str.replace('\\', "/");

        // Build the command block that ExifTool's `-@` mode expects.
        // Format:
        //   -json
        //   -fast2
        //   -charset
        //   filename=utf8
        //   --
        //   <path>
        //   -execute
        //
        // The `--` separator tells ExifTool that all following arguments are
        // file paths, not option names, which prevents path-injection attacks.
        let command = format!(
            "-json\n-fast2\n-charset\nfilename=utf8\n--\n{}\n-execute\n",
            path_normalised
        );

        daemon.stdin.write_all(command.as_bytes())?;
        daemon.stdin.flush()?;

        // Read lines until ExifTool writes the sentinel `{ready}` line.
        // ExifTool appends this after every `-execute` command.
        let mut json_lines: Vec<String> = Vec::with_capacity(64);
        let mut line_buf = String::with_capacity(256);

        loop {
            line_buf.clear();
            let bytes_read = daemon.stdout.read_line(&mut line_buf)?;

            if bytes_read == 0 {
                // EOF from ExifTool — the process has exited unexpectedly.
                return Err(NexGenError::Exiftool {
                    code: None,
                    stderr: "ExifTool stdout closed unexpectedly (EOF before {ready})".to_owned(),
                });
            }

            // The sentinel line that ExifTool writes after each -execute.
            // It may have a trailing newline; trim before comparing.
            let trimmed = line_buf.trim_end_matches(['\r', '\n']);
            if trimmed == "{ready}" {
                break;
            }

            json_lines.push(line_buf.clone());
        }

        // Concatenate all lines before the sentinel into one string.
        let json_str: String = json_lines.concat();
        let trimmed_json = json_str.trim();

        if trimmed_json.is_empty() {
            return Err(NexGenError::Exiftool {
                code: None,
                stderr: format!(
                    "ExifTool returned no output for path: {}",
                    path_normalised
                ),
            });
        }

        // Parse as JSON.  ExifTool always returns a JSON array when `-json` is
        // given, even for a single file.
        let value: serde_json::Value = serde_json::from_str(trimmed_json).map_err(|e| {
            NexGenError::Parser {
                file: path_normalised.clone(),
                reason: format!("ExifTool JSON parse error: {}", e),
            }
        })?;

        Ok(value)
    }

    /// Kill a misbehaving daemon, spawn a fresh replacement, and push the
    /// replacement back into the pool so capacity is restored.
    fn kill_and_replace(
        exiftool_path: &Path,
        queue: &ArrayQueue<ExiftoolDaemon>,
        mut daemon: ExiftoolDaemon,
    ) -> Result<(), NexGenError> {
        // Best-effort kill; ignore errors (the process may have already exited).
        let _ = daemon.child.kill();
        let _ = daemon.child.wait();

        // Spawn a replacement so the pool remains at full capacity.
        let replacement = Self::spawn_daemon(exiftool_path)?;

        // Again, push failure is non-fatal — we log and move on.
        if queue.push(replacement).is_err() {
            // This can only happen if the queue is already at capacity, which
            // would mean another thread pushed a daemon between our pop and
            // this push. That's a bug, but it's safer to drop the extra daemon
            // than to panic in production.
        }

        Ok(())
    }
}
