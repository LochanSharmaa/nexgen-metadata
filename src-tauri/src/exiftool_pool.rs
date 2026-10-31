//! exiftool_pool.rs — Synchronous ExifTool daemon pool using crossbeam-channel
//!
//! Spawns N worker threads (N = CPU cores), each maintaining a persistent
//! ExifTool process in `-stay_open` mode. Communication is 100% synchronous
//! via crossbeam unbounded channels.

use std::io::{BufRead, BufReader, BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use zip::ZipArchive;

use crossbeam::channel::{unbounded, Receiver, Sender};
use crate::errors::NexGenError;

pub static EMBEDDED_EXIFTOOL_ZIP: &[u8] = include_bytes!("exiftool.zip");

pub fn ensure_exiftool_provisioned() -> Result<PathBuf, NexGenError> {
    let target_dir = if let Some(base_dirs) = directories::BaseDirs::new() {
        base_dirs.data_local_dir().join("NexGen").join("bin")
    } else {
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\AppData".to_string());
        PathBuf::from(local_app_data).join("NexGen").join("bin")
    };

    if !target_dir.exists() {
        std::fs::create_dir_all(&target_dir)?;
        tracing::info!("Created safe persistent AppData directory: {}", target_dir.display());
    }

    let exiftool_exe = target_dir.join("exiftool.exe");
    let needs_extract = !exiftool_exe.exists()
        || std::fs::metadata(&exiftool_exe).map(|m| m.len()).unwrap_or(0) == 0;

    if needs_extract {
        tracing::info!(
            "Unpacking embedded ExifTool suite ({} bytes) to safe AppData path: {}",
            EMBEDDED_EXIFTOOL_ZIP.len(),
            target_dir.display()
        );

        let reader = Cursor::new(EMBEDDED_EXIFTOOL_ZIP);
        let mut archive = ZipArchive::new(reader).map_err(|e| {
            NexGenError::Parser {
                file: "embedded:exiftool.zip".to_string(),
                reason: format!("Failed to read embedded ExifTool zip archive: {}", e),
            }
        })?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| {
                NexGenError::Parser {
                    file: format!("zip_entry_{}", i),
                    reason: format!("Corrupt zip entry in embedded ExifTool archive: {}", e),
                }
            })?;

            let outpath = match file.enclosed_name() {
                Some(path) => target_dir.join(path),
                None => continue,
            };

            if file.is_dir() {
                std::fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        std::fs::create_dir_all(p)?;
                    }
                }
                let mut outfile = std::fs::File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }
        tracing::info!("✓ Embedded ExifTool successfully deployed to {}", exiftool_exe.display());
    }

    Ok(exiftool_exe)
}

struct WorkerTask {
    file_path: PathBuf,
    resp_tx: Sender<Result<serde_json::Value, NexGenError>>,
}

enum WorkerMessage {
    Task(WorkerTask),
    Shutdown,
}

pub struct ExiftoolPool {
    task_tx: Sender<WorkerMessage>,
    pub exiftool_path: PathBuf,
}

impl ExiftoolPool {
    pub fn new(mut exiftool_path: PathBuf) -> Result<Arc<Self>, NexGenError> {
        if !exiftool_path.exists() {
            if let Ok(safe_path) = ensure_exiftool_provisioned() {
                exiftool_path = safe_path;
            }
        }

        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let (task_tx, task_rx) = unbounded::<WorkerMessage>();

        for worker_id in 0..parallelism {
            let rx = task_rx.clone();
            let bin_path = exiftool_path.clone();

            std::thread::Builder::new()
                .name(format!("exiftool-worker-{}", worker_id))
                .spawn(move || {
                    worker_loop(rx, bin_path);
                })
                .map_err(|e| NexGenError::Forensic(format!("Failed to spawn ExifTool worker thread: {}", e)))?;
        }

        Ok(Arc::new(Self {
            task_tx,
            exiftool_path,
        }))
    }

    pub fn query_blocking(&self, file_path: &Path) -> Result<serde_json::Value, NexGenError> {
        let (resp_tx, resp_rx) = unbounded();
        self.task_tx
            .send(WorkerMessage::Task(WorkerTask {
                file_path: file_path.to_path_buf(),
                resp_tx,
            }))
            .map_err(|e| NexGenError::Forensic(format!("ExifTool pool worker channel disconnected: {}", e)))?;

        // 5-second timeout on query response
        match resp_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(res) => res,
            Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                Err(NexGenError::Forensic(format!("ExifTool query timed out for {:?}", file_path)))
            }
            Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                Err(NexGenError::Forensic("ExifTool worker disconnected unexpectedly".to_string()))
            }
        }
    }

    pub async fn query(&self, file_path: &Path) -> Result<serde_json::Value, NexGenError> {
        self.query_blocking(file_path)
    }

    pub fn shutdown(&self) {
        let _ = self.task_tx.send(WorkerMessage::Shutdown);
    }
}

fn spawn_child(exiftool_path: &Path) -> Result<(Child, BufWriter<ChildStdin>, BufReader<ChildStdout>), NexGenError> {
    let mut cmd = Command::new(exiftool_path);
    cmd.args(["-stay_open", "True", "-@", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut child = cmd.spawn()?;
    let stdin = BufWriter::new(child.stdin.take().ok_or_else(|| {
        NexGenError::Forensic("Child stdin unavailable".to_string())
    })?);
    let stdout = BufReader::new(child.stdout.take().ok_or_else(|| {
        NexGenError::Forensic("Child stdout unavailable".to_string())
    })?);

    Ok((child, stdin, stdout))
}

fn worker_loop(rx: Receiver<WorkerMessage>, exiftool_path: PathBuf) {
    let mut daemon = spawn_child(&exiftool_path);

    while let Ok(msg) = rx.recv() {
        match msg {
            WorkerMessage::Task(task) => {
                let res = match daemon.as_mut() {
                    Ok((child, stdin, stdout)) => {
                        let path_str = task.file_path.to_string_lossy().to_string();
                        let command = format!("-json\r\n-fast2\r\n{}\r\n-execute\r\n", path_str);

                        let write_res = stdin.write_all(command.as_bytes()).and_then(|_| stdin.flush());
                        if write_res.is_err() {
                            let _ = child.kill();
                            let _ = child.wait();
                            daemon = spawn_child(&exiftool_path);
                            Err(NexGenError::Forensic("Failed writing to ExifTool daemon stdin".to_string()))
                        } else {
                            let mut json_lines = Vec::new();
                            let mut line_buf = String::new();
                            let mut read_err = false;

                            loop {
                                line_buf.clear();
                                match stdout.read_line(&mut line_buf) {
                                    Ok(0) => {
                                        read_err = true;
                                        break;
                                    }
                                    Ok(_) => {
                                        let trimmed = line_buf.trim_end_matches(['\r', '\n']);
                                        if trimmed == "{ready}" {
                                            break;
                                        }
                                        json_lines.push(line_buf.clone());
                                    }
                                    Err(_) => {
                                        read_err = true;
                                        break;
                                    }
                                }
                            }

                            if read_err {
                                let _ = child.kill();
                                let _ = child.wait();
                                daemon = spawn_child(&exiftool_path);
                                Err(NexGenError::Forensic("ExifTool daemon stdout EOF or pipe failure".to_string()))
                            } else {
                                let json_str = json_lines.concat();
                                match serde_json::from_str::<serde_json::Value>(json_str.trim()) {
                                    Ok(val) => {
                                        if let Some(first) = val.as_array().and_then(|a| a.first()).cloned() {
                                            Ok(first)
                                        } else {
                                            Ok(val)
                                        }
                                    }
                                    Err(e) => Err(NexGenError::Forensic(format!("JSON parse error from ExifTool: {}", e))),
                                }
                            }
                        }
                    }
                    Err(_) => {
                        daemon = spawn_child(&exiftool_path);
                        Err(NexGenError::Forensic("ExifTool process unspawnable".to_string()))
                    }
                };
                let _ = task.resp_tx.send(res);
            }
            WorkerMessage::Shutdown => {
                if let Ok((mut child, mut stdin, _)) = daemon {
                    let _ = stdin.write_all(b"-stay_open\r\nFalse\r\n-execute\r\n");
                    let _ = stdin.flush();
                    let _ = child.wait();
                }
                break;
            }
        }
    }
}
