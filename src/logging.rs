//! Logging: the audit facade and a size-capped rotating file writer.
//!
//! # The never-log rule
//!
//! Per the security design (invariant 12) and the CLI design doc, the audit log
//! records **only**: entry id, command name, canonical executable path, a
//! SHA-256 hash of the full argv, and the result status. It must **never**
//! contain the secret, the raw trailing arguments, or the full command line
//! (paths, branch names, and titles can themselves be sensitive).
//!
//! To make this structural rather than a convention, call sites do not build
//! log records by hand. They go through [`log_run_result`], whose signature
//! simply has no parameter for raw argv or secret material — only the safe,
//! pre-hashed fields. Adding a new audit call means adding a function here, in
//! this one reviewed place, with the same discipline. Do not call
//! `tracing::info!` with request data directly from command handlers.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

use crate::error::Result;
use crate::paths;
use crate::status::KpexecStatus;

/// Rotate when the active log reaches this many bytes (5 MB).
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
/// Number of rotated files to keep (`kpexec.log.1` .. `kpexec.log.3`).
const KEEP_ROTATED: usize = 3;

/// Compute the argv hash the audit log records instead of the raw argv.
///
/// The full argv is joined with `\0` (a byte that cannot appear inside an argv
/// element) and hashed with SHA-256; the hex digest is what gets logged. This
/// lets two runs be compared for equality without ever storing the arguments
/// themselves — branch names, titles, and paths stay out of the log.
pub fn argv_hash<S: AsRef<str>>(argv: &[S]) -> String {
    let mut hasher = Sha256::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            hasher.update([0u8]);
        }
        hasher.update(arg.as_ref().as_bytes());
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Record the result of a run in the audit log.
///
/// This is the ONLY sanctioned way to write a run record. Its parameters are
/// exactly the fields the never-log rule permits — there is deliberately no way
/// to pass raw trailing args or the secret through this function.
///
/// * `entry_id` — the `kpexec.id` of the selected entry.
/// * `command_name` — the selected command template's name.
/// * `canonical_exe` — the canonicalized executable path that was (or would be)
///   run.
/// * `argv_hash` — the SHA-256 hex digest from [`argv_hash`], never the argv.
/// * `status` — the outcome.
pub fn log_run_result(
    entry_id: &str,
    command_name: &str,
    canonical_exe: &Path,
    argv_hash: &str,
    status: KpexecStatus,
) {
    tracing::info!(
        target: "kpexec::audit",
        entry_id,
        command_name,
        canonical_exe = %canonical_exe.display(),
        argv_hash,
        status = status.as_str(),
        "run"
    );
}

/// A `Write` that appends to a file and rotates it once it exceeds a byte cap.
///
/// Rotation is `kpexec.log -> kpexec.log.1 -> ... -> kpexec.log.N`, dropping the
/// oldest. This is a small, self-contained implementation rather than a heavier
/// dependency because the size-based (not time-based) policy the spec requires
/// is not offered by `tracing-appender`.
struct RotatingWriter {
    path: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: fs::File,
    written: u64,
}

impl RotatingWriter {
    fn open(path: PathBuf, max_bytes: u64, keep: usize) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(RotatingWriter {
            path,
            max_bytes,
            keep,
            file,
            written,
        })
    }

    /// Shift `kpexec.log.{keep-1}` -> `.{keep}` (dropping the oldest), then the
    /// active file -> `.1`, and open a fresh active file.
    fn rotate(&mut self) -> io::Result<()> {
        // Drop the oldest.
        let oldest = self.rotated_path(self.keep);
        if oldest.exists() {
            let _ = fs::remove_file(&oldest);
        }
        // Shift the middle files up by one.
        for n in (1..self.keep).rev() {
            let from = self.rotated_path(n);
            if from.exists() {
                let to = self.rotated_path(n + 1);
                let _ = fs::rename(&from, &to);
            }
        }
        // Active -> .1
        if self.path.exists() {
            let _ = fs::rename(&self.path, self.rotated_path(1));
        }
        self.file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }

    fn rotated_path(&self, n: usize) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_default();
        name.push(format!(".{n}"));
        self.path.with_file_name(name)
    }
}

impl Write for RotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > self.max_bytes && self.written > 0 {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// A `MakeWriter` that hands out a clone-free, mutex-guarded handle to the
/// single rotating writer.
struct SharedWriter(std::sync::Arc<Mutex<RotatingWriter>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriterGuard;
    fn make_writer(&'a self) -> Self::Writer {
        SharedWriterGuard(self.0.clone())
    }
}

struct SharedWriterGuard(std::sync::Arc<Mutex<RotatingWriter>>);

impl Write for SharedWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut w = self
            .0
            .lock()
            .map_err(|_| io::Error::other("log writer mutex poisoned"))?;
        w.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut w = self
            .0
            .lock()
            .map_err(|_| io::Error::other("log writer mutex poisoned"))?;
        w.flush()
    }
}

/// Initialize tracing to the rotating log file at
/// `~/Library/Logs/kpexec/kpexec.log`.
///
/// Best-effort: if the log location cannot be opened (e.g. an unwritable home),
/// logging is silently disabled rather than aborting the command — the audit
/// log is advisory, not a boundary. Returns the resolved log path on success.
pub fn init() -> Result<PathBuf> {
    let path = paths::log_file()?;
    init_at(path.clone(), MAX_LOG_BYTES, KEEP_ROTATED);
    Ok(path)
}

/// Initialize tracing to a specific path with explicit rotation params.
/// Exposed for testing.
pub fn init_at(path: PathBuf, max_bytes: u64, keep: usize) {
    let writer = match RotatingWriter::open(path, max_bytes, keep) {
        Ok(w) => w,
        Err(_) => return, // advisory log: disable on failure, do not abort.
    };
    let shared = SharedWriter(std::sync::Arc::new(Mutex::new(writer)));

    // Default to info; honor RUST_LOG for local debugging only.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(shared)
        .with_ansi(false)
        .with_target(true)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_hash_is_stable_and_hex() {
        let h = argv_hash(&["gh", "pr", "create"]);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic.
        assert_eq!(h, argv_hash(&["gh", "pr", "create"]));
    }

    #[test]
    fn argv_hash_is_injective_across_boundaries() {
        // The NUL separator prevents ["a","bc"] and ["ab","c"] colliding.
        assert_ne!(argv_hash(&["a", "bc"]), argv_hash(&["ab", "c"]));
    }

    #[test]
    fn argv_hash_empty() {
        // SHA-256 of the empty input.
        assert_eq!(
            argv_hash::<&str>(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rotation_keeps_bounded_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kpexec.log");
        // Cap at 100 bytes, keep 3 rotated.
        let mut w = RotatingWriter::open(path.clone(), 100, 3).unwrap();
        // Write 10 chunks of 60 bytes -> forces several rotations.
        let chunk = [b'x'; 60];
        for _ in 0..10 {
            w.write_all(&chunk).unwrap();
        }
        w.flush().unwrap();
        drop(w);

        // Active file exists, and at most `keep` rotated files exist.
        assert!(path.exists());
        assert!(path.with_file_name("kpexec.log.1").exists());
        // .4 must never exist (keep = 3).
        assert!(!path.with_file_name("kpexec.log.4").exists());
    }
}
