//! Vault write locking + KeePassXC-lockfile detection.
//!
//! Two independent guards protect a vault write (security-design "Policy
//! integrity"; cli-design KDBX rules):
//!
//! 1. **kpexec write lock** — a `<vault>.kpexec-lock` file adjacent to the
//!    vault holding the holder's PID + start time. A second kpexec process
//!    sees the file and refuses. If the recorded PID is no longer running the
//!    lock is *stale* and is reclaimed (a crashed holder must not wedge the
//!    vault forever).
//! 2. **KeePassXC lockfile refusal** — KeePassXC writes `.<vaultname>.lockfile`
//!    in the vault's directory while it has the DB open. kpexec refuses to
//!    write when it is present (the user must close KeePassXC first), because
//!    concurrent writers can corrupt or lose edits.
//!
//! The lock is advisory (same-user files), consistent with the threat model —
//! it serializes kpexec against itself and against KeePassXC, not against
//! hostile local code.

use std::path::{Path, PathBuf};

use crate::error::{KpexecError, Result};
use crate::status::KpexecStatus;

/// The suffix appended to the vault path for the kpexec lock file.
const LOCK_SUFFIX: &str = ".kpexec-lock";

/// A held vault write lock. Dropping it removes the lock file (best-effort).
#[derive(Debug)]
pub struct VaultLock {
    path: PathBuf,
    /// Set false if we reclaimed/adopted rather than created, so Drop still
    /// cleans up — we always own the file for the duration.
    _held: bool,
}

impl VaultLock {
    /// The lock-file path for a vault.
    pub fn path_for(vault: &Path) -> PathBuf {
        let mut name = vault.as_os_str().to_os_string();
        name.push(LOCK_SUFFIX);
        PathBuf::from(name)
    }

    /// The KeePassXC lockfile path for a vault (`.<vaultname>.lockfile` in the
    /// same directory).
    pub fn keepassxc_lockfile_for(vault: &Path) -> PathBuf {
        let dir = vault.parent().unwrap_or_else(|| Path::new("."));
        let name = vault
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        dir.join(format!(".{name}.lockfile"))
    }

    /// Acquire the write lock for `vault`, refusing if KeePassXC holds it or if
    /// another live kpexec holds it. A stale kpexec lock (dead holder) is
    /// reclaimed.
    pub fn acquire(vault: &Path) -> Result<VaultLock> {
        // 1. Refuse if KeePassXC has the DB open.
        let kpxc = Self::keepassxc_lockfile_for(vault);
        if kpxc.exists() {
            return Err(KpexecError::new(
                KpexecStatus::ConfigError,
                format!(
                    "KeePassXC lockfile present ({}); close KeePassXC before editing the vault",
                    kpxc.display()
                ),
            ));
        }

        let lock_path = Self::path_for(vault);

        // 2. If a kpexec lock exists, decide stale-vs-live.
        if let Ok(contents) = std::fs::read_to_string(&lock_path) {
            match LockInfo::parse(&contents) {
                Some(info) if info.pid != std::process::id() && process_alive(info.pid) => {
                    return Err(KpexecError::new(
                        KpexecStatus::ConfigError,
                        format!(
                            "vault is locked by a running kpexec (pid {}); retry when it finishes",
                            info.pid
                        ),
                    ));
                }
                // Dead holder, unparseable, or our own pid: reclaim.
                _ => {
                    let _ = std::fs::remove_file(&lock_path);
                }
            }
        }

        // 3. Write our lock. We do not rely on O_EXCL atomicity across the
        //    reclaim window (single-user advisory lock); the read-then-write is
        //    adequate for serializing kpexec-vs-kpexec and kpexec-vs-KeePassXC.
        let info = LockInfo::current();
        std::fs::write(&lock_path, info.encode()).map_err(|e| {
            KpexecError::new(
                KpexecStatus::ConfigError,
                format!("cannot write vault lock {}: {e}", lock_path.display()),
            )
        })?;

        Ok(VaultLock {
            path: lock_path,
            _held: true,
        })
    }

    /// Explicitly release the lock (also done on drop).
    pub fn release(self) {
        // Drop does the work.
        drop(self);
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The recorded lock holder: PID + a start marker.
struct LockInfo {
    pid: u32,
    /// Seconds since the Unix epoch when the lock was taken. Recorded per the
    /// spec ("PID + start time"); used for human diagnostics.
    start_epoch: u64,
}

impl LockInfo {
    fn current() -> Self {
        let start_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        LockInfo {
            pid: std::process::id(),
            start_epoch,
        }
    }

    fn encode(&self) -> String {
        format!("pid={}\nstart_epoch={}\n", self.pid, self.start_epoch)
    }

    fn parse(contents: &str) -> Option<LockInfo> {
        let mut pid = None;
        let mut start = None;
        for line in contents.lines() {
            if let Some(v) = line.strip_prefix("pid=") {
                pid = v.trim().parse().ok();
            } else if let Some(v) = line.strip_prefix("start_epoch=") {
                start = v.trim().parse().ok();
            }
        }
        Some(LockInfo {
            pid: pid?,
            start_epoch: start.unwrap_or(0),
        })
    }
}

/// Whether a process with `pid` is currently alive.
///
/// Uses `kill(pid, 0)`: returns Ok when the process exists (or we lack
/// permission, `EPERM` — still alive), Err(ESRCH) when it does not. On the
/// non-unix path we conservatively report "alive" so we never steal a lock we
/// cannot reason about.
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // SAFETY: `kill` with signal 0 performs error checking without sending a
    // signal; passing a pid is sound.
    let ret = unsafe { libc_kill(pid as i32, 0) };
    if ret == 0 {
        return true;
    }
    // errno == EPERM (1) means the process exists but we can't signal it.
    std::io::Error::last_os_error().raw_os_error() == Some(1)
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    true
}

// Minimal FFI shim for `kill(2)` so we do not pull in the whole `libc` crate
// just for liveness detection.
#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_paths_are_adjacent() {
        let vault = Path::new("/vaults/agent.kdbx");
        assert_eq!(
            VaultLock::path_for(vault),
            PathBuf::from("/vaults/agent.kdbx.kpexec-lock")
        );
        assert_eq!(
            VaultLock::keepassxc_lockfile_for(vault),
            PathBuf::from("/vaults/.agent.kdbx.lockfile")
        );
    }

    #[test]
    fn acquire_and_release_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kdbx");
        std::fs::write(&vault, b"x").unwrap();
        let lock = VaultLock::acquire(&vault).unwrap();
        assert!(VaultLock::path_for(&vault).exists());
        lock.release();
        assert!(!VaultLock::path_for(&vault).exists());
    }

    #[test]
    fn refuses_when_keepassxc_lockfile_present() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kdbx");
        std::fs::write(&vault, b"x").unwrap();
        std::fs::write(VaultLock::keepassxc_lockfile_for(&vault), b"").unwrap();
        let err = VaultLock::acquire(&vault).unwrap_err();
        assert_eq!(err.status(), KpexecStatus::ConfigError);
        assert!(err.message().contains("KeePassXC"));
    }

    #[test]
    fn stale_lock_is_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kdbx");
        std::fs::write(&vault, b"x").unwrap();
        // Write a lock owned by a PID that is (almost certainly) dead.
        let dead = LockInfo {
            pid: 999_999_999,
            start_epoch: 0,
        };
        std::fs::write(VaultLock::path_for(&vault), dead.encode()).unwrap();
        // Should reclaim rather than refuse.
        let lock = VaultLock::acquire(&vault).unwrap();
        lock.release();
    }

    #[test]
    fn live_lock_blocks_second_acquire() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kdbx");
        std::fs::write(&vault, b"x").unwrap();
        // A lock held by *another* live pid (use pid 1, always alive on unix).
        let live = LockInfo {
            pid: 1,
            start_epoch: 0,
        };
        std::fs::write(VaultLock::path_for(&vault), live.encode()).unwrap();
        let err = VaultLock::acquire(&vault).unwrap_err();
        assert_eq!(err.status(), KpexecStatus::ConfigError);
        assert!(err.message().contains("locked"));
    }
}
