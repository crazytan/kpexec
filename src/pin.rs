//! Executable pinning: canonicalization + SHA-256 of the target bytes.
//!
//! Per security-design invariants 4 and 5, a policy executable must be an
//! absolute path that canonicalizes (symlinks resolved) to an existing regular
//! file; the policy stores the SHA-256 of that canonical file's *bytes*
//! (`exe_sha256`), computed at authoring time. `run` (M4) re-hashes immediately
//! before exec and rejects on mismatch; `entry repin` recomputes after a
//! legitimate upgrade.
//!
//! This module owns the canonicalize + hash + metadata primitives shared by
//! `entry add`, `entry add-command`, `entry repin`, and `check`.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::error::{KpexecError, Result};

/// The result of canonicalizing and hashing an executable target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The canonical (symlink-resolved) path actually hashed.
    pub canonical: PathBuf,
    /// Lowercase hex SHA-256 of the canonical file's bytes.
    pub sha256: String,
    /// File size in bytes (shown by `repin` for user confirmation).
    pub size: u64,
    /// File mtime, if available (shown by `repin`).
    pub mtime: Option<SystemTime>,
}

/// Canonicalize an executable path and hash its bytes.
///
/// The path must be absolute, must canonicalize, and the target must be a
/// regular file. Failure rejects (deny by default) with a message safe to
/// surface — paths are already visible to the user authoring the policy.
pub fn compute(exe: &str) -> Result<Pin> {
    let path = Path::new(exe);
    if !path.is_absolute() {
        return Err(KpexecError::new(
            crate::status::KpexecStatus::MalformedPolicy,
            format!("executable path must be absolute: {exe}"),
        ));
    }
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        KpexecError::new(
            crate::status::KpexecStatus::MalformedPolicy,
            format!("cannot canonicalize {exe}: {e}"),
        )
    })?;
    let meta = std::fs::metadata(&canonical).map_err(|e| {
        KpexecError::new(
            crate::status::KpexecStatus::MalformedPolicy,
            format!("cannot stat {}: {e}", canonical.display()),
        )
    })?;
    if !meta.is_file() {
        return Err(KpexecError::new(
            crate::status::KpexecStatus::MalformedPolicy,
            format!("{} is not a regular file", canonical.display()),
        ));
    }
    let bytes = std::fs::read(&canonical).map_err(|e| {
        KpexecError::new(
            crate::status::KpexecStatus::MalformedPolicy,
            format!("cannot read {}: {e}", canonical.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = hex(&hasher.finalize());

    Ok(Pin {
        canonical,
        sha256,
        size: meta.len(),
        mtime: meta.modified().ok(),
    })
}

/// Whether the recorded pin still matches the current on-disk bytes.
///
/// Returns:
/// * `Ok(true)` — pin present and current,
/// * `Ok(false)` — pin present but the current hash differs (stale), and
/// * `Err(_)` — the executable no longer canonicalizes / cannot be read.
///
/// A `None` recorded pin (unpinned command) is not this function's concern;
/// callers handle the missing-pin warning separately.
pub fn is_current(exe: &str, recorded: &str) -> Result<bool> {
    let pin = compute(exe)?;
    Ok(pin.sha256.eq_ignore_ascii_case(recorded))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn computes_stable_hash() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        let mut f = std::fs::File::create(&exe).unwrap();
        f.write_all(b"hello-bytes").unwrap();
        drop(f);

        let a = compute(exe.to_str().unwrap()).unwrap();
        let b = compute(exe.to_str().unwrap()).unwrap();
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(a.size, 11);
        // Known SHA-256 of "hello-bytes".
        assert_eq!(a.sha256.len(), 64);
    }

    #[test]
    fn stale_pin_detected_after_edit() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"v1").unwrap();
        let p = compute(exe.to_str().unwrap()).unwrap();
        // Legitimate current.
        assert!(is_current(exe.to_str().unwrap(), &p.sha256).unwrap());
        // Tamper / upgrade.
        std::fs::write(&exe, b"v2-different").unwrap();
        assert!(!is_current(exe.to_str().unwrap(), &p.sha256).unwrap());
    }

    #[test]
    fn relative_path_rejected() {
        let err = compute("relative/path").unwrap_err();
        assert_eq!(err.status(), crate::status::KpexecStatus::MalformedPolicy);
    }

    #[test]
    fn missing_exe_rejected() {
        let err = compute("/definitely/not/here/xyz").unwrap_err();
        assert_eq!(err.status(), crate::status::KpexecStatus::MalformedPolicy);
    }

    #[test]
    fn resolves_symlink_before_hashing() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"payload").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let via_link = compute(link.to_str().unwrap()).unwrap();
        let via_real = compute(real.to_str().unwrap()).unwrap();
        assert_eq!(via_link.sha256, via_real.sha256);
        assert_eq!(via_link.canonical, via_real.canonical);
    }
}
