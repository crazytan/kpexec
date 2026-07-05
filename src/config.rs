//! Loading `~/.config/kpexec/config.toml`.
//!
//! # Trust
//!
//! The config file is **agent-writable and therefore untrusted input**. It is a
//! *hint* only: it can point kpexec at a vault path and set a timeout, but it
//! must never carry a secret, and (per the security design) the ACL-protected
//! Keychain item — not this file — decides which vault is real. This module
//! therefore:
//!
//! * treats a missing file as the normal "not initialized" state (defaults),
//! * warns on unknown keys instead of failing (forward compatibility),
//! * reports parse failures as [`KpexecStatus::ConfigError`], and
//! * has no env-var overrides (the file is the only input).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{KpexecError, Result};
use crate::paths;

/// Default child timeout when the config does not specify one.
pub const DEFAULT_TIMEOUT_SEC: u64 = 300;

/// The effective configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The vault path hint, if the config named one. `None` means the config is
    /// absent or did not set `db_path` — treated as "not initialized".
    pub db_path: Option<PathBuf>,
    /// Default child timeout in seconds. Defaults to [`DEFAULT_TIMEOUT_SEC`].
    pub default_timeout_sec: u64,
    /// `true` when no config file existed on disk (so the caller can report the
    /// "not initialized" state to the user).
    pub file_present: bool,
    /// Unknown keys encountered while parsing. These are warned about, never
    /// fatal — surfaced here so `doctor`/`main` can log a warning.
    pub unknown_keys: Vec<String>,
}

impl Config {
    /// Defaults for the case where no config file is present.
    fn defaults_absent() -> Self {
        Config {
            db_path: None,
            default_timeout_sec: DEFAULT_TIMEOUT_SEC,
            file_present: false,
            unknown_keys: Vec::new(),
        }
    }
}

/// The raw on-disk shape. `deny_unknown_fields` is intentionally NOT used —
/// unknown keys are collected via `flatten` into `extra` so we can warn rather
/// than fail.
#[derive(Debug, Deserialize)]
struct RawConfig {
    db_path: Option<String>,
    default_timeout_sec: Option<u64>,
    #[serde(flatten)]
    extra: toml::Table,
}

/// Load the config from the default path (`~/.config/kpexec/config.toml`).
pub fn load() -> Result<Config> {
    let path = paths::config_file()?;
    load_from(&path)
}

/// Load the config from a specific path. Exposed for testing and for `doctor`.
pub fn load_from(path: &Path) -> Result<Config> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Missing file is fine: defaults + "not initialized".
            return Ok(Config::defaults_absent());
        }
        Err(e) => {
            return Err(KpexecError::config(format!(
                "could not read config file {}: {e}",
                path.display()
            )));
        }
    };

    parse(&contents)
}

/// Parse config TOML text into a [`Config`], marking it as present.
///
/// Separated from I/O so it is trivially unit-testable.
pub fn parse(contents: &str) -> Result<Config> {
    let raw: RawConfig = toml::from_str(contents).map_err(|e| {
        // The error message from `toml` is about structure, not values, so it
        // is safe to surface — but config is untrusted, so we do not echo the
        // file contents themselves.
        KpexecError::config(format!("malformed config.toml: {e}"))
    })?;

    let unknown_keys: Vec<String> = raw.extra.keys().cloned().collect();

    Ok(Config {
        db_path: raw.db_path.map(PathBuf::from),
        default_timeout_sec: raw.default_timeout_sec.unwrap_or(DEFAULT_TIMEOUT_SEC),
        file_present: true,
        unknown_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_config_parses() {
        let toml = r#"
            db_path = "/Users/tan/Secrets/kpexec-agent.kdbx"
            default_timeout_sec = 120
        "#;
        let cfg = parse(toml).unwrap();
        assert_eq!(
            cfg.db_path,
            Some(PathBuf::from("/Users/tan/Secrets/kpexec-agent.kdbx"))
        );
        assert_eq!(cfg.default_timeout_sec, 120);
        assert!(cfg.file_present);
        assert!(cfg.unknown_keys.is_empty());
    }

    #[test]
    fn timeout_defaults_when_absent() {
        let cfg = parse(r#"db_path = "/x.kdbx""#).unwrap();
        assert_eq!(cfg.default_timeout_sec, DEFAULT_TIMEOUT_SEC);
    }

    #[test]
    fn empty_config_uses_all_defaults() {
        let cfg = parse("").unwrap();
        assert_eq!(cfg.db_path, None);
        assert_eq!(cfg.default_timeout_sec, DEFAULT_TIMEOUT_SEC);
        assert!(cfg.file_present);
    }

    #[test]
    fn missing_file_is_not_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        let cfg = load_from(&path).unwrap();
        assert!(!cfg.file_present);
        assert_eq!(cfg.db_path, None);
        assert_eq!(cfg.default_timeout_sec, DEFAULT_TIMEOUT_SEC);
    }

    #[test]
    fn malformed_config_is_config_error() {
        let err = parse("db_path = = broken").unwrap_err();
        assert_eq!(err.status(), crate::status::KpexecStatus::ConfigError);
    }

    #[test]
    fn wrong_type_is_config_error() {
        // default_timeout_sec must be an integer.
        let err = parse(r#"default_timeout_sec = "not a number""#).unwrap_err();
        assert_eq!(err.status(), crate::status::KpexecStatus::ConfigError);
    }

    #[test]
    fn unknown_keys_warn_not_fail() {
        let toml = r#"
            db_path = "/x.kdbx"
            future_option = true
            another_unknown = 5
        "#;
        let cfg = parse(toml).unwrap();
        assert_eq!(cfg.db_path, Some(PathBuf::from("/x.kdbx")));
        assert_eq!(cfg.unknown_keys.len(), 2);
        assert!(cfg.unknown_keys.contains(&"future_option".to_string()));
        assert!(cfg.unknown_keys.contains(&"another_unknown".to_string()));
    }
}
