//! `kpexec doctor` — the M1 subset.
//!
//! M1 covers only checks that need neither the vault nor the Keychain:
//! config presence/parse, `db_path` existence, log-dir writability, and a
//! placeholder scan of nearby `.env*` files for credential-shaped variable
//! names. Vault/Keychain/code-signature checks arrive in M2/M3.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::config::{self, Config};
use crate::error::Result;
use crate::paths;
use crate::status::KpexecStatus;

/// Severity of a single doctor check line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Ok => "OK  ",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        }
    }
}

/// One line of doctor output.
#[derive(Debug, Clone)]
pub struct Check {
    pub level: Level,
    pub message: String,
}

impl Check {
    fn ok(message: impl Into<String>) -> Self {
        Check {
            level: Level::Ok,
            message: message.into(),
        }
    }
    fn warn(message: impl Into<String>) -> Self {
        Check {
            level: Level::Warn,
            message: message.into(),
        }
    }
    fn fail(message: impl Into<String>) -> Self {
        Check {
            level: Level::Fail,
            message: message.into(),
        }
    }
}

/// The outcome of a full doctor run: the individual checks plus the overall
/// status used for the exit code.
#[derive(Debug)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    /// The overall exit status: FAIL wins over WARN wins over OK.
    pub fn status(&self) -> KpexecStatus {
        if self.checks.iter().any(|c| c.level == Level::Fail) {
            // A failed environment check is a config-error class problem.
            KpexecStatus::ConfigError
        } else {
            KpexecStatus::Success
        }
    }

    /// Render the human-readable report.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for c in &self.checks {
            let _ = writeln!(out, "[{}] {}", c.level.label(), c.message);
        }
        let fails = self
            .checks
            .iter()
            .filter(|c| c.level == Level::Fail)
            .count();
        let warns = self
            .checks
            .iter()
            .filter(|c| c.level == Level::Warn)
            .count();
        let _ = writeln!(out);
        if fails > 0 {
            let _ = writeln!(out, "doctor: {fails} failure(s), {warns} warning(s)");
        } else if warns > 0 {
            let _ = writeln!(out, "doctor: no failures, {warns} warning(s)");
        } else {
            let _ = writeln!(out, "doctor: all checks passed");
        }
        out
    }
}

/// Run the M1 doctor checks against the default config path.
pub fn run() -> Result<Report> {
    let config_path = paths::config_file()?;
    let log_dir = paths::log_dir()?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let home = paths::home().ok();
    Ok(run_with(&config_path, &log_dir, &cwd, home.as_deref()))
}

/// Run the checks with explicit locations (testable).
pub fn run_with(config_path: &Path, log_dir: &Path, cwd: &Path, home: Option<&Path>) -> Report {
    let mut checks = Vec::new();

    // 1. Config file exists + parses.
    let cfg = check_config(config_path, &mut checks);

    // 2. db_path (if set) exists.
    check_db_path(cfg.as_ref(), &mut checks);

    // 3. Log dir writable.
    check_log_dir_writable(log_dir, &mut checks);

    // 4. Nearby .env* credential-name scan (placeholder; see TODO below).
    check_env_files(cwd, home, &mut checks);

    Report { checks }
}

fn check_config(config_path: &Path, checks: &mut Vec<Check>) -> Option<Config> {
    match config::load_from(config_path) {
        Ok(cfg) if !cfg.file_present => {
            checks.push(Check::warn(format!(
                "config {} not found — run `kpexec init` (not initialized)",
                config_path.display()
            )));
            Some(cfg)
        }
        Ok(cfg) => {
            checks.push(Check::ok(format!(
                "config {} parses",
                config_path.display()
            )));
            for key in &cfg.unknown_keys {
                checks.push(Check::warn(format!(
                    "config has unknown key `{key}` (ignored)"
                )));
            }
            Some(cfg)
        }
        Err(e) => {
            checks.push(Check::fail(format!("config: {}", e.message())));
            None
        }
    }
}

fn check_db_path(cfg: Option<&Config>, checks: &mut Vec<Check>) {
    match cfg.and_then(|c| c.db_path.as_ref()) {
        Some(db) if db.exists() => {
            checks.push(Check::ok(format!("db_path {} exists", db.display())));
        }
        Some(db) => {
            checks.push(Check::fail(format!(
                "db_path {} does not exist",
                db.display()
            )));
        }
        None => {
            checks.push(Check::warn(
                "db_path not set in config — vault not initialized",
            ));
        }
    }
}

fn check_log_dir_writable(log_dir: &Path, checks: &mut Vec<Check>) {
    // Try to create the directory and write a probe file.
    let probe = log_dir.join(".kpexec-doctor-probe");
    let writable =
        std::fs::create_dir_all(log_dir).is_ok() && std::fs::write(&probe, b"probe").is_ok();
    let _ = std::fs::remove_file(&probe);
    if writable {
        checks.push(Check::ok(format!(
            "log dir {} is writable",
            log_dir.display()
        )));
    } else {
        checks.push(Check::fail(format!(
            "log dir {} is not writable",
            log_dir.display()
        )));
    }
}

/// Substrings that mark an environment variable name as credential-shaped.
const CREDENTIAL_MARKERS: [&str; 4] = ["TOKEN", "SECRET", "KEY", "PASSWORD"];

/// Scan `.env*` files from `cwd` up to the repo root or `$HOME` (whichever
/// comes first) for variable names that look like credentials.
///
/// TODO(M2): once policies are readable, replace this substring heuristic with
/// the policy-driven scan (A9) — warn specifically when a `.env*` file defines a
/// variable name that a policy *injects*, which is the real leakage signal.
fn check_env_files(cwd: &Path, home: Option<&Path>, checks: &mut Vec<Check>) {
    let mut hits = Vec::new();
    let mut current = cwd.to_path_buf();

    loop {
        scan_dir_env_files(&current, &mut hits);

        // Stop at repo root (a dir containing `.git`) or at $HOME.
        if current.join(".git").exists() {
            break;
        }
        if home.is_some_and(|h| current == h) {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }

    if hits.is_empty() {
        checks.push(Check::ok(
            "no credential-shaped names found in nearby .env* files",
        ));
    } else {
        for (file, var) in hits {
            checks.push(Check::warn(format!(
                "{} defines `{}` (credential-shaped name near cwd)",
                file.display(),
                var
            )));
        }
    }
}

fn scan_dir_env_files(dir: &Path, hits: &mut Vec<(PathBuf, String)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Match `.env`, `.env.local`, `.env.production`, etc.
        if !name.starts_with(".env") {
            continue;
        }
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for var in env_var_names(&contents) {
            let upper = var.to_ascii_uppercase();
            if CREDENTIAL_MARKERS.iter().any(|m| upper.contains(m)) {
                hits.push((path.clone(), var));
            }
        }
    }
}

/// Extract the variable *names* (left of `=`) from `.env` text. Values are never
/// read into the report — only names are inspected, so no secret is surfaced.
fn env_var_names(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(name, _)| name.trim().trim_start_matches("export ").trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_names_ignores_values_and_comments() {
        let text = "# comment\nGH_TOKEN=abc123\nexport API_SECRET = xyz\nPLAIN=hello\n";
        let names = env_var_names(text);
        assert!(names.contains(&"GH_TOKEN".to_string()));
        assert!(names.contains(&"API_SECRET".to_string()));
        assert!(names.contains(&"PLAIN".to_string()));
        // Value material must not appear.
        assert!(!names.iter().any(|n| n.contains("abc123")));
    }

    #[test]
    fn env_scan_flags_credential_names() {
        let dir = tempfile::tempdir().unwrap();
        // Make it a repo root so the walk stops here.
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "GH_TOKEN=secretvalue\nHARMLESS=1\n",
        )
        .unwrap();

        let mut hits = Vec::new();
        scan_dir_env_files(dir.path(), &mut hits);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "GH_TOKEN");
        // No secret value in the recorded hit.
        assert!(!hits[0].1.contains("secretvalue"));
    }

    #[test]
    fn db_path_missing_is_fail() {
        let mut checks = Vec::new();
        let cfg = Config {
            db_path: Some(PathBuf::from("/definitely/not/here.kdbx")),
            default_timeout_sec: 300,
            file_present: true,
            unknown_keys: vec![],
        };
        check_db_path(Some(&cfg), &mut checks);
        assert_eq!(checks[0].level, Level::Fail);
    }

    #[test]
    fn report_status_maps_fail_to_config_error() {
        let report = Report {
            checks: vec![Check::fail("x")],
        };
        assert_eq!(report.status(), KpexecStatus::ConfigError);
    }

    #[test]
    fn report_status_ok_when_only_warnings() {
        let report = Report {
            checks: vec![Check::warn("x"), Check::ok("y")],
        };
        assert_eq!(report.status(), KpexecStatus::Success);
    }

    #[test]
    fn missing_config_warns_not_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let log_dir = dir.path().join("logs");
        let report = run_with(&config_path, &log_dir, dir.path(), Some(dir.path()));
        // Not initialized => at least one warning, no failures from config.
        assert!(report.checks.iter().any(|c| c.level == Level::Warn));
        assert_eq!(report.status(), KpexecStatus::Success);
    }
}
