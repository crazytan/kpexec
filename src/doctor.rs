//! `kpexec doctor` environment and security-boundary diagnostics.
//!
//! Production diagnostics check the executable's release signature before
//! permitting any protected Keychain read, then require the Keychain backend
//! to prove the item's anti-substitution ACL binding. If either proof is
//! missing, doctor fails closed and does not bring the vault password into the
//! process. Tests inject a file-backed Keychain and parsed signature result, so
//! no test can display Keychain or authentication UI.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cmd_check;
use crate::config::{self, Config};
use crate::error::Result;
use crate::keychain::{
    AclBinding, EXPECTED_IDENTIFIER, EXPECTED_TEAM_ID, KeychainStore, account_for,
};
use crate::paths;
use crate::policy::Policy;
use crate::status::KpexecStatus;
use crate::vault::Vault;

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

/// A parsed assessment of the current executable's distribution signature.
///
/// This contains no secret data and is public solely so tests can inject a
/// deterministic assessment without signing or executing helper programs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSignature {
    pub integrity_valid: bool,
    pub developer_id: bool,
    pub identifier_valid: bool,
    pub team_id_valid: bool,
    pub hardened_runtime: bool,
    pub gatekeeper: GatekeeperAssessment,
}

/// What `spctl --assess --type execute` established for the current executable.
///
/// A bare command-line executable installed from a notarized package is not an
/// app bundle, so Gatekeeper may correctly decline to assess it as an app. The
/// package itself remains the authoritative notarization artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatekeeperAssessment {
    /// Gatekeeper explicitly reported `source=Notarized Developer ID`.
    NotarizedDeveloperId,
    /// The code is valid, but this assessment type does not apply to a bare CLI.
    NotApplicableToBareCli,
    /// Gatekeeper made an actual rejection decision.
    Rejected,
    /// The tool failed or returned an unrecognized result.
    Unknown,
}

impl CodeSignature {
    fn trusted_for_keychain(&self) -> bool {
        self.integrity_valid
            && self.developer_id
            && self.identifier_valid
            && self.team_id_valid
            && self.hardened_runtime
    }
}

/// Run all doctor checks against default locations.
pub fn run() -> Result<Report> {
    let config_path = paths::config_file()?;
    let log_dir = paths::log_dir()?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let home = paths::home().ok();
    let signature = inspect_current_signature();
    let keychain = crate::vaultctx::production_keychain()?;
    Ok(run_full_with(
        &config_path,
        &log_dir,
        &cwd,
        home.as_deref(),
        &signature,
        keychain.as_ref(),
    ))
}

/// Run filesystem-only checks with explicit locations.
///
/// This compatibility/test helper cannot make a security-boundary assertion;
/// production uses [`run_full_with`].
pub fn run_with(config_path: &Path, log_dir: &Path, cwd: &Path, home: Option<&Path>) -> Report {
    let mut checks = Vec::new();

    // 1. Config file exists + parses.
    let cfg = check_config(config_path, &mut checks);

    // 2. db_path (if set) exists.
    check_db_path(cfg.as_ref(), &mut checks);

    // 3. Log dir writable.
    check_log_dir_writable(log_dir, &mut checks);

    // 4. Filesystem-only fallback scan. The production path replaces this
    // heuristic with exact policy-injected names after the trusted vault opens.
    check_env_files(cwd, home, &mut checks);

    Report { checks }
}

/// Run the complete diagnostic set with injected, non-interactive probes.
pub fn run_full_with(
    config_path: &Path,
    log_dir: &Path,
    cwd: &Path,
    home: Option<&Path>,
    signature: &CodeSignature,
    keychain: &dyn KeychainStore,
) -> Report {
    let mut checks = Vec::new();
    let cfg = check_config(config_path, &mut checks);
    check_db_path(cfg.as_ref(), &mut checks);
    check_log_dir_writable(log_dir, &mut checks);
    check_code_signature(signature, &mut checks);

    let Some(vault_path) = cfg.as_ref().and_then(|c| c.db_path.as_deref()) else {
        checks.push(Check::warn(
            "Keychain ACL, vault, pin, and policy-driven .env checks skipped: no vault configured",
        ));
        return Report { checks };
    };

    let account = account_for(vault_path);
    let acl_verified = match keychain.acl_binding(&account) {
        Ok(AclBinding::Verified) => {
            checks.push(Check::ok(
                "Keychain item has the singleton creator Team-ID partition and the current executable has the exact release identity",
            ));
            true
        }
        Ok(AclBinding::Unverified) => {
            checks.push(Check::fail(
                "Keychain ACL provenance is absent or is not the singleton release Team-ID partition; protected credential read refused",
            ));
            false
        }
        Err(error) => {
            checks.push(Check::fail(format!(
                "Keychain ACL inspection failed: {}",
                error.message()
            )));
            false
        }
    };

    if !signature.trusted_for_keychain() || !acl_verified {
        checks.push(Check::warn(
            "vault open, executable-pin, and policy-driven .env checks skipped because the protected-read boundary is not trusted",
        ));
        return Report { checks };
    }

    match Vault::open(vault_path, keychain, Some(vault_path)) {
        Ok(vault) => {
            checks.push(Check::ok(
                "Keychain item exists, its protected db_path agrees with config, and the vault opens",
            ));
            let policy_report = cmd_check::check_vault(&vault, None);
            checks.extend(policy_report.checks);
            let inject_names = policy_inject_names(&vault);
            check_env_files_for_names(cwd, home, &inject_names, &mut checks);
        }
        Err(error) => {
            checks.push(Check::fail(format!(
                "Keychain/vault identity or openability check failed: {}",
                error.message()
            )));
            checks.push(Check::warn(
                "executable-pin and policy-driven .env checks skipped because the vault did not open",
            ));
        }
    }

    Report { checks }
}

fn inspect_current_signature() -> CodeSignature {
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return parse_signature_outputs(false, "", false, ""),
    };
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(&executable)
        .output();
    let display = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(&executable)
        .output();
    let gatekeeper = Command::new("/usr/sbin/spctl")
        .args(["--assess", "--type", "execute", "--verbose=4"])
        .arg(&executable)
        .output();

    let verify_ok = verify.as_ref().is_ok_and(|o| o.status.success());
    let display_text = display
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
        .unwrap_or_default();
    let gatekeeper_ok = gatekeeper.as_ref().is_ok_and(|o| o.status.success());
    let gatekeeper_text = gatekeeper
        .as_ref()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default();
    parse_signature_outputs(verify_ok, &display_text, gatekeeper_ok, &gatekeeper_text)
}

fn parse_signature_outputs(
    verify_ok: bool,
    display: &str,
    gatekeeper_ok: bool,
    gatekeeper: &str,
) -> CodeSignature {
    CodeSignature {
        integrity_valid: verify_ok,
        developer_id: display
            .lines()
            .any(|line| line.starts_with("Authority=Developer ID Application:")),
        identifier_valid: display
            .lines()
            .any(|line| line == format!("Identifier={EXPECTED_IDENTIFIER}")),
        team_id_valid: display
            .lines()
            .any(|line| line == format!("TeamIdentifier={EXPECTED_TEAM_ID}")),
        hardened_runtime: display
            .lines()
            .any(|line| line.starts_with("CodeDirectory ") && line.contains("(runtime)")),
        gatekeeper: parse_gatekeeper_assessment(gatekeeper_ok, gatekeeper),
    }
}

fn parse_gatekeeper_assessment(success: bool, output: &str) -> GatekeeperAssessment {
    if success && output.contains("source=Notarized Developer ID") {
        return GatekeeperAssessment::NotarizedDeveloperId;
    }
    let normalized = output.to_ascii_lowercase();
    if normalized.contains("code is valid but does not seem to be an app") {
        GatekeeperAssessment::NotApplicableToBareCli
    } else if normalized.contains("rejected") {
        GatekeeperAssessment::Rejected
    } else {
        GatekeeperAssessment::Unknown
    }
}

fn check_code_signature(signature: &CodeSignature, checks: &mut Vec<Check>) {
    signature_check(
        signature.integrity_valid,
        "code signature passes strict integrity verification",
        "code signature is absent or fails strict integrity verification",
        checks,
    );
    signature_check(
        signature.developer_id,
        "code signature uses a Developer ID Application identity",
        "code signature is not a Developer ID Application signature",
        checks,
    );
    signature_check(
        signature.identifier_valid,
        format!("code-signing identifier is {EXPECTED_IDENTIFIER}"),
        format!("code-signing identifier is not {EXPECTED_IDENTIFIER}"),
        checks,
    );
    signature_check(
        signature.team_id_valid,
        format!("code-signing Team ID is {EXPECTED_TEAM_ID}"),
        format!("code-signing Team ID is not {EXPECTED_TEAM_ID}"),
        checks,
    );
    signature_check(
        signature.hardened_runtime,
        "hardened runtime is enabled",
        "hardened runtime is not enabled",
        checks,
    );
    checks.push(match signature.gatekeeper {
        GatekeeperAssessment::NotarizedDeveloperId => Check::ok(
            "Gatekeeper identifies the executable as Notarized Developer ID",
        ),
        GatekeeperAssessment::NotApplicableToBareCli => Check::warn(
            "Gatekeeper executable assessment is not applicable to this bare CLI; the installed executable cannot prove installer notarization, so verify the distributed package",
        ),
        GatekeeperAssessment::Rejected => Check::fail(
            "Gatekeeper rejected the executable; verify the distributed installer package and installed payload",
        ),
        GatekeeperAssessment::Unknown => Check::warn(
            "Gatekeeper executable assessment was unavailable or unrecognized; notarization must be verified on the distributed installer package",
        ),
    });
}

fn signature_check(
    passed: bool,
    ok: impl Into<String>,
    fail: impl Into<String>,
    checks: &mut Vec<Check>,
) {
    checks.push(if passed {
        Check::ok(ok)
    } else {
        Check::fail(fail)
    });
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

/// Filesystem-only fallback scan used by [`run_with`]. Production diagnostics
/// use the policy-driven exact-name scan after the vault opens.
fn check_env_files(cwd: &Path, home: Option<&Path>, checks: &mut Vec<Check>) {
    let hits = nearby_env_names(cwd, home)
        .into_iter()
        .filter(|(_, var)| {
            let upper = var.to_ascii_uppercase();
            CREDENTIAL_MARKERS
                .iter()
                .any(|marker| upper.contains(marker))
        })
        .collect::<Vec<_>>();

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

#[cfg(test)]
fn scan_dir_env_files(dir: &Path, hits: &mut Vec<(PathBuf, String)>) {
    hits.extend(scan_dir_all_env_names(dir).into_iter().filter(|(_, var)| {
        let upper = var.to_ascii_uppercase();
        CREDENTIAL_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
    }));
}

fn scan_dir_all_env_names(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut hits = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return hits,
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
            hits.push((path.clone(), var));
        }
    }
    hits
}

fn nearby_env_names(cwd: &Path, home: Option<&Path>) -> Vec<(PathBuf, String)> {
    let mut hits = Vec::new();
    let mut current = cwd.to_path_buf();
    loop {
        hits.extend(scan_dir_all_env_names(&current));
        if current.join(".git").exists() || home.is_some_and(|h| current == h) {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }
    hits
}

fn policy_inject_names(vault: &Vault) -> BTreeSet<String> {
    vault
        .raw_entries()
        .into_iter()
        .filter_map(|raw| raw.policy_json)
        .filter_map(|json| Policy::parse(&json).ok())
        .map(|policy| policy.secret.inject.name)
        .collect()
}

fn check_env_files_for_names(
    cwd: &Path,
    home: Option<&Path>,
    inject_names: &BTreeSet<String>,
    checks: &mut Vec<Check>,
) {
    let hits = nearby_env_names(cwd, home)
        .into_iter()
        .filter(|(_, var)| inject_names.contains(var))
        .collect::<Vec<_>>();
    if hits.is_empty() {
        checks.push(Check::ok(
            "no policy-injected variable names found in nearby .env* files",
        ));
    } else {
        for (file, var) in hits {
            checks.push(Check::warn(format!(
                "{} defines policy-injected variable `{var}`",
                file.display()
            )));
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
    use std::cell::Cell;

    use crate::error::KpexecError;
    use crate::keychain::{FileKeychain, VaultCredential};
    use crate::secret::Secret;

    fn trusted_signature() -> CodeSignature {
        CodeSignature {
            integrity_valid: true,
            developer_id: true,
            identifier_valid: true,
            team_id_valid: true,
            hardened_runtime: true,
            gatekeeper: GatekeeperAssessment::NotarizedDeveloperId,
        }
    }

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

    #[test]
    fn parses_exact_release_signature_and_notarization() {
        let display = "\
Executable=/tmp/kpexec\n\
Identifier=dev.crazytan.kpexec\n\
CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+0 location=embedded\n\
Authority=Developer ID Application: Jia Tan (V82M9YX8BR)\n\
TeamIdentifier=V82M9YX8BR\n";
        let parsed = parse_signature_outputs(
            true,
            display,
            true,
            "/tmp/kpexec: accepted\nsource=Notarized Developer ID\n",
        );
        assert_eq!(parsed, trusted_signature());

        let impostor = display.replace("V82M9YX8BR", "OTHERTEAM1");
        let parsed = parse_signature_outputs(true, &impostor, true, "source=Developer ID");
        assert!(!parsed.team_id_valid);
        assert_eq!(parsed.gatekeeper, GatekeeperAssessment::Unknown);
        assert!(!parsed.trusted_for_keychain());
    }

    #[test]
    fn bare_cli_gatekeeper_not_applicable_is_warning_not_trust_failure() {
        let display = "\
Identifier=dev.crazytan.kpexec\n\
CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+0 location=embedded\n\
Authority=Developer ID Application: Jia Tan (V82M9YX8BR)\n\
TeamIdentifier=V82M9YX8BR\n";
        let parsed = parse_signature_outputs(
            true,
            display,
            false,
            "/usr/local/bin/kpexec: rejected (the code is valid but does not seem to be an app)\n",
        );
        assert_eq!(
            parsed.gatekeeper,
            GatekeeperAssessment::NotApplicableToBareCli
        );
        assert!(parsed.trusted_for_keychain());

        let mut checks = Vec::new();
        check_code_signature(&parsed, &mut checks);
        assert!(checks.iter().any(|check| {
            check.level == Level::Warn
                && check
                    .message
                    .contains("cannot prove installer notarization")
        }));
        assert!(
            !checks.iter().any(|check| {
                check.level == Level::Fail && check.message.contains("Gatekeeper")
            })
        );
    }

    #[test]
    fn actual_gatekeeper_rejection_remains_failure() {
        assert_eq!(
            parse_gatekeeper_assessment(
                false,
                "/usr/local/bin/kpexec: rejected\nsource=Unnotarized Developer ID\n"
            ),
            GatekeeperAssessment::Rejected
        );
        let mut signature = trusted_signature();
        signature.gatekeeper = GatekeeperAssessment::Rejected;
        let mut checks = Vec::new();
        check_code_signature(&signature, &mut checks);
        assert!(checks.iter().any(|check| {
            check.level == Level::Fail && check.message.contains("Gatekeeper rejected")
        }));
        // Package notarization is not part of the Keychain identity proof.
        assert!(signature.trusted_for_keychain());
    }

    struct CountingStore {
        gets: Cell<usize>,
        binding: AclBinding,
    }

    impl KeychainStore for CountingStore {
        fn acl_binding(&self, _account: &str) -> Result<AclBinding> {
            Ok(self.binding)
        }

        fn get(&self, _account: &str) -> Result<Option<VaultCredential>> {
            self.gets.set(self.gets.get() + 1);
            Err(KpexecError::internal("get must not be called"))
        }

        fn set(&self, _account: &str, _credential: &VaultCredential) -> Result<()> {
            unreachable!()
        }

        fn delete(&self, _account: &str) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn unverified_acl_never_reads_protected_credential() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        std::fs::write(&vault_path, b"not opened").unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("db_path = {:?}\n", vault_path.to_string_lossy()),
        )
        .unwrap();
        let store = CountingStore {
            gets: Cell::new(0),
            binding: AclBinding::Unverified,
        };

        let report = run_full_with(
            &config_path,
            &dir.path().join("logs"),
            dir.path(),
            Some(dir.path()),
            &trusted_signature(),
            &store,
        );
        assert_eq!(store.gets.get(), 0);
        assert!(report.checks.iter().any(|check| {
            check.level == Level::Fail && check.message.contains("ACL provenance is absent")
        }));
    }

    #[test]
    fn invalid_identity_with_bare_cli_assessment_never_reads_credential() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        std::fs::write(&vault_path, b"not opened").unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("db_path = {:?}\n", vault_path.to_string_lossy()),
        )
        .unwrap();
        let store = CountingStore {
            gets: Cell::new(0),
            binding: AclBinding::Verified,
        };
        let mut signature = trusted_signature();
        signature.identifier_valid = false;
        signature.gatekeeper = GatekeeperAssessment::NotApplicableToBareCli;

        let report = run_full_with(
            &config_path,
            &dir.path().join("logs"),
            dir.path(),
            Some(dir.path()),
            &signature,
            &store,
        );

        assert_eq!(store.gets.get(), 0);
        assert!(report.checks.iter().any(|check| {
            check.level == Level::Fail && check.message.contains("code-signing identifier")
        }));
        assert!(report.checks.iter().any(|check| {
            check.level == Level::Warn
                && check
                    .message
                    .contains("cannot prove installer notarization")
        }));
    }

    #[test]
    fn full_checks_validate_identity_pins_and_policy_env_names_with_fake_store() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".env"), "GH_TOKEN=must-not-be-reported\n").unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let master = Secret::new("test-master-password".to_string());
        let mut vault = Vault::create(vault_path.clone(), master.clone());
        let mut policy = Policy::new("test".to_string(), "GH_TOKEN".to_string(), None);
        let executable = std::fs::canonicalize("/bin/echo").unwrap();
        policy.commands.push(crate::policy::Command {
            name: "echo".to_string(),
            exe: executable.to_string_lossy().into_owned(),
            exe_sha256: Some(
                crate::pin::compute(executable.to_str().unwrap())
                    .unwrap()
                    .sha256,
            ),
            argv_prefix: Vec::new(),
        });
        vault
            .insert_entry(
                "test",
                "test",
                &Secret::new("entry-secret".to_string()),
                &policy,
            )
            .unwrap();
        vault.save_atomic().unwrap();

        let keychain = FileKeychain::new(dir.path().join("keychain")).unwrap();
        let canonical = std::fs::canonicalize(&vault_path).unwrap();
        keychain
            .set(
                &account_for(&vault_path),
                &VaultCredential {
                    password: master,
                    db_path: canonical.to_string_lossy().into_owned(),
                },
            )
            .unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("db_path = {:?}\n", canonical.to_string_lossy()),
        )
        .unwrap();

        let mut signature = trusted_signature();
        signature.gatekeeper = GatekeeperAssessment::NotApplicableToBareCli;
        let report = run_full_with(
            &config_path,
            &dir.path().join("logs"),
            dir.path(),
            Some(dir.path()),
            &signature,
            &keychain,
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| { check.level == Level::Ok && check.message.contains("pin current") })
        );
        assert!(report.checks.iter().any(|check| {
            check.level == Level::Warn
                && check
                    .message
                    .contains("policy-injected variable `GH_TOKEN`")
        }));
        assert!(report.checks.iter().any(|check| {
            check.level == Level::Ok
                && check
                    .message
                    .contains("protected db_path agrees with config")
        }));
        assert!(report.checks.iter().any(|check| {
            check.level == Level::Warn
                && check
                    .message
                    .contains("cannot prove installer notarization")
        }));
        assert!(!report.render().contains("must-not-be-reported"));
    }
}
