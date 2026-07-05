//! `kpexec check [--entry <id>]` — validate policies without running anything.
//!
//! Validates, per cli-design:
//! * policy JSON parses (with `deny_unknown_fields` — unknown fields reject),
//! * the schema string is known,
//! * `kpexec.id` is unique across the vault,
//! * command names are unique per entry,
//! * each exe exists and canonicalizes,
//! * pins are present and current (missing/stale pins are WARNINGS).
//!
//! Reuses the doctor-style `Level`/`Check`/`Report` shapes so output is
//! consistent. A FAIL maps to a non-success exit; WARN-only is success.

use crate::cli::CheckArgs;
use crate::doctor::{Check, Level, Report};
use crate::error::Result;
use crate::pin;
use crate::policy::Policy;
use crate::status::Outcome;
use crate::vault::Vault;
use crate::vaultctx;

/// `kpexec check` production entry point.
pub fn run(args: CheckArgs) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    let vault = Vault::open(&vault_path, keychain.as_ref(), cfg.db_path.as_deref())?;
    let report = check_vault(&vault, args.entry.as_deref());
    print!("{}", report.render());
    Ok(Outcome::Kpexec(report.status()))
}

/// Run the checks against an already-open vault (testable).
pub fn check_vault(vault: &Vault, only: Option<&str>) -> Report {
    let mut checks = Vec::new();

    // Vault-wide uniqueness of kpexec.id.
    let dups = vault.duplicate_ids();
    if dups.is_empty() {
        checks.push(check_ok("all kpexec.id values are unique"));
    } else {
        for id in &dups {
            checks.push(check_fail(format!(
                "duplicate kpexec.id {id:?} across the vault"
            )));
        }
    }

    let raws = vault.raw_entries();
    if raws.is_empty() {
        checks.push(check_warn("vault has no kpexec entries"));
    }

    for raw in raws {
        if only.is_some_and(|target| raw.id != target) {
            continue;
        }
        // Skip duplicated ids here — already reported as a fail above, and
        // find_entry would reject.
        if dups.contains(&raw.id) {
            continue;
        }
        check_one_entry(vault, &raw.id, &mut checks);
    }

    if only.is_some_and(|target| !vault.contains(target)) {
        let target = only.unwrap_or_default();
        checks.push(check_fail(format!("no entry with id {target:?}")));
    }

    Report { checks }
}

fn check_one_entry(vault: &Vault, id: &str, checks: &mut Vec<Check>) {
    let view = match vault.find_entry(id) {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(e) => {
            // Malformed policy / unknown schema / unknown field all land here.
            checks.push(check_fail(format!("entry {id}: {}", e.message())));
            return;
        }
    };
    let policy = &view.policy;

    // Schema is validated inside Policy::parse; getting here means it is known.
    checks.push(check_ok(format!(
        "entry {id}: policy parses (schema known)"
    )));

    if !view.has_secret {
        checks.push(check_warn(format!(
            "entry {id}: no secret stored (Password field empty)"
        )));
    }

    // Per-entry command-name uniqueness.
    let dup_names = policy.duplicate_command_names();
    for name in &dup_names {
        checks.push(check_fail(format!(
            "entry {id}: duplicate command name {name:?}"
        )));
    }

    for cmd in &policy.commands {
        check_command_pin(id, policy, &cmd.name, checks);
    }
}

fn check_command_pin(id: &str, policy: &Policy, name: &str, checks: &mut Vec<Check>) {
    let Some(cmd) = policy.command(name) else {
        return;
    };
    // Exe must exist and canonicalize.
    match pin::compute(&cmd.exe) {
        Ok(fresh) => match &cmd.exe_sha256 {
            None => checks.push(check_warn(format!(
                "entry {id} command {name}: unpinned (--no-pin); repin to close the tampered-binary hole"
            ))),
            Some(recorded) if recorded.eq_ignore_ascii_case(&fresh.sha256) => {
                checks.push(check_ok(format!("entry {id} command {name}: pin current")));
            }
            Some(_) => checks.push(check_warn(format!(
                "entry {id} command {name}: pin STALE (binary changed since authoring) — run `kpexec entry repin {id} {name}`"
            ))),
        },
        Err(e) => checks.push(check_fail(format!(
            "entry {id} command {name}: {}",
            e.message()
        ))),
    }
}

// Small constructors mirroring doctor's private ones (which are not public).
fn check_ok(msg: impl Into<String>) -> Check {
    Check {
        level: Level::Ok,
        message: msg.into(),
    }
}
fn check_warn(msg: impl Into<String>) -> Check {
    Check {
        level: Level::Warn,
        message: msg.into(),
    }
}
fn check_fail(msg: impl Into<String>) -> Check {
    Check {
        level: Level::Fail,
        message: msg.into(),
    }
}

/// Open `vault_path` with the given keychain and run the checks. Exposed for
/// integration tests (and reusable by callers that already hold a path).
pub fn check_at(
    vault_path: &std::path::Path,
    keychain: &dyn crate::keychain::KeychainStore,
    config_hint: Option<&std::path::Path>,
    only: Option<&str>,
) -> Result<Report> {
    let vault = Vault::open(vault_path, keychain, config_hint)?;
    Ok(check_vault(&vault, only))
}
