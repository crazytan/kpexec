//! `kpexec entry …` — the entry/policy lifecycle handlers.
//!
//! Every mutating handler:
//! 1. prints the pre-M3 mutation warning,
//! 2. resolves the vault path (config hint) + Keychain store,
//! 3. takes a write lock (refusing on a KeePassXC lockfile / live kpexec lock),
//! 4. opens the vault (identity-bound), mutates in memory, and saves atomically.
//!
//! Wizard fields may be supplied via flags for non-interactive use; the wizard
//! prompts only for what a flag did not provide. Secrets are read hidden and
//! held in [`Secret`]; `show` masks the secret ALWAYS.

use std::io::Write as _;
use std::path::Path;

use crate::cli::{
    CommandSpec, EntryAddArgs, EntryAddCommandArgs, EntryEditArgs, EntryListArgs, EntryRepinArgs,
    EntryRmCommandArgs, EntrySetSecretArgs, EntryShowArgs,
};
use crate::error::{KpexecError, Result};
use crate::keychain::KeychainStore;
use crate::pin;
use crate::policy::{Command, Policy};
use crate::status::{KpexecStatus, Outcome};
use crate::vault::{EntryView, Vault, acquire_write_lock};
use crate::{prompt, vaultctx};

// ---------------------------------------------------------------------------
// Shared open helpers
// ---------------------------------------------------------------------------

/// Open the configured vault for reading through the production keychain.
fn open_configured_ro() -> Result<Vault> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    open_ro(&vault_path, keychain.as_ref(), cfg.db_path.as_deref())
}

/// Open a specific vault path for reading with an explicit keychain (testable).
pub fn open_ro(
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Vault> {
    Vault::open(vault_path, keychain, config_hint)
}

// ---------------------------------------------------------------------------
// entry add
// ---------------------------------------------------------------------------

/// `kpexec entry add` production entry point.
pub fn add(args: EntryAddArgs) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    add_with(
        &args,
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
    )
}

/// Testable core of `entry add`.
pub fn add_with(
    args: &EntryAddArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let id = prompt::read_line("Entry id", args.id.clone())?;
    reject_empty(&id, "entry id")?;

    let description = prompt::read_line("Description", args.description.clone())?;
    let inject = prompt::read_line("Inject as env var", args.inject.clone())?;
    reject_empty(&inject, "inject env var name")?;
    let title = args.title.clone().unwrap_or_else(|| id.clone());

    let secret = prompt::read_secret("Secret (hidden): ", args.secret_stdin)?;

    let mut policy = Policy::new(description, inject, None);
    let commands = collect_commands(&args.commands, args.no_pin)?;
    if commands.is_empty() {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            "an entry needs at least one command template",
        ));
    }
    policy.commands = commands;
    reject_duplicate_command_names(&policy)?;

    // Lock + open + mutate + save.
    let _lock = acquire_write_lock(vault_path)?;
    let mut vault = Vault::open(vault_path, keychain, config_hint)?;

    if vault.contains(&id) && !args.force {
        return Err(KpexecError::new(
            KpexecStatus::ConfigError,
            format!("entry {id:?} already exists; pass --force to replace it"),
        ));
    }
    if vault.contains(&id) {
        vault.remove_entry(&id)?;
    }
    vault.insert_entry(&id, &title, &secret, &policy)?;
    vault.save_atomic()?;

    println!(
        "entry {:?} ({} command(s)) written to {}",
        id,
        policy.commands.len(),
        vault_path.display()
    );
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

// ---------------------------------------------------------------------------
// entry add-command
// ---------------------------------------------------------------------------

/// `kpexec entry add-command` production entry point.
pub fn add_command(args: EntryAddCommandArgs) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    add_command_with(
        &args,
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
    )
}

/// Testable core of `entry add-command`.
pub fn add_command_with(
    args: &EntryAddCommandArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let new_commands = collect_commands(&args.commands, args.no_pin)?;
    if new_commands.is_empty() {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            "add-command needs at least one command template",
        ));
    }

    let _lock = acquire_write_lock(vault_path)?;
    let mut vault = Vault::open(vault_path, keychain, config_hint)?;
    let view = require_entry(&vault, &args.id)?;
    let mut policy = view.policy;
    policy.commands.extend(new_commands);
    reject_duplicate_command_names(&policy)?;

    vault.update_policy(&args.id, &policy)?;
    vault.save_atomic()?;

    println!(
        "entry {:?} now has {} command(s)",
        args.id,
        policy.commands.len()
    );
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

// ---------------------------------------------------------------------------
// entry rm-command
// ---------------------------------------------------------------------------

/// `kpexec entry rm-command` production entry point.
pub fn rm_command(args: EntryRmCommandArgs) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    rm_command_with(
        &args,
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
    )
}

/// Testable core of `entry rm-command`.
pub fn rm_command_with(
    args: &EntryRmCommandArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let _lock = acquire_write_lock(vault_path)?;
    let mut vault = Vault::open(vault_path, keychain, config_hint)?;
    let view = require_entry(&vault, &args.id)?;
    let mut policy = view.policy;
    let before = policy.commands.len();
    policy.commands.retain(|c| c.name != args.name);
    if policy.commands.len() == before {
        return Err(KpexecError::new(
            KpexecStatus::UnknownCommand,
            format!("entry {:?} has no command {:?}", args.id, args.name),
        ));
    }
    if policy.commands.is_empty() {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            "cannot remove the last command; use `entry rm` to delete the entry",
        ));
    }

    vault.update_policy(&args.id, &policy)?;
    vault.save_atomic()?;
    println!("removed command {:?} from entry {:?}", args.name, args.id);
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

// ---------------------------------------------------------------------------
// entry set-secret
// ---------------------------------------------------------------------------

/// `kpexec entry set-secret` production entry point.
pub fn set_secret(args: EntrySetSecretArgs) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    set_secret_with(
        &args,
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
    )
}

/// Testable core of `entry set-secret`.
pub fn set_secret_with(
    args: &EntrySetSecretArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let secret = prompt::read_secret("New secret (hidden): ", args.secret_stdin)?;

    let _lock = acquire_write_lock(vault_path)?;
    let mut vault = Vault::open(vault_path, keychain, config_hint)?;
    // Ensure the entry exists (and is unique) before mutating.
    require_entry(&vault, &args.id)?;
    vault.update_secret(&args.id, &secret)?;
    vault.save_atomic()?;
    println!("rotated secret for entry {:?}", args.id);
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

// ---------------------------------------------------------------------------
// entry edit
// ---------------------------------------------------------------------------

/// `kpexec entry edit` production entry point.
pub fn edit(args: EntryEditArgs) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    edit_with(
        &args,
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
    )
}

/// Testable core of `entry edit` (description / inject only; commands are edited
/// via add-command / rm-command / repin, secrets via set-secret).
pub fn edit_with(
    args: &EntryEditArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let _lock = acquire_write_lock(vault_path)?;
    let mut vault = Vault::open(vault_path, keychain, config_hint)?;
    let view = require_entry(&vault, &args.id)?;
    let mut policy = view.policy;

    if let Some(d) = &args.description {
        policy.description = d.clone();
    }
    if let Some(name) = &args.inject {
        reject_empty(name, "inject env var name")?;
        policy.secret.inject.name = name.clone();
    }

    vault.update_policy(&args.id, &policy)?;
    vault.save_atomic()?;
    // Title edits are display-only; not part of the policy JSON. Left to a
    // future flag if needed — the doc treats Title as display-only.
    let _ = &args.title;
    println!("updated entry {:?}", args.id);
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

// ---------------------------------------------------------------------------
// entry rm
// ---------------------------------------------------------------------------

/// `kpexec entry rm` production entry point.
pub fn rm(id: &str) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    rm_with(id, &vault_path, keychain.as_ref(), cfg.db_path.as_deref())
}

/// Testable core of `entry rm`.
pub fn rm_with(
    id: &str,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let _lock = acquire_write_lock(vault_path)?;
    let mut vault = Vault::open(vault_path, keychain, config_hint)?;
    require_entry(&vault, id)?;
    vault.remove_entry(id)?;
    vault.save_atomic()?;
    println!("removed entry {id:?}");
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

// ---------------------------------------------------------------------------
// entry list
// ---------------------------------------------------------------------------

/// `kpexec entry list` production entry point.
pub fn list(args: EntryListArgs) -> Result<Outcome> {
    let vault = open_configured_ro()?;
    list_render(&vault, args.json)
}

/// Render the list (testable with an open vault).
pub fn list_render(vault: &Vault, json: bool) -> Result<Outcome> {
    // A duplicate id across the vault is a hard reject (deny by default, never
    // pick-first) — surface it before rendering anything.
    let dups = vault.duplicate_ids();
    if !dups.is_empty() {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            format!(
                "duplicate kpexec.id(s): {}; refusing to list",
                dups.join(", ")
            ),
        ));
    }

    let mut views = Vec::new();
    for raw in vault.raw_entries() {
        // Malformed-policy entries are skipped here (list shows well-formed
        // entries); `check` reports the malformed ones with detail.
        match vault.find_entry(&raw.id) {
            Ok(Some(view)) => views.push(view),
            Ok(None) => {}
            Err(_) => {}
        }
    }

    if json {
        println!("{}", list_json(&views));
    } else {
        print_table(&views);
    }
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

fn list_json(views: &[EntryView]) -> String {
    // Build a plain serde_json value: agents consume this. Secret is never
    // included.
    let entries: Vec<serde_json::Value> = views
        .iter()
        .map(|v| {
            let commands: Vec<serde_json::Value> = v
                .policy
                .commands
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "exe": c.exe,
                        "argv_prefix": c.argv_prefix,
                        "pinned": c.exe_sha256.is_some(),
                    })
                })
                .collect();
            serde_json::json!({
                "id": v.id,
                "description": v.policy.description,
                "inject": v.policy.secret.inject.name,
                "commands": commands,
            })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({ "entries": entries }))
        .unwrap_or_else(|_| r#"{"entries":[]}"#.to_string())
}

fn print_table(views: &[EntryView]) {
    if views.is_empty() {
        println!("(no entries)");
        return;
    }
    println!(
        "{:<12} {:<16} {:<24} PREFIX",
        "ENTRY", "COMMAND", "EXECUTABLE"
    );
    for v in views {
        for c in &v.policy.commands {
            println!(
                "{:<12} {:<16} {:<24} {}",
                v.id,
                c.name,
                c.exe,
                c.argv_prefix.join(" ")
            );
        }
    }
}

// ---------------------------------------------------------------------------
// entry show
// ---------------------------------------------------------------------------

/// `kpexec entry show` production entry point.
pub fn show(args: EntryShowArgs) -> Result<Outcome> {
    let vault = open_configured_ro()?;
    show_render(&vault, &args.id, args.json)
}

/// Render one entry, secret ALWAYS masked (testable).
pub fn show_render(vault: &Vault, id: &str, json: bool) -> Result<Outcome> {
    let view = require_entry(vault, id)?;
    if json {
        println!("{}", show_json(&view));
    } else {
        print_show(&view);
    }
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

/// The masked marker used everywhere the secret would otherwise appear.
pub const MASK: &str = "********";

fn show_json(view: &EntryView) -> String {
    let commands: Vec<serde_json::Value> = view
        .policy
        .commands
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "exe": c.exe,
                "exe_sha256": c.exe_sha256,
                "argv_prefix": c.argv_prefix,
            })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "id": view.id,
        "description": view.policy.description,
        // The secret is ALWAYS masked; the value is never serialized.
        "secret": MASK,
        "inject": view.policy.secret.inject.name,
        "commands": commands,
        "output": {
            "max_stdout_bytes": view.policy.output.max_stdout_bytes,
            "max_stderr_bytes": view.policy.output.max_stderr_bytes,
        },
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn print_show(view: &EntryView) {
    println!("id:          {}", view.id);
    println!("description: {}", view.policy.description);
    println!("secret:      {MASK} (Password field)");
    println!("inject:      env {}", view.policy.secret.inject.name);
    println!("commands:");
    for c in &view.policy.commands {
        let pin = if c.exe_sha256.is_some() {
            "pinned"
        } else {
            "UNPINNED"
        };
        println!(
            "  {} -> {} {} [trailing args...] ({pin})",
            c.name,
            c.exe,
            c.argv_prefix.join(" ")
        );
    }
    println!(
        "output:      stdout <= {} B, stderr <= {} B",
        view.policy.output.max_stdout_bytes, view.policy.output.max_stderr_bytes
    );
}

// ---------------------------------------------------------------------------
// entry repin
// ---------------------------------------------------------------------------

/// `kpexec entry repin` production entry point.
pub fn repin(args: EntryRepinArgs) -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    repin_with(
        &args,
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
    )
}

/// Testable core of `entry repin`. Shows old -> new hash + mtime + size before
/// the (M3) Touch ID prompt.
pub fn repin_with(
    args: &EntryRepinArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let _lock = acquire_write_lock(vault_path)?;
    let mut vault = Vault::open(vault_path, keychain, config_hint)?;
    let view = require_entry(&vault, &args.id)?;
    let mut policy = view.policy;

    let target = args.command_name.as_deref();
    if target.is_some_and(|name| policy.command(name).is_none()) {
        let name = target.unwrap_or_default();
        return Err(KpexecError::new(
            KpexecStatus::UnknownCommand,
            format!("entry {:?} has no command {name:?}", args.id),
        ));
    }

    let mut repinned = 0usize;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for cmd in policy.commands.iter_mut() {
        if target.is_some_and(|name| cmd.name != name) {
            continue;
        }
        let fresh = pin::compute(&cmd.exe)?;
        let old = cmd.exe_sha256.clone();
        // Without a target name, only repin stale/missing pins.
        let is_stale = old.as_deref() != Some(fresh.sha256.as_str());
        if target.is_none() && !is_stale {
            continue;
        }
        let _ = writeln!(
            out,
            "repin {}: {} -> {} (size {} B{})",
            cmd.name,
            old.as_deref().unwrap_or("<unpinned>"),
            fresh.sha256,
            fresh.size,
            match fresh
                .mtime
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            {
                Some(d) => format!(", mtime {}s", d.as_secs()),
                None => String::new(),
            }
        );
        cmd.exe_sha256 = Some(fresh.sha256);
        repinned += 1;
    }

    if repinned == 0 {
        println!("nothing to repin (all pins current)");
        return Ok(Outcome::Kpexec(KpexecStatus::Success));
    }

    vault.update_policy(&args.id, &policy)?;
    vault.save_atomic()?;
    println!("repinned {repinned} command(s) in entry {:?}", args.id);
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

// ---------------------------------------------------------------------------
// Shared wizard / validation helpers
// ---------------------------------------------------------------------------

/// Turn CLI command specs (or an interactive loop) into policy [`Command`]s,
/// computing pins unless `no_pin` is set. Prints prefix warnings to stderr.
fn collect_commands(specs: &[CommandSpec], no_pin: bool) -> Result<Vec<Command>> {
    if specs.is_empty() {
        // Interactive wizard loop.
        return collect_commands_interactive(no_pin);
    }
    let mut out = Vec::new();
    for spec in specs {
        out.push(build_command(&spec.name, &spec.exe, &spec.prefix, no_pin)?);
    }
    Ok(out)
}

/// The interactive command-collection loop (used only when no `--command`
/// flags were passed). Errors out when stdin is not a terminal so scripts fail
/// loudly rather than hanging.
fn collect_commands_interactive(no_pin: bool) -> Result<Vec<Command>> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        return Err(KpexecError::new(
            KpexecStatus::ConfigError,
            "no --command specs supplied and stdin is not a terminal; pass --command name=..;exe=..;prefix=..",
        ));
    }
    let mut out = Vec::new();
    loop {
        let n = out.len() + 1;
        println!("Command template {n}");
        let name = prompt::read_line("  Name", None)?;
        let exe = prompt::read_line("  Executable (absolute path)", None)?;
        let prefix = prompt::read_line("  Fixed argument prefix", None)?;
        out.push(build_command(&name, &exe, &prefix, no_pin)?);
        let more = prompt::read_line("Add another command template? [y/N]", None)?;
        if !matches!(more.trim(), "y" | "Y" | "yes") {
            break;
        }
    }
    Ok(out)
}

/// Build one [`Command`], canonicalizing + pinning the exe unless `no_pin`.
fn build_command(name: &str, exe: &str, prefix_raw: &str, no_pin: bool) -> Result<Command> {
    reject_empty(name, "command name")?;
    reject_empty(exe, "command executable")?;
    let (prefix, warning) = prompt::parse_prefix(prefix_raw)?;
    if let Some(w) = warning {
        eprintln!("{}", w.message());
    }
    let exe_sha256 = if no_pin {
        eprintln!(
            "[kpexec] WARNING: command {name:?} authored with --no-pin (flagged by check/doctor)"
        );
        None
    } else {
        Some(pin::compute(exe)?.sha256)
    };
    Ok(Command {
        name: name.to_string(),
        exe: exe.to_string(),
        exe_sha256,
        argv_prefix: prefix,
    })
}

/// Fetch an entry, mapping "absent" to a clean `unknown-entry` error.
fn require_entry(vault: &Vault, id: &str) -> Result<EntryView> {
    vault.find_entry(id)?.ok_or_else(|| {
        KpexecError::new(
            KpexecStatus::UnknownEntry,
            format!("no entry with id {id:?}"),
        )
    })
}

fn reject_empty(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            format!("{what} must not be empty"),
        ));
    }
    Ok(())
}

fn reject_duplicate_command_names(policy: &Policy) -> Result<()> {
    let dups = policy.duplicate_command_names();
    if !dups.is_empty() {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            format!("duplicate command name(s): {}", dups.join(", ")),
        ));
    }
    Ok(())
}
