//! The clap command tree.
//!
//! Mirrors the subcommand surface in `docs/cli-design.md` exactly. This module
//! only *describes* the CLI; dispatch and behavior live in [`crate::commands`].

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// kpexec — broker secrets into policy-shaped child processes.
#[derive(Debug, Parser)]
#[command(name = "kpexec", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Execute an allowed command template (the only agent-facing command).
    Run(RunArgs),

    /// Create and initialize a new vault.
    Init(InitArgs),

    /// Validate config, filesystem, and (in later milestones) the vault.
    Doctor,

    /// Entry and policy management.
    #[command(subcommand)]
    Entry(EntryCommand),

    /// Validate policies without running anything.
    Check(CheckArgs),

    /// Vault-level maintenance.
    #[command(subcommand)]
    Db(DbCommand),
}

/// `kpexec run --entry <id> --command <name> [flags] [-- trailing...]`
#[derive(Debug, Args)]
pub struct RunArgs {
    /// The entry id (credential bundle) to use.
    #[arg(long)]
    pub entry: String,

    /// The command template (allowed action) under that entry.
    #[arg(long)]
    pub command: String,

    /// Resolve the request and print the exact argv without running anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Kill the child after this many seconds (default from config, else 300).
    #[arg(long, value_name = "SEC")]
    pub timeout: Option<u64>,

    /// Emit the structured JSON result envelope.
    #[arg(long)]
    pub json: bool,

    /// Arguments appended verbatim to the policy's argv prefix. Everything after
    /// `--` is captured as-is (hyphen-leading values included).
    #[arg(last = true, allow_hyphen_values = true)]
    pub trailing: Vec<String>,
}

/// `kpexec init [--db <path>] [--use-existing] [--force]`
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Vault path to create (default: ~/Secrets/kpexec-agent.kdbx).
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Adopt an existing kdbx instead of creating one.
    #[arg(long)]
    pub use_existing: bool,

    /// Overwrite an existing vault/config/Keychain item. Refused otherwise.
    #[arg(long)]
    pub force: bool,

    /// Read the existing vault's password from stdin (implies non-interactive;
    /// used with `--use-existing`). A deliberate extension so `init` is
    /// scriptable and testable without a TTY.
    #[arg(long)]
    pub password_stdin: bool,
}

/// `kpexec check [--entry <id>]`
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Restrict the check to a single entry.
    #[arg(long)]
    pub entry: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum EntryCommand {
    /// Add a new entry (credential + policy) via a wizard.
    Add(EntryAddArgs),

    /// Append another command template to an existing entry.
    AddCommand(EntryAddCommandArgs),

    /// Revoke a single command template from an entry.
    RmCommand(EntryRmCommandArgs),

    /// Rotate the stored credential without touching the policy.
    SetSecret(EntrySetSecretArgs),

    /// Re-run the wizard fields for an entry.
    Edit(EntryEditArgs),

    /// Remove an entry entirely.
    Rm(EntryIdArg),

    /// List entries and their commands.
    List(EntryListArgs),

    /// Show one entry's full policy (secret always masked).
    Show(EntryShowArgs),

    /// Recompute executable pins after a legitimate binary upgrade.
    Repin(EntryRepinArgs),
}

/// A single `--command name=<n>,exe=<path>,prefix=<shell words>` value.
///
/// Command templates may be supplied non-interactively via repeated
/// `--command` flags (a deliberate extension so tests/scripts run without a
/// TTY). Format is comma-separated `key=value` pairs; `prefix` uses shell-word
/// quoting so commas inside a quoted arg are preserved by splitting on the
/// first `=` per key. Recognized keys: `name`, `exe`, `prefix`.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    /// The command name.
    pub name: String,
    /// The absolute executable path.
    pub exe: String,
    /// The raw prefix string (shell-word parsed downstream).
    pub prefix: String,
}

impl std::str::FromStr for CommandSpec {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut name = None;
        let mut exe = None;
        let mut prefix = String::new();
        for part in s.split(';') {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| format!("expected key=value in {part:?}"))?;
            match k.trim() {
                "name" => name = Some(v.to_string()),
                "exe" => exe = Some(v.to_string()),
                "prefix" => prefix = v.to_string(),
                other => return Err(format!("unknown command key {other:?}")),
            }
        }
        Ok(CommandSpec {
            name: name.ok_or("command spec missing name=")?,
            exe: exe.ok_or("command spec missing exe=")?,
            prefix,
        })
    }
}

/// `kpexec entry add [<id>] [--no-pin] [--secret-stdin] [wizard overrides]`
#[derive(Debug, Args)]
pub struct EntryAddArgs {
    /// Optional entry id; prompted for if omitted.
    pub id: Option<String>,

    /// Skip executable pinning for the command(s) (flagged by check/doctor).
    #[arg(long)]
    pub no_pin: bool,

    /// Read the secret from stdin instead of an interactive prompt.
    #[arg(long)]
    pub secret_stdin: bool,

    /// Non-interactive: entry description.
    #[arg(long)]
    pub description: Option<String>,

    /// Non-interactive: the KeePass Title (display label). Defaults to the id.
    #[arg(long)]
    pub title: Option<String>,

    /// Non-interactive: the env var name to inject the secret as.
    #[arg(long)]
    pub inject: Option<String>,

    /// Non-interactive: repeatable command template
    /// (`name=..;exe=..;prefix=..`).
    #[arg(long = "command", value_name = "SPEC")]
    pub commands: Vec<CommandSpec>,

    /// Refuse to overwrite an existing entry with the same id unless set.
    #[arg(long)]
    pub force: bool,
}

/// `kpexec entry add-command <id> [wizard overrides]`
#[derive(Debug, Args)]
pub struct EntryAddCommandArgs {
    /// The entry id.
    pub id: String,

    /// Skip executable pinning for the new command.
    #[arg(long)]
    pub no_pin: bool,

    /// Non-interactive: repeatable command template
    /// (`name=..;exe=..;prefix=..`).
    #[arg(long = "command", value_name = "SPEC")]
    pub commands: Vec<CommandSpec>,
}

/// `kpexec entry set-secret <id> [--secret-stdin]`
#[derive(Debug, Args)]
pub struct EntrySetSecretArgs {
    /// The entry id.
    pub id: String,

    /// Read the new secret from stdin instead of a hidden prompt.
    #[arg(long)]
    pub secret_stdin: bool,
}

/// `kpexec entry edit <id> [wizard overrides]`
#[derive(Debug, Args)]
pub struct EntryEditArgs {
    /// The entry id.
    pub id: String,

    /// Non-interactive: new description.
    #[arg(long)]
    pub description: Option<String>,

    /// Non-interactive: new KeePass Title.
    #[arg(long)]
    pub title: Option<String>,

    /// Non-interactive: new inject env var name.
    #[arg(long)]
    pub inject: Option<String>,
}

/// A bare `<id>` positional, shared by several entry subcommands.
#[derive(Debug, Args)]
pub struct EntryIdArg {
    /// The entry id.
    pub id: String,
}

/// `kpexec entry rm-command <id> <name>`
#[derive(Debug, Args)]
pub struct EntryRmCommandArgs {
    /// The entry id.
    pub id: String,
    /// The command name to revoke.
    pub name: String,
}

/// `kpexec entry list [--json]`
#[derive(Debug, Args)]
pub struct EntryListArgs {
    /// Emit machine-readable JSON (agents should use this).
    #[arg(long)]
    pub json: bool,
}

/// `kpexec entry show <id> [--json]`
#[derive(Debug, Args)]
pub struct EntryShowArgs {
    /// The entry id.
    pub id: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// `kpexec entry repin <id> [<command-name>]`
#[derive(Debug, Args)]
pub struct EntryRepinArgs {
    /// The entry id.
    pub id: String,
    /// A single command to repin; if omitted, repins every stale command.
    pub command_name: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Regenerate the vault master password and re-encrypt.
    RotatePassword,
    /// Re-display the vault master password.
    ShowPassword,
}
