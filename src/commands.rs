//! Command dispatch.
//!
//! Every subcommand is routed here. This is also the single authorization
//! boundary: every write-capable or recovery-password command must pass the
//! macOS user-presence gate before its handler can run.

use crate::cli::{Command, DbCommand, EntryCommand};
use crate::error::Result as KpexecResult;
use crate::status::Outcome;
use crate::user_presence::{SystemUserPresence, UserPresence};
use crate::{cmd_check, cmd_entry, cmd_init, cmd_run, doctor};

/// Dispatch a parsed command to its handler.
///
/// Returns the [`Outcome`] used to compute the process exit code. Human-facing
/// output is printed here; the `--json` envelope is emitted by the individual
/// handlers that support it (currently `run`).
pub fn dispatch(command: Command) -> KpexecResult<Outcome> {
    dispatch_with_user_presence(command, &SystemUserPresence)
}

/// Dispatch with an explicit user-presence provider.
///
/// This is the security boundary for CLI mutations. Authorization is evaluated
/// before the selected handler is entered, so a denial cannot create a lock,
/// open or change the vault, access the Keychain, or update config. Keeping the
/// provider injectable also makes that ordering automatically testable without
/// presenting a real macOS authentication sheet.
pub fn dispatch_with_user_presence(
    command: Command,
    user_presence: &dyn UserPresence,
) -> KpexecResult<Outcome> {
    if let Some(reason) = authorization_reason(&command) {
        user_presence.authorize(&reason)?;
    }
    dispatch_authorized(command)
}

/// Route a command after the dispatch boundary has performed any required
/// authorization.
fn dispatch_authorized(command: Command) -> KpexecResult<Outcome> {
    match command {
        Command::Run(args) => cmd_run::run(args),
        Command::Init(args) => cmd_init::run(args),
        Command::Doctor => doctor_cmd(),
        Command::Entry(sub) => entry(sub),
        Command::Check(args) => cmd_check::run(args),
        Command::Db(sub) => db(sub),
    }
}

/// Return a secret-free LocalAuthentication reason for commands that require a
/// present human. This exhaustive match is intentionally adjacent to dispatch:
/// adding a CLI variant forces an explicit gated/ungated decision.
fn authorization_reason(command: &Command) -> Option<String> {
    match command {
        Command::Init(args) => Some(match &args.db {
            Some(path) => format!(
                "Approve initializing the kpexec vault at {}",
                prompt_safe(&path.to_string_lossy())
            ),
            None => "Approve initializing the kpexec vault".to_string(),
        }),
        Command::Entry(sub) => match sub {
            EntryCommand::Add(args) => Some(match &args.id {
                Some(id) => format!("Approve creating kpexec entry '{}'", prompt_safe(id)),
                None => "Approve creating a new kpexec entry".to_string(),
            }),
            EntryCommand::AddCommand(args) => Some(format!(
                "Approve adding a command to kpexec entry '{}'",
                prompt_safe(&args.id)
            )),
            EntryCommand::RmCommand(args) => Some(format!(
                "Approve removing command '{}' from kpexec entry '{}'",
                prompt_safe(&args.name),
                prompt_safe(&args.id)
            )),
            EntryCommand::SetSecret(args) => Some(format!(
                "Approve changing the secret for kpexec entry '{}'",
                prompt_safe(&args.id)
            )),
            EntryCommand::Edit(args) => Some(format!(
                "Approve editing kpexec entry '{}'",
                prompt_safe(&args.id)
            )),
            EntryCommand::Rm(args) => Some(format!(
                "Approve deleting kpexec entry '{}'",
                prompt_safe(&args.id)
            )),
            EntryCommand::Repin(args) => Some(match &args.command_name {
                Some(name) => format!(
                    "Approve updating executable pin '{}' for kpexec entry '{}'",
                    prompt_safe(name),
                    prompt_safe(&args.id)
                ),
                None => format!(
                    "Approve updating executable pins for kpexec entry '{}'",
                    prompt_safe(&args.id)
                ),
            }),
            EntryCommand::List(_) | EntryCommand::Show(_) => None,
        },
        Command::Db(DbCommand::RotatePassword) => {
            Some("Approve rotating the kpexec vault password".to_string())
        }
        Command::Db(DbCommand::ShowPassword) => {
            Some("Approve displaying the kpexec vault recovery password".to_string())
        }
        Command::Run(_) | Command::Doctor | Command::Check(_) => None,
    }
}

/// Prevent user-controlled identifiers from injecting line breaks or an
/// unbounded amount of text into the system authentication prompt.
fn prompt_safe(value: &str) -> String {
    const MAX_CHARS: usize = 96;
    let mut safe: String = value
        .chars()
        .take(MAX_CHARS)
        .map(|ch| {
            if ch.is_alphanumeric() || matches!(ch, ' ' | '-' | '_' | '.' | '/' | ':' | '@') {
                ch
            } else {
                '?'
            }
        })
        .collect();
    if value.chars().count() > MAX_CHARS {
        safe.push('…');
    }
    safe
}

/// `kpexec doctor` — the M1 config + filesystem checks.
fn doctor_cmd() -> KpexecResult<Outcome> {
    let report = doctor::run()?;
    print!("{}", report.render());
    Ok(Outcome::Kpexec(report.status()))
}

fn entry(sub: EntryCommand) -> KpexecResult<Outcome> {
    // All entry subcommands are vault-backed. List/show are read paths; the
    // dispatcher has authorized every mutation before this function is called.
    match sub {
        EntryCommand::Add(args) => cmd_entry::add(args),
        EntryCommand::AddCommand(args) => cmd_entry::add_command(args),
        EntryCommand::RmCommand(args) => cmd_entry::rm_command(args),
        EntryCommand::SetSecret(args) => cmd_entry::set_secret(args),
        EntryCommand::Edit(args) => cmd_entry::edit(args),
        EntryCommand::Rm(args) => cmd_entry::rm(&args.id),
        EntryCommand::List(args) => cmd_entry::list(args),
        EntryCommand::Show(args) => cmd_entry::show(args),
        EntryCommand::Repin(args) => cmd_entry::repin(args),
    }
}

fn db(sub: DbCommand) -> KpexecResult<Outcome> {
    match sub {
        DbCommand::RotatePassword => crate::cmd_db::rotate_password(),
        DbCommand::ShowPassword => crate::cmd_db::show_password(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::*;
    use crate::error::KpexecError;
    use crate::status::KpexecStatus;

    struct Deny;

    impl UserPresence for Deny {
        fn authorize(&self, _reason: &str) -> KpexecResult<()> {
            Err(KpexecError::new(
                KpexecStatus::UserPresenceDenied,
                "test denial",
            ))
        }
    }

    #[test]
    fn every_write_capable_command_is_classified_as_gated() {
        let mutations = [
            Command::Init(InitArgs {
                db: None,
                use_existing: false,
                force: false,
                password_stdin: false,
            }),
            Command::Entry(EntryCommand::Add(EntryAddArgs {
                id: Some("entry".into()),
                no_pin: false,
                secret_stdin: false,
                description: None,
                title: None,
                inject: None,
                commands: vec![],
                force: false,
            })),
            Command::Entry(EntryCommand::AddCommand(EntryAddCommandArgs {
                id: "entry".into(),
                no_pin: false,
                commands: vec![],
            })),
            Command::Entry(EntryCommand::RmCommand(EntryRmCommandArgs {
                id: "entry".into(),
                name: "command".into(),
            })),
            Command::Entry(EntryCommand::SetSecret(EntrySetSecretArgs {
                id: "entry".into(),
                secret_stdin: false,
            })),
            Command::Entry(EntryCommand::Edit(EntryEditArgs {
                id: "entry".into(),
                description: None,
                title: None,
                inject: None,
            })),
            Command::Entry(EntryCommand::Rm(EntryIdArg { id: "entry".into() })),
            Command::Entry(EntryCommand::Repin(EntryRepinArgs {
                id: "entry".into(),
                command_name: None,
            })),
            Command::Db(DbCommand::RotatePassword),
            Command::Db(DbCommand::ShowPassword),
        ];

        for command in mutations {
            assert!(authorization_reason(&command).is_some());
            let err = dispatch_with_user_presence(command, &Deny).unwrap_err();
            assert_eq!(err.status(), KpexecStatus::UserPresenceDenied);
        }
    }

    #[test]
    fn read_run_and_check_commands_are_not_gated() {
        let ungated = [
            Command::Run(RunArgs {
                entry: "entry".into(),
                command: "command".into(),
                dry_run: true,
                timeout: None,
                json: false,
                trailing: vec![],
            }),
            Command::Doctor,
            Command::Check(CheckArgs { entry: None }),
            Command::Entry(EntryCommand::List(EntryListArgs { json: false })),
            Command::Entry(EntryCommand::Show(EntryShowArgs {
                id: "entry".into(),
                json: false,
            })),
        ];
        for command in ungated {
            assert!(authorization_reason(&command).is_none());
        }
    }

    #[test]
    fn prompt_text_is_bounded_single_line_and_secret_free() {
        let id = format!("{}\nspoof\u{202e}", "x".repeat(120));
        let command = Command::Entry(EntryCommand::SetSecret(EntrySetSecretArgs {
            id,
            secret_stdin: true,
        }));
        let reason = authorization_reason(&command).unwrap();
        assert!(!reason.contains('\n'));
        assert!(!reason.contains('\u{202e}'));
        assert!(reason.chars().count() < 160);
        assert!(!reason.contains("secret value"));
    }
}
