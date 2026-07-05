//! Command dispatch.
//!
//! Every subcommand is routed here. In M1 only `doctor` does real work; every
//! other command returns a clean [`KpexecStatus::NotImplemented`] error naming
//! the milestone that will implement it, via the structured error path — never
//! a `todo!()`/`panic!`.

use crate::cli::{Command, DbCommand, EntryCommand, RunArgs};
use crate::error::{KpexecError, Result};
use crate::status::{JsonEnvelope, KpexecStatus, Outcome};
use crate::{config, doctor};

/// Dispatch a parsed command to its handler.
///
/// Returns the [`Outcome`] used to compute the process exit code. Human-facing
/// output is printed here; the `--json` envelope is emitted by the individual
/// handlers that support it (currently `run`).
pub fn dispatch(command: Command) -> Result<Outcome> {
    match command {
        Command::Run(args) => run(args),
        Command::Init(_) => Err(KpexecError::not_implemented("init", 2)),
        Command::Doctor => doctor_cmd(),
        Command::Entry(sub) => entry(sub),
        Command::Check(_) => Err(KpexecError::not_implemented("check", 2)),
        Command::Db(sub) => db(sub),
    }
}

/// `kpexec doctor` — the M1 config + filesystem checks.
fn doctor_cmd() -> Result<Outcome> {
    let report = doctor::run()?;
    print!("{}", report.render());
    Ok(Outcome::Kpexec(report.status()))
}

/// `kpexec run` — the run path is M4. In M1 it fails closed, honoring `--json`
/// so the not-implemented status is machine-readable even now.
fn run(args: RunArgs) -> Result<Outcome> {
    // Config is loaded so an invalid config is reported as config-error even on
    // the stubbed run path (exercises the untrusted-hint semantics end to end).
    let _cfg = config::load()?;

    let status = KpexecStatus::NotImplemented;
    if args.json {
        let diag = "[kpexec] run is not implemented yet (milestone 4)".to_string();
        println!(
            "{}",
            JsonEnvelope::kpexec_with_stderr(status, diag).to_json()
        );
        Ok(Outcome::Kpexec(status))
    } else {
        Err(KpexecError::not_implemented("run", 4))
    }
}

fn entry(sub: EntryCommand) -> Result<Outcome> {
    // All entry subcommands are vault-backed (M2). List/show are read paths but
    // still need the vault, so they are M2 as well.
    let feature = match sub {
        EntryCommand::Add(_) => "entry add",
        EntryCommand::AddCommand(_) => "entry add-command",
        EntryCommand::RmCommand(_) => "entry rm-command",
        EntryCommand::SetSecret(_) => "entry set-secret",
        EntryCommand::Edit(_) => "entry edit",
        EntryCommand::Rm(_) => "entry rm",
        EntryCommand::List(_) => "entry list",
        EntryCommand::Show(_) => "entry show",
        EntryCommand::Repin(_) => "entry repin",
    };
    Err(KpexecError::not_implemented(feature, 2))
}

fn db(sub: DbCommand) -> Result<Outcome> {
    let feature = match sub {
        DbCommand::RotatePassword => "db rotate-password",
        DbCommand::ShowPassword => "db show-password",
    };
    // db maintenance is part of the hardening milestone.
    Err(KpexecError::not_implemented(feature, 3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::*;

    #[test]
    fn stubs_return_not_implemented() {
        let cases: Vec<Command> = vec![
            Command::Init(InitArgs {
                db: None,
                use_existing: false,
            }),
            Command::Check(CheckArgs { entry: None }),
            Command::Entry(EntryCommand::List(EntryListArgs { json: false })),
            Command::Entry(EntryCommand::Add(EntryAddArgs {
                id: None,
                no_pin: false,
                secret_stdin: false,
            })),
            Command::Db(DbCommand::ShowPassword),
        ];
        for cmd in cases {
            let err = dispatch(cmd).unwrap_err();
            assert_eq!(err.status(), KpexecStatus::NotImplemented);
            assert!(err.message().contains("milestone"));
        }
    }
}
