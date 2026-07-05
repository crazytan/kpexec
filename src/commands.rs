//! Command dispatch.
//!
//! Every subcommand is routed here. In M1 only `doctor` does real work; every
//! other command returns a clean [`KpexecStatus::NotImplemented`] error naming
//! the milestone that will implement it, via the structured error path — never
//! a `todo!()`/`panic!`.

use crate::cli::{Command, DbCommand, EntryCommand};
use crate::error::{KpexecError, Result};
use crate::status::Outcome;
use crate::{cmd_check, cmd_entry, cmd_init, cmd_run, doctor};

/// Dispatch a parsed command to its handler.
///
/// Returns the [`Outcome`] used to compute the process exit code. Human-facing
/// output is printed here; the `--json` envelope is emitted by the individual
/// handlers that support it (currently `run`).
pub fn dispatch(command: Command) -> Result<Outcome> {
    match command {
        Command::Run(args) => cmd_run::run(args),
        Command::Init(args) => cmd_init::run(args),
        Command::Doctor => doctor_cmd(),
        Command::Entry(sub) => entry(sub),
        Command::Check(args) => cmd_check::run(args),
        Command::Db(sub) => db(sub),
    }
}

/// `kpexec doctor` — the M1 config + filesystem checks.
fn doctor_cmd() -> Result<Outcome> {
    let report = doctor::run()?;
    print!("{}", report.render());
    Ok(Outcome::Kpexec(report.status()))
}

fn entry(sub: EntryCommand) -> Result<Outcome> {
    // All entry subcommands are vault-backed (M2). List/show are read paths;
    // the rest mutate the vault and print the pre-M3 mutation warning.
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
    use crate::status::KpexecStatus;

    #[test]
    fn db_stubs_still_not_implemented() {
        // db maintenance stays M3; other M1 stubs are now implemented in M2, so
        // only the db subcommands remain not-implemented here.
        for cmd in [
            Command::Db(DbCommand::ShowPassword),
            Command::Db(DbCommand::RotatePassword),
        ] {
            let err = dispatch(cmd).unwrap_err();
            assert_eq!(err.status(), KpexecStatus::NotImplemented);
            assert!(err.message().contains("milestone"));
        }
    }
}
