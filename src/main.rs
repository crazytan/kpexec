//! kpexec binary entry point.
//!
//! Kept deliberately thin: parse the CLI, initialize the audit log, dispatch,
//! then translate the [`Outcome`]/[`KpexecError`] into the process exit code.
//! There is exactly one place that touches `std::process::exit`.

use std::process::ExitCode;

use clap::Parser;

use kpexec::cli::Cli;
use kpexec::commands;
use kpexec::error::KpexecError;
use kpexec::logging;
use kpexec::status::Outcome;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Best-effort audit log init; failure disables logging, never aborts.
    let _ = logging::init();

    match commands::dispatch(cli.command) {
        Ok(outcome) => code(outcome),
        Err(err) => {
            report_error(&err);
            code(Outcome::Kpexec(err.status()))
        }
    }
}

/// Print a kpexec-level error to stderr in the standard `[kpexec] ...` form.
fn report_error(err: &KpexecError) {
    eprintln!("[kpexec] {}", err.message());
}

/// Convert an [`Outcome`] to an [`ExitCode`], clamping to the u8 range that the
/// process exit interface allows.
fn code(outcome: Outcome) -> ExitCode {
    let raw = outcome.exit_code();
    ExitCode::from(u8::try_from(raw).unwrap_or(u8::MAX))
}
