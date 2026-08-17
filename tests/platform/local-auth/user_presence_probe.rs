//! Supervised LocalAuthentication probe using kpexec's production Rust/Objective-C path.
//!
//! This binary is built and signed by `tests/platform/local-auth/run.sh`. Never
//! run it from automated tests: it intentionally presents system authentication
//! UI when attached to an interactive macOS session.

use std::process::ExitCode;

use kpexec::status::KpexecStatus;
use kpexec::user_presence::{SystemUserPresence, UserPresence};

fn main() -> ExitCode {
    match SystemUserPresence.authorize("kpexec: approve production user-presence validation") {
        Ok(()) => {
            println!("AUTHORIZED: LocalAuthentication approved user presence");
            ExitCode::SUCCESS
        }
        Err(error) if error.status() == KpexecStatus::UserPresenceDenied => {
            eprintln!("DENIED: {}", error.message());
            ExitCode::from(1)
        }
        Err(error) if error.status() == KpexecStatus::UserPresenceUnavailable => {
            eprintln!("UNAVAILABLE: {}", error.message());
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("INTERNAL: {}", error.message());
            ExitCode::from(3)
        }
    }
}
