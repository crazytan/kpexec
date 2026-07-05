//! Well-known filesystem locations.
//!
//! Centralizes the paths the CLI design doc fixes, so nothing else has to
//! reconstruct them:
//!
//! * config: `~/.config/kpexec/config.toml`
//! * logs:   `~/Library/Logs/kpexec/kpexec.log`

use std::path::PathBuf;

use crate::error::{KpexecError, Result};

/// `~/.config/kpexec` — the config directory.
pub fn config_dir() -> Result<PathBuf> {
    // The doc pins `~/.config/kpexec` explicitly (not the platform config dir),
    // so derive it from HOME rather than `dirs::config_dir()`.
    Ok(home()?.join(".config").join("kpexec"))
}

/// `~/.config/kpexec/config.toml` — the config file.
pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// `~/Library/Logs/kpexec` — the log directory.
pub fn log_dir() -> Result<PathBuf> {
    Ok(home()?.join("Library").join("Logs").join("kpexec"))
}

/// `~/Library/Logs/kpexec/kpexec.log` — the active log file.
pub fn log_file() -> Result<PathBuf> {
    Ok(log_dir()?.join("kpexec.log"))
}

/// The user's home directory.
pub fn home() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| KpexecError::internal("could not determine home directory"))
}
