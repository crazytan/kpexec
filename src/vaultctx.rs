//! Resolving the vault path + Keychain store for the command handlers.
//!
//! Read and write handlers all need the same two things: the vault path (from
//! config, an untrusted hint) and a [`KeychainStore`]. This module centralizes
//! that resolution and the pre-M3 mutation warning, so every handler stays
//! small and consistent.

use std::path::PathBuf;

use crate::config::{self, Config};
use crate::error::{KpexecError, Result};
use crate::keychain::KeychainStore;
use crate::status::KpexecStatus;

/// The warning every mutating command prints until M3 wires the Touch ID gate.
pub const MUTATION_WARNING: &str =
    "[kpexec] WARNING: pre-M3 build - mutations are not yet Touch ID-gated";

/// Print the pre-M3 mutation warning to stderr.
pub fn warn_no_user_presence() {
    eprintln!("{MUTATION_WARNING}");
}

/// The default vault location when config does not name one.
pub fn default_vault_path() -> Result<PathBuf> {
    Ok(crate::paths::home()?
        .join("Secrets")
        .join("kpexec-agent.kdbx"))
}

/// Resolve the vault path from config (the untrusted hint). Errors when neither
/// config nor a default can be determined and no explicit path is given.
pub fn resolve_vault_path(cfg: &Config) -> Result<PathBuf> {
    match &cfg.db_path {
        Some(p) => Ok(p.clone()),
        None => Err(KpexecError::new(
            KpexecStatus::ConfigError,
            "no vault configured — run `kpexec init` (config.toml has no db_path)",
        )),
    }
}

/// The real Keychain store for production use.
///
/// On macOS this is the login-Keychain-backed store; on other platforms the
/// build has no real store and this errors (M2 targets macOS; the file-backed
/// fake is test-only).
#[cfg(target_os = "macos")]
pub fn production_keychain() -> Result<Box<dyn KeychainStore>> {
    Ok(Box::new(crate::keychain::macos::MacKeychain))
}

/// Non-macOS stub: there is no production Keychain.
#[cfg(not(target_os = "macos"))]
pub fn production_keychain() -> Result<Box<dyn KeychainStore>> {
    Err(KpexecError::new(
        KpexecStatus::Internal,
        "kpexec's Keychain backend is only available on macOS",
    ))
}

/// Load config as the untrusted hint used by handlers.
pub fn load_config() -> Result<Config> {
    config::load()
}
