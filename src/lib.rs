//! kpexec — broker secrets into policy-shaped child processes from a dedicated
//! KeePass vault.
//!
//! This crate is split into a library (the modules below) and a thin binary
//! (`main.rs`) so that integration tests can drive the CLI parsing and dispatch
//! without spawning a process.

pub mod cli;
pub mod cmd_check;
pub mod cmd_entry;
pub mod cmd_init;
pub mod cmd_run;
pub mod commands;
pub mod config;
pub mod doctor;
pub mod error;
pub mod keychain;
pub mod lock;
pub mod logging;
pub mod masterpw;
pub mod output;
pub mod paths;
pub mod pin;
pub mod policy;
pub mod prompt;
pub mod secret;
pub mod status;
pub mod vault;
pub mod vaultctx;
