//! kpexec — broker secrets into policy-shaped child processes from a dedicated
//! KeePass vault.
//!
//! This crate is split into a library (the modules below) and a thin binary
//! (`main.rs`) so that integration tests can drive the CLI parsing and dispatch
//! without spawning a process.

pub mod cli;
pub mod commands;
pub mod config;
pub mod doctor;
pub mod error;
pub mod logging;
pub mod paths;
pub mod status;
