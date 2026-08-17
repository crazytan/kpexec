//! The structured error type.
//!
//! Every fallible operation in kpexec returns [`KpexecError`], which pairs a
//! human-readable message with a [`KpexecStatus`]. `main` turns the status into
//! the process exit code and (when `--json` is requested) into the envelope, so
//! there is exactly one error channel and one place that decides exit codes.

use crate::status::KpexecStatus;

/// A kpexec error: a status plus a message.
///
/// Construct via [`KpexecError::new`] or a status-specific helper such as
/// [`KpexecError::config`] so the status is always paired with an
/// appropriate message. The `Display` impl is the message alone; the status is
/// carried separately and drives the exit code.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct KpexecError {
    status: KpexecStatus,
    message: String,
}

impl KpexecError {
    /// Create an error with an explicit status and message.
    pub fn new(status: KpexecStatus, message: impl Into<String>) -> Self {
        KpexecError {
            status,
            message: message.into(),
        }
    }

    /// The status carried by this error (drives the exit code and JSON status).
    pub fn status(&self) -> KpexecStatus {
        self.status
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// A config-error: the untrusted config hint was unparseable or inconsistent.
    pub fn config(message: impl Into<String>) -> Self {
        KpexecError::new(KpexecStatus::ConfigError, message)
    }

    /// An unexpected internal error (a bug).
    pub fn internal(message: impl Into<String>) -> Self {
        KpexecError::new(KpexecStatus::Internal, message)
    }
}

/// Convenience alias for kpexec's fallible operations.
pub type Result<T> = std::result::Result<T, KpexecError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_status() {
        let e = KpexecError::config("bad toml");
        assert_eq!(e.status(), KpexecStatus::ConfigError);
    }
}
