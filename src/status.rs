//! Result status codes and the `--json` envelope.
//!
//! This module is the single source of truth for how kpexec-level outcomes map
//! to process exit codes. Later milestones (M4 run path, M5 output handling)
//! build their result reporting on the types defined here, so the mapping is
//! kept deliberately small and stable.
//!
//! # Exit-code contract
//!
//! * On a real child execution kpexec propagates the **child's** exit code
//!   verbatim (see [`Outcome::ChildExit`]). Children can legitimately exit in
//!   the 100–125 range, so the numeric code alone is ambiguous — agents that
//!   need to distinguish a kpexec failure from a child failure must read the
//!   `kpexec_status` field of the `--json` envelope, which is unambiguous.
//! * kpexec-level failures use a reserved band starting at 100. The mapping is
//!   defined once in [`KpexecStatus::exit_code`]; do not hard-code these numbers
//!   anywhere else.

use serde::Serialize;

/// The canonical outcome of a kpexec invocation.
///
/// Every kpexec-level condition has exactly one variant here. The string form
/// (via [`KpexecStatus::as_str`]) is the stable wire value that appears in the
/// `--json` envelope and in logs; the numeric form (via
/// [`KpexecStatus::exit_code`]) is the stable process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KpexecStatus {
    /// Everything succeeded and there was no child process to defer to.
    Success,
    /// The requested `--entry <id>` does not exist in the vault.
    UnknownEntry,
    /// The entry exists but has no `--command <name>` template.
    UnknownCommand,
    /// A policy JSON document failed to parse or violated the schema.
    MalformedPolicy,
    /// The pinned executable's on-disk bytes no longer match `exe_sha256`.
    ExeHashMismatch,
    /// The vault could not be unlocked (bad/missing Keychain password, etc.).
    UnlockFailed,
    /// Output redaction could not guarantee the secret was removed; output was
    /// suppressed and the run failed closed.
    RedactionFailure,
    /// The child exceeded `--timeout` and was terminated.
    Timeout,
    /// `config.toml` was present but could not be parsed, or is internally
    /// inconsistent. Config is an untrusted hint, so this never carries secrets.
    ConfigError,
    /// A feature that is not part of the current milestone was invoked.
    NotImplemented,
    /// An unexpected internal error (a bug); the catch-all.
    Internal,
}

impl KpexecStatus {
    /// The stable kebab-case wire string (matches the `--json` `kpexec_status`
    /// field and the value used in logs).
    pub fn as_str(self) -> &'static str {
        match self {
            KpexecStatus::Success => "success",
            KpexecStatus::UnknownEntry => "unknown-entry",
            KpexecStatus::UnknownCommand => "unknown-command",
            KpexecStatus::MalformedPolicy => "malformed-policy",
            KpexecStatus::ExeHashMismatch => "exe-hash-mismatch",
            KpexecStatus::UnlockFailed => "unlock-failed",
            KpexecStatus::RedactionFailure => "redaction-failure",
            KpexecStatus::Timeout => "timeout",
            KpexecStatus::ConfigError => "config-error",
            KpexecStatus::NotImplemented => "not-implemented",
            KpexecStatus::Internal => "internal",
        }
    }

    /// The process exit code for this status when kpexec is the failing party.
    ///
    /// The 100+ band is documented in [`the module docs`](self). `Success` maps
    /// to `0`. Child exit codes are propagated separately via
    /// [`Outcome::ChildExit`] and never routed through this function.
    pub fn exit_code(self) -> i32 {
        match self {
            KpexecStatus::Success => 0,
            KpexecStatus::UnknownEntry => 100,
            KpexecStatus::UnknownCommand => 101,
            KpexecStatus::MalformedPolicy => 102,
            KpexecStatus::ExeHashMismatch => 103,
            KpexecStatus::UnlockFailed => 104,
            KpexecStatus::RedactionFailure => 105,
            KpexecStatus::Timeout => 106,
            KpexecStatus::ConfigError => 107,
            KpexecStatus::NotImplemented => 108,
            KpexecStatus::Internal => 109,
        }
    }
}

/// The final thing a command produces: either a kpexec-level status, or a
/// child process whose exit code we propagate verbatim.
///
/// `main` converts this into the actual process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A kpexec-level status. Exit code comes from [`KpexecStatus::exit_code`].
    Kpexec(KpexecStatus),
    /// A child process exited with this code; propagate it verbatim.
    ChildExit(i32),
}

impl Outcome {
    /// The process exit code this outcome should produce.
    pub fn exit_code(self) -> i32 {
        match self {
            Outcome::Kpexec(status) => status.exit_code(),
            Outcome::ChildExit(code) => code,
        }
    }
}

impl From<KpexecStatus> for Outcome {
    fn from(status: KpexecStatus) -> Self {
        Outcome::Kpexec(status)
    }
}

/// The `--json` result envelope emitted by `run` (and any command that supports
/// `--json`).
///
/// Shape is fixed by the CLI design doc:
/// `{"kpexec_status": "...", "child_exit_code": N|null, "stdout": "...", "stderr": "..."}`.
/// `child_exit_code` is `null` whenever no child process ran (kpexec-level
/// outcome). `stdout`/`stderr` are the already-redacted child streams; for
/// kpexec-level outcomes they are empty strings, never `null`, so consumers can
/// treat them as always-present strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsonEnvelope {
    pub kpexec_status: KpexecStatus,
    pub child_exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl JsonEnvelope {
    /// Envelope for a kpexec-level outcome with no child process.
    pub fn kpexec(status: KpexecStatus) -> Self {
        Self::kpexec_with_stderr(status, String::new())
    }

    /// A kpexec-level (no child) envelope carrying a diagnostic in `stderr`,
    /// so `--json` consumers see the reason, not just the status.
    pub fn kpexec_with_stderr(status: KpexecStatus, stderr: String) -> Self {
        JsonEnvelope {
            kpexec_status: status,
            child_exit_code: None,
            stdout: String::new(),
            stderr,
        }
    }

    /// Serialize to a compact JSON string. Serialization of this fixed,
    /// string/number-only shape cannot fail; the fallback keeps the signature
    /// infallible for call sites.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            // Unreachable in practice: all fields are plain strings/ints.
            r#"{"kpexec_status":"internal","child_exit_code":null,"stdout":"","stderr":""}"#
                .to_string()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_are_kebab_case() {
        assert_eq!(KpexecStatus::UnknownEntry.as_str(), "unknown-entry");
        assert_eq!(KpexecStatus::ExeHashMismatch.as_str(), "exe-hash-mismatch");
        assert_eq!(KpexecStatus::ConfigError.as_str(), "config-error");
        assert_eq!(KpexecStatus::NotImplemented.as_str(), "not-implemented");
    }

    #[test]
    fn success_exits_zero() {
        assert_eq!(KpexecStatus::Success.exit_code(), 0);
    }

    #[test]
    fn failures_use_the_reserved_band() {
        // Every non-success status must land at or above 100 and be distinct.
        let statuses = [
            KpexecStatus::UnknownEntry,
            KpexecStatus::UnknownCommand,
            KpexecStatus::MalformedPolicy,
            KpexecStatus::ExeHashMismatch,
            KpexecStatus::UnlockFailed,
            KpexecStatus::RedactionFailure,
            KpexecStatus::Timeout,
            KpexecStatus::ConfigError,
            KpexecStatus::NotImplemented,
            KpexecStatus::Internal,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in statuses {
            let code = s.exit_code();
            assert!(code >= 100, "{} should be in the 100+ band", s.as_str());
            assert!(seen.insert(code), "duplicate exit code {code}");
        }
    }

    #[test]
    fn child_exit_is_propagated_verbatim() {
        assert_eq!(Outcome::ChildExit(42).exit_code(), 42);
        assert_eq!(Outcome::ChildExit(0).exit_code(), 0);
        // A child may legitimately exit inside the reserved band.
        assert_eq!(Outcome::ChildExit(101).exit_code(), 101);
    }

    #[test]
    fn json_envelope_shape() {
        let env = JsonEnvelope {
            kpexec_status: KpexecStatus::UnknownCommand,
            child_exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
        let v: serde_json::Value = serde_json::from_str(&env.to_json()).unwrap();
        assert_eq!(v["kpexec_status"], "unknown-command");
        assert!(v["child_exit_code"].is_null());
        assert_eq!(v["stdout"], "");
        assert_eq!(v["stderr"], "");
        // Exactly these four keys, nothing more.
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn json_envelope_with_child() {
        let env = JsonEnvelope {
            kpexec_status: KpexecStatus::Success,
            child_exit_code: Some(0),
            stdout: "ok".into(),
            stderr: String::new(),
        };
        let v: serde_json::Value = serde_json::from_str(&env.to_json()).unwrap();
        assert_eq!(v["kpexec_status"], "success");
        assert_eq!(v["child_exit_code"], 0);
        assert_eq!(v["stdout"], "ok");
    }
}
