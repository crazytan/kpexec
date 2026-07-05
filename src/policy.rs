//! The policy JSON document (`kpexec.policy.v1`).
//!
//! One policy is stored per entry in the `kpexec.policy.v1` custom string
//! field, exactly per `docs/cli-design.md`. The `id` is NOT part of the JSON —
//! identity lives solely in the separate `kpexec.id` field (the single source
//! of truth). This module is the parse/serialize boundary and enforces the
//! deny-by-default posture:
//!
//! * `#[serde(deny_unknown_fields)]` on every struct — an unknown field
//!   rejects the whole document (security-design invariant 11).
//! * the `schema` string must equal [`POLICY_SCHEMA`]; a future revision ships
//!   as `kpexec.policy.v2` rather than mutating v1.
//!
//! Parsing never touches the secret: the policy carries only the *shape* of
//! injection (`field`, `inject`), never the credential value.

use serde::{Deserialize, Serialize};

/// The one schema string this milestone understands.
pub const POLICY_SCHEMA: &str = "kpexec.policy.v1";

/// The `kpexec.id` custom-field key (identity, single source of truth).
pub const FIELD_ID: &str = "kpexec.id";
/// The `kpexec.policy.v1` custom-field key (the policy JSON).
pub const FIELD_POLICY: &str = "kpexec.policy.v1";

/// Documented default stdout byte cap.
pub const DEFAULT_MAX_STDOUT_BYTES: u64 = 200_000;
/// Documented default stderr byte cap.
pub const DEFAULT_MAX_STDERR_BYTES: u64 = 50_000;

/// The parsed policy document (`kpexec.policy.v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Must equal [`POLICY_SCHEMA`]; validated by [`Policy::validate_schema`].
    pub schema: String,
    /// Human-readable description shown in listings and logs.
    pub description: String,
    /// How the secret is injected into the child.
    pub secret: SecretSpec,
    /// Optional non-secret environment variables for the child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvSpec>,
    /// The allowed command templates.
    pub commands: Vec<Command>,
    /// Output byte limits.
    pub output: OutputSpec,
}

/// The `secret` block: which field holds the value and how it is injected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSpec {
    /// Always `"password"` in v1 — the value lives in the KeePass `Password`
    /// field. A string (not an enum) so a future field kind is a v2 concern.
    pub field: String,
    /// The injection target.
    pub inject: InjectSpec,
}

/// The `inject` block: env-only in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectSpec {
    /// Injection kind. `"env"` is the only value in v1 (invariant 6).
    #[serde(rename = "type")]
    pub kind: String,
    /// The environment variable name that receives the secret.
    pub name: String,
}

/// The optional `env.set` block of non-secret variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSpec {
    /// Non-secret variables added to the child's baseline environment.
    pub set: std::collections::BTreeMap<String, String>,
}

/// One allowed command template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    /// Agent-facing name; unique within the entry.
    pub name: String,
    /// Absolute executable path (validated at authoring time).
    pub exe: String,
    /// SHA-256 of the canonical executable bytes. `None` only when authored
    /// with `--no-pin` (flagged by `check`/`doctor`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_sha256: Option<String>,
    /// Fixed leading arguments.
    pub argv_prefix: Vec<String>,
}

/// Output byte caps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    /// Max captured stdout bytes.
    pub max_stdout_bytes: u64,
    /// Max captured stderr bytes.
    pub max_stderr_bytes: u64,
}

impl Default for OutputSpec {
    fn default() -> Self {
        OutputSpec {
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
        }
    }
}

impl Policy {
    /// Build a fresh, empty-command policy with the documented defaults.
    pub fn new(description: String, inject_name: String, env: Option<EnvSpec>) -> Self {
        Policy {
            schema: POLICY_SCHEMA.to_string(),
            description,
            secret: SecretSpec {
                field: "password".to_string(),
                inject: InjectSpec {
                    kind: "env".to_string(),
                    name: inject_name,
                },
            },
            env,
            commands: Vec::new(),
            output: OutputSpec::default(),
        }
    }

    /// Parse a policy JSON string. Unknown fields, malformed JSON, and an
    /// unknown schema string all reject (deny by default).
    pub fn parse(json: &str) -> Result<Policy, PolicyError> {
        let policy: Policy = serde_json::from_str(json).map_err(|e| PolicyError(e.to_string()))?;
        policy.validate_schema()?;
        Ok(policy)
    }

    /// Serialize to a compact JSON string for storage in the KeePass field.
    pub fn to_json(&self) -> Result<String, PolicyError> {
        serde_json::to_string(self).map_err(|e| PolicyError(e.to_string()))
    }

    /// Verify the `schema` field matches [`POLICY_SCHEMA`].
    pub fn validate_schema(&self) -> Result<(), PolicyError> {
        if self.schema != POLICY_SCHEMA {
            return Err(PolicyError(format!(
                "unknown policy schema {:?} (expected {POLICY_SCHEMA})",
                self.schema
            )));
        }
        Ok(())
    }

    /// Find a command template by name.
    pub fn command(&self, name: &str) -> Option<&Command> {
        self.commands.iter().find(|c| c.name == name)
    }

    /// Names that appear more than once in this entry's command list.
    pub fn duplicate_command_names(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeMap::new();
        for c in &self.commands {
            *seen.entry(c.name.clone()).or_insert(0usize) += 1;
        }
        seen.into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(name, _)| name)
            .collect()
    }
}

/// A policy parse/serialize error. Carries a message only — no secret material
/// ever passes through the policy layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "schema":"kpexec.policy.v1",
        "description":"GitHub token",
        "secret":{"field":"password","inject":{"type":"env","name":"GH_TOKEN"}},
        "env":{"set":{"PATH":"/opt/homebrew/bin:/usr/bin:/bin"}},
        "commands":[{"name":"pr-list","exe":"/opt/homebrew/bin/gh","exe_sha256":"aa","argv_prefix":["pr","list"]}],
        "output":{"max_stdout_bytes":200000,"max_stderr_bytes":50000}
    }"#;

    #[test]
    fn parses_valid_policy() {
        let p = Policy::parse(SAMPLE).unwrap();
        assert_eq!(p.description, "GitHub token");
        assert_eq!(p.secret.inject.name, "GH_TOKEN");
        assert_eq!(p.commands.len(), 1);
        assert_eq!(p.commands[0].exe_sha256.as_deref(), Some("aa"));
    }

    #[test]
    fn unknown_field_rejected() {
        let json = SAMPLE.replace(r#""description""#, r#""surprise":1,"description""#);
        let err = Policy::parse(&json).unwrap_err();
        assert!(err.0.contains("surprise") || err.0.contains("unknown"));
    }

    #[test]
    fn unknown_schema_rejected() {
        let json = SAMPLE.replace("kpexec.policy.v1", "kpexec.policy.v2");
        let err = Policy::parse(&json).unwrap_err();
        assert!(err.0.contains("schema"));
    }

    #[test]
    fn no_pin_roundtrips_without_hash_key() {
        let mut p = Policy::new("d".into(), "TOK".into(), None);
        p.commands.push(Command {
            name: "c".into(),
            exe: "/bin/echo".into(),
            exe_sha256: None,
            argv_prefix: vec![],
        });
        let json = p.to_json().unwrap();
        // The absent pin must not serialize as null; check/round-trip relies on
        // the key being absent to mean "unpinned".
        assert!(!json.contains("exe_sha256"));
        let back = Policy::parse(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn duplicate_command_names_detected() {
        let mut p = Policy::new("d".into(), "TOK".into(), None);
        for _ in 0..2 {
            p.commands.push(Command {
                name: "dup".into(),
                exe: "/bin/echo".into(),
                exe_sha256: None,
                argv_prefix: vec![],
            });
        }
        assert_eq!(p.duplicate_command_names(), vec!["dup".to_string()]);
    }
}
