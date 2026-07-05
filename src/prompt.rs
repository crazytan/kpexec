//! Interactive prompting + non-interactive flag overrides.
//!
//! Every wizard field can ALSO be supplied via an optional CLI flag
//! (`--description`, `--inject`, `--exe`, `--prefix`, …). This is a deliberate
//! extension over the doc's interactive-only wizard: it lets tests and scripts
//! drive `entry add`/`edit`/etc. non-interactively, and the wizard prompts only
//! for the fields a flag did not already supply. Hidden secret entry uses
//! `rpassword` so the secret never echoes and never lands in shell history.
//!
//! Secret input returns a [`Secret`] directly — the plaintext `String` from the
//! prompt is moved into the zeroizing wrapper at the earliest point.

use std::io::{self, IsTerminal, Write};

use crate::error::{KpexecError, Result};
use crate::secret::Secret;
use crate::status::KpexecStatus;

/// Read a hidden secret line.
///
/// * `--secret-stdin` (`from_stdin = true`) reads one line from stdin without a
///   TTY prompt (pipe-friendly for tests/scripts).
/// * otherwise a hidden `rpassword` prompt is shown.
///
/// The `< 8 chars` refusal is enforced here so every secret entry point shares
/// it (cli-design: "Secrets shorter than 8 characters are refused").
pub fn read_secret(prompt: &str, from_stdin: bool) -> Result<Secret> {
    let raw = if from_stdin {
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| KpexecError::internal(format!("reading secret from stdin: {e}")))?;
        // Trim exactly one trailing newline, not internal whitespace.
        let trimmed = line.strip_suffix('\n').unwrap_or(&line);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        trimmed.to_string()
    } else {
        rpassword::prompt_password(prompt)
            .map_err(|e| KpexecError::internal(format!("hidden prompt failed: {e}")))?
    };

    validate_secret(raw)
}

/// The minimum secret length (cli-design: shorter secrets redact unreliably).
pub const MIN_SECRET_LEN: usize = 8;

/// Wrap a raw plaintext secret, enforcing the `< 8 chars` refusal. Split out
/// from I/O so the floor is unit-testable without touching a real prompt/stdin.
pub fn validate_secret(raw: String) -> Result<Secret> {
    let secret = Secret::new(raw);
    if secret.len() < MIN_SECRET_LEN {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            "secret must be at least 8 characters (shorter secrets redact unreliably)",
        ));
    }
    Ok(secret)
}

/// Prompt for a plain (non-secret) line, returning the supplied `flag` value if
/// present so callers can run non-interactively.
///
/// When no flag value is given and stdin is not a TTY, this errors rather than
/// blocking — a script that forgot a flag should fail loudly, not hang.
pub fn read_line(prompt: &str, flag: Option<String>) -> Result<String> {
    if let Some(v) = flag {
        return Ok(v);
    }
    if !io::stdin().is_terminal() {
        return Err(KpexecError::new(
            KpexecStatus::ConfigError,
            format!(
                "missing required input ({prompt}) and stdin is not a terminal; pass the corresponding flag"
            ),
        ));
    }
    print!("{prompt}: ");
    io::stdout()
        .flush()
        .map_err(|e| KpexecError::internal(format!("stdout flush: {e}")))?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| KpexecError::internal(format!("read line: {e}")))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Parse an argument prefix with shell-word rules (quoting supported). Warns via
/// the returned [`PrefixWarning`] when the prefix is empty or a single word,
/// since short prefixes grant a broad surface (cli-design).
pub fn parse_prefix(input: &str) -> Result<(Vec<String>, Option<PrefixWarning>)> {
    let words = shell_words::split(input).map_err(|e| {
        KpexecError::new(
            KpexecStatus::MalformedPolicy,
            format!("could not parse argument prefix (unbalanced quotes?): {e}"),
        )
    })?;
    let warning = match words.len() {
        0 => Some(PrefixWarning::Empty),
        1 => Some(PrefixWarning::SingleWord),
        _ => None,
    };
    Ok((words, warning))
}

/// A non-fatal warning about a short/broad argument prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixWarning {
    /// No prefix words at all — every argument is attacker-controlled.
    Empty,
    /// A single word — a broad surface (e.g. just the subcommand).
    SingleWord,
}

impl PrefixWarning {
    /// The human message to print to stderr.
    pub fn message(self) -> &'static str {
        match self {
            PrefixWarning::Empty => {
                "[kpexec] WARNING: empty argument prefix — the agent controls the entire argv"
            }
            PrefixWarning::SingleWord => {
                "[kpexec] WARNING: single-word prefix — grants a broad surface; consider a longer prefix"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_shorter_than_8_is_refused() {
        let err = validate_secret("short".to_string()).unwrap_err();
        assert_eq!(err.status(), KpexecStatus::MalformedPolicy);
        // Exactly 8 is accepted.
        assert!(validate_secret("eightchr".to_string()).is_ok());
    }

    #[test]
    fn read_line_uses_flag_without_prompt() {
        let v = read_line("Description", Some("from-flag".into())).unwrap();
        assert_eq!(v, "from-flag");
    }

    #[test]
    fn prefix_shell_words_quoting() {
        let (words, warn) = parse_prefix(r#"pr create --title "Fix build""#).unwrap();
        assert_eq!(words, vec!["pr", "create", "--title", "Fix build"]);
        assert!(warn.is_none());
    }

    #[test]
    fn prefix_empty_warns() {
        let (words, warn) = parse_prefix("").unwrap();
        assert!(words.is_empty());
        assert_eq!(warn, Some(PrefixWarning::Empty));
    }

    #[test]
    fn prefix_single_word_warns() {
        let (words, warn) = parse_prefix("deploy").unwrap();
        assert_eq!(words, vec!["deploy"]);
        assert_eq!(warn, Some(PrefixWarning::SingleWord));
    }

    #[test]
    fn prefix_unbalanced_quotes_error() {
        let err = parse_prefix(r#"pr "unterminated"#).unwrap_err();
        assert_eq!(err.status(), KpexecStatus::MalformedPolicy);
    }
}
