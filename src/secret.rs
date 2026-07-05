//! Zeroizing secret wrapper.
//!
//! Every credential value — the vault master password and the brokered entry
//! secrets — is held in a [`Secret`] from the moment it is read or prompted.
//! The wrapper is built on the `secrecy`/`zeroize` crates so the underlying
//! bytes are scrubbed on drop and can never be `Debug`/`Display`-printed by
//! accident. This is security-design invariant 9 ("secrets held in zeroizing
//! wrapper types; never logged; never echoed").
//!
//! Secrets must NEVER be passed through the logging facade
//! ([`crate::logging`]) — there is no code path that does so, and the wrapper
//! has no `Display`/`Debug` that would reveal the value if one were attempted.

use secrecy::{ExposeSecret, SecretString};

/// A secret string held in zeroizing memory.
///
/// Wraps `secrecy::SecretString`. There is deliberately no `Display`, no
/// `Debug` that reveals contents, and no `Serialize` — the only way to reach
/// the bytes is [`Secret::expose`], which callers use at exactly the two
/// permitted boundaries (unlock the vault; inject into a child env in a later
/// milestone).
#[derive(Clone)]
pub struct Secret(SecretString);

impl Secret {
    /// Wrap a plaintext string. The input `String`'s buffer is moved into the
    /// zeroizing wrapper; keep the plaintext lifetime as short as possible at
    /// the call site.
    pub fn new(value: String) -> Self {
        Secret(SecretString::from(value))
    }

    /// Borrow the plaintext. Use only at a real boundary (KDF unlock, env
    /// injection). Do not clone the returned `&str` into a long-lived `String`,
    /// and never hand it to the logging facade.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// Length of the underlying secret in bytes. Used for the `< 8 chars`
    /// refusal without materializing the value anywhere loggable.
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// A hand-written Debug that never reveals the value: it is easy to accidentally
// `{:?}` a struct that contains a Secret, so make that safe by construction.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals() {
        let s = Secret::new("hunter2-EXAMPLE".to_string());
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "Secret(<redacted>)");
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn expose_roundtrips() {
        let s = Secret::new("value".to_string());
        assert_eq!(s.expose(), "value");
        assert_eq!(s.len(), 5);
        assert!(!s.is_empty());
    }
}
