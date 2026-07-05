//! The output-processing pipeline (the M5 seam).
//!
//! A child's stdout/stderr are captured **fully buffered** (no streaming in V1;
//! see security-design invariant 10 and the CLI design doc) and then handed to
//! [`process`], which turns raw [`Captured`] bytes into [`Processed`] strings
//! ready for emission.
//!
//! # What this module does *today* (M4)
//!
//! Only the policy **byte limits** are applied: stdout is truncated at
//! `max_stdout_bytes`, stderr at `max_stderr_bytes`, each with a clear
//! truncation marker so a reader can tell output was cut. Bytes are decoded
//! lossily to UTF-8 (children may emit arbitrary bytes; we never surface raw
//! non-UTF-8 to a JSON envelope).
//!
//! # What this module does NOT do yet — the TODO(M5) seam
//!
//! Redaction (invariant 10: mask the exact secret plus its JSON-escaped,
//! shell-escaped, and URL-encoded forms, then fail closed if secret material
//! survives) is **not implemented**. The single insertion point is marked
//! `TODO(M5)` inside [`process`]. Because redaction is not active, callers of a
//! non-dry-run execution MUST print the pre-M5 warning
//! ([`PRE_M5_REDACTION_WARNING`]) to stderr — the run path does this
//! unconditionally.

use crate::policy::OutputSpec;

/// The stderr line every non-dry-run execution prints until M5 wires redaction.
///
/// Kept here next to the seam it describes so the two stay in sync.
pub const PRE_M5_REDACTION_WARNING: &str =
    "[kpexec] WARNING: pre-M5 build - output redaction is not yet active";

/// The marker appended to a stream that was truncated at its byte cap. Chosen to
/// be visually obvious and unlikely to be mistaken for child output.
pub const TRUNCATION_MARKER: &str = "\n[kpexec] ...output truncated (byte limit reached)...\n";

/// Raw child output as captured from the pipes, before any processing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    /// Raw stdout bytes, read to EOF.
    pub stdout: Vec<u8>,
    /// Raw stderr bytes, read to EOF.
    pub stderr: Vec<u8>,
}

/// Processed output ready for emission (byte-limited today; redacted in M5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Processed {
    /// Processed stdout as a lossy-UTF-8 string.
    pub stdout: String,
    /// Processed stderr as a lossy-UTF-8 string.
    pub stderr: String,
    /// Whether stdout was truncated at its byte cap.
    pub stdout_truncated: bool,
    /// Whether stderr was truncated at its byte cap.
    pub stderr_truncated: bool,
}

/// Turn captured bytes into emittable strings, applying the policy byte limits.
///
/// M4 behavior: truncate at the caps, decode lossily. The redaction step slots
/// in at the `TODO(M5)` marker below, operating on the (already length-bounded)
/// bytes before they are decoded — redaction must run on bytes so it can catch
/// encoded forms of the secret, and it may switch the outcome to fail-closed
/// suppression, which is why it belongs *inside* this single function rather
/// than at the call site.
pub fn process(captured: Captured, limits: &OutputSpec) -> Processed {
    // ---- byte limiting -----------------------------------------------------
    let (stdout_bytes, stdout_truncated) = truncate(&captured.stdout, limits.max_stdout_bytes);
    let (stderr_bytes, stderr_truncated) = truncate(&captured.stderr, limits.max_stderr_bytes);

    // TODO(M5): redaction seam.
    //
    // Insert here, operating on `stdout_bytes` / `stderr_bytes` (post-limit,
    // pre-decode): replace every occurrence of the secret and its JSON-escaped,
    // shell-escaped, and URL-encoded forms; if secret material is still detected
    // after replacement, return fully suppressed output so the caller can fail
    // closed with `KpexecStatus::RedactionFailure`. Until then, no redaction is
    // applied and the run path prints `PRE_M5_REDACTION_WARNING`.

    // ---- lossy decode ------------------------------------------------------
    let mut stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    if stdout_truncated {
        stdout.push_str(TRUNCATION_MARKER);
    }
    let mut stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    if stderr_truncated {
        stderr.push_str(TRUNCATION_MARKER);
    }

    Processed {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    }
}

/// Truncate `bytes` to at most `max` bytes. Returns the (possibly borrowed-then-
/// owned) slice and whether truncation occurred. A `max` of 0 means "no output"
/// but still records truncation if there were any bytes.
fn truncate(bytes: &[u8], max: u64) -> (Vec<u8>, bool) {
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    if bytes.len() > max {
        (bytes[..max].to_vec(), true)
    } else {
        (bytes.to_vec(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(out: u64, err: u64) -> OutputSpec {
        OutputSpec {
            max_stdout_bytes: out,
            max_stderr_bytes: err,
        }
    }

    #[test]
    fn passes_through_under_limit() {
        let cap = Captured {
            stdout: b"hello".to_vec(),
            stderr: b"warn".to_vec(),
        };
        let p = process(cap, &limits(100, 100));
        assert_eq!(p.stdout, "hello");
        assert_eq!(p.stderr, "warn");
        assert!(!p.stdout_truncated);
        assert!(!p.stderr_truncated);
    }

    #[test]
    fn truncates_stdout_with_marker() {
        let cap = Captured {
            stdout: vec![b'x'; 50],
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(10, 100));
        assert!(p.stdout_truncated);
        assert!(p.stdout.starts_with("xxxxxxxxxx"));
        assert!(p.stdout.contains("truncated"));
        // Exactly 10 payload bytes retained before the marker. Count the payload
        // prefix only — the marker text itself contains an 'x' ("[kpexec]").
        let payload = p.stdout.strip_suffix(TRUNCATION_MARKER).unwrap();
        assert_eq!(payload.len(), 10);
        assert_eq!(payload.matches('x').count(), 10);
    }

    #[test]
    fn truncates_stderr_independently() {
        let cap = Captured {
            stdout: vec![b'a'; 5],
            stderr: vec![b'b'; 200],
        };
        let p = process(cap, &limits(100, 20));
        assert!(!p.stdout_truncated);
        assert!(p.stderr_truncated);
        // Count the payload prefix only — the marker ("byte limit reached")
        // itself contains a 'b'.
        let payload = p.stderr.strip_suffix(TRUNCATION_MARKER).unwrap();
        assert_eq!(payload.len(), 20);
        assert_eq!(payload.matches('b').count(), 20);
    }

    #[test]
    fn lossy_decode_never_panics_on_binary() {
        let cap = Captured {
            stdout: vec![0xff, 0xfe, 0x00, b'a'],
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(100, 100));
        // Replacement char present; the trailing 'a' survives.
        assert!(p.stdout.contains('a'));
    }

    #[test]
    fn zero_limit_suppresses_but_marks() {
        let cap = Captured {
            stdout: b"anything".to_vec(),
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(0, 0));
        assert!(p.stdout_truncated);
        // No payload bytes, only the marker.
        assert!(p.stdout.starts_with("\n[kpexec]"));
    }
}
