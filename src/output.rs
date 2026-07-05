//! The output-processing pipeline (M5: redaction + fail-closed suppression).
//!
//! A child's stdout/stderr are captured **fully buffered** (no streaming in V1;
//! see security-design invariant 10 and the CLI design doc) and then handed to
//! [`process`], which turns raw [`Captured`] bytes into [`Processed`] strings
//! ready for emission.
//!
//! # Pipeline (in order)
//!
//! 1. **Redaction** (invariant 10) — on the *raw* bytes, before any decode or
//!    truncation, every occurrence of the secret and of its computed variant
//!    encodings (JSON-escaped, URL percent-encoded, shell-escaped) is replaced
//!    with the fixed marker [`REDACTION_MARKER`]. Redaction is *unconditional*:
//!    there is no policy knob and no flag to disable it.
//! 2. **Fail-closed re-scan** (invariant 10) — after replacement (iterated to a
//!    fixpoint within a small bound) the processed bytes are re-scanned for all
//!    variant forms. If any survive, BOTH streams are suppressed entirely and
//!    replaced with a single diagnostic line, and [`Processed::redaction_failed`]
//!    is set so the caller fails closed with
//!    [`crate::status::KpexecStatus::RedactionFailure`].
//! 3. **Byte limiting** — stdout/stderr are truncated at the policy caps, with a
//!    clear truncation marker. Truncation happens *after* redaction and is not
//!    allowed to split the marker (see [`truncate_no_split_marker`]).
//! 4. **Lossy decode** — the redacted, byte-limited bytes are decoded lossily to
//!    UTF-8 for the envelope / passthrough. Because redaction ran on the raw
//!    bytes, a secret hidden inside otherwise-invalid UTF-8 cannot slip past the
//!    scanner via mojibake.
//!
//! # Why redact before truncating
//!
//! Truncating first could cut a secret occurrence mid-way, leaving a partial
//! secret that a full-match scan can no longer recognise (the cut fragment is
//! shorter than any variant). So redaction runs on the full buffer first; only
//! the already-masked bytes are then length-bounded.
//!
//! # The `[REDACTED:kpexec]` marker
//!
//! The marker is a fixed ASCII string with no `%`, no backslash, no quote and no
//! byte that percent-encoding escapes, so replacing a secret can never
//! manufacture a fresh occurrence of any variant form. (It *can* end up adjacent
//! to leftover secret bytes in pathological overlap cases; that is exactly what
//! the fail-closed re-scan catches.)

use crate::policy::OutputSpec;
use crate::secret::Secret;

/// The fixed marker that replaces every detected secret occurrence.
///
/// Deliberately contains no character that any variant encoding escapes (`%`,
/// `\`, `'`, `"`) so a replacement can never synthesize a new variant match.
pub const REDACTION_MARKER: &[u8] = b"[REDACTED:kpexec]";

/// The single line emitted (on both streams collapsing to it) when fail-closed
/// suppression trips: secret material survived redaction.
pub const SUPPRESSION_LINE: &str =
    "[kpexec] output suppressed: secret material detected in subprocess output";

/// Maximum number of replacement passes before declaring fail-closed.
///
/// A single pass cannot handle *overlapping* occurrences of a self-similar
/// secret (e.g. `abab` inside `ababab`): a left-to-right non-overlapping replace
/// leaves a residual match that a second pass cleans. A tiny bound lets such
/// trivial overlaps self-heal while guaranteeing termination — we never loop
/// unboundedly. If material still survives after the bound, we suppress.
const MAX_REDACTION_PASSES: usize = 4;

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

/// Processed output ready for emission (redacted, byte-limited, decoded).
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
    /// Whether fail-closed suppression tripped: secret material survived
    /// redaction, so BOTH streams were suppressed and the caller must fail
    /// closed with [`crate::status::KpexecStatus::RedactionFailure`].
    pub redaction_failed: bool,
}

/// Turn captured bytes into emittable strings: redact, fail-closed check, byte
/// limit, decode.
///
/// The secret is borrowed (never stored) and its plaintext is exposed only
/// inside [`secret_variants`]; this function holds no owned copy of the secret
/// bytes beyond the transient variant list, which is dropped on return.
pub fn process(captured: Captured, limits: &OutputSpec, secret: &Secret) -> Processed {
    process_with_bound(captured, limits, secret, MAX_REDACTION_PASSES)
}

/// Core of [`process`] with the fixpoint iteration bound made explicit.
///
/// The production path always calls this with [`MAX_REDACTION_PASSES`]. Tests
/// pass a deliberately reduced bound to exercise the fail-closed branch, since
/// with the production bound (and a marker containing no variant bytes) a single
/// greedy pass provably removes every constructible occurrence — so the branch
/// would otherwise be unreachable with a real secret.
fn process_with_bound(
    captured: Captured,
    limits: &OutputSpec,
    secret: &Secret,
    bound: usize,
) -> Processed {
    let variants = secret_variants(secret);

    // ---- redaction (before truncation, on raw bytes) -----------------------
    let (stdout_bytes, out_clean) = redact_bounded(&captured.stdout, &variants, bound);
    let (stderr_bytes, err_clean) = redact_bounded(&captured.stderr, &variants, bound);

    // ---- fail-closed: any surviving variant on EITHER stream suppresses both.
    if !out_clean || !err_clean {
        return Processed {
            stdout: SUPPRESSION_LINE.to_string(),
            stderr: SUPPRESSION_LINE.to_string(),
            stdout_truncated: false,
            stderr_truncated: false,
            redaction_failed: true,
        };
    }

    // ---- byte limiting (marker-safe) ---------------------------------------
    let (stdout_bytes, stdout_truncated) =
        truncate_no_split_marker(&stdout_bytes, limits.max_stdout_bytes);
    let (stderr_bytes, stderr_truncated) =
        truncate_no_split_marker(&stderr_bytes, limits.max_stderr_bytes);

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
        redaction_failed: false,
    }
}

// ---------------------------------------------------------------------------
// Variant generation
// ---------------------------------------------------------------------------

/// Compute every byte form of the secret that redaction must scan for.
///
/// For a typical opaque-token alphabet several of these coincide with the exact
/// bytes; we *compute* rather than assume, then deduplicate, so the common case
/// carries just 1–2 distinct entries while unusual secrets (containing quotes,
/// spaces, `+/=:@`, control bytes) get their true encoded forms too.
///
/// Forms produced:
/// * **exact** — the literal secret bytes.
/// * **JSON-escaped** — the secret as it appears *inside* a serde_json string
///   literal (surrounding quotes stripped): `"` → `\"`, `\` → `\\`, control
///   bytes → `\n`/`\t`/`\uXXXX`, etc.
/// * **URL percent-encoded (upper hex)** and **(lower hex)** — every byte that
///   percent-encoding escapes becomes `%XX`; unreserved bytes stay literal. The
///   two hex-case variants are distinct forms an emitter may choose.
/// * **shell single-quoted body** — the secret as it appears *between* the outer
///   single quotes of an `sh` single-quoted string, i.e. every `'` rewritten to
///   the classic `'\''` escape.
/// * **shell backslash-escaped** — the secret with shell metacharacters
///   backslash-escaped (as `printf %q`-style quoting would render them).
///
/// The exposed plaintext lives only for the body of this function; the returned
/// `Vec<Vec<u8>>` is owned bytes, and the caller drops it after redaction.
pub fn secret_variants(secret: &Secret) -> Vec<Vec<u8>> {
    // The one and only expose() in this module. Copied into a local byte vec so
    // all variant computation works on bytes; the borrow does not outlive here.
    let raw: Vec<u8> = secret.expose().as_bytes().to_vec();

    let mut variants: Vec<Vec<u8>> = Vec::with_capacity(6);
    // exact
    variants.push(raw.clone());
    // JSON-escaped (body of a serde_json string literal)
    variants.push(json_escaped_body(&raw));
    // URL percent-encoded, both hex cases
    variants.push(percent_encode(&raw, HexCase::Upper));
    variants.push(percent_encode(&raw, HexCase::Lower));
    // shell single-quoted body
    variants.push(shell_single_quoted_body(&raw));
    // shell backslash-escaped
    variants.push(shell_backslash_escaped(&raw));

    // Dedup while preserving nothing but distinctness. Empty variants cannot
    // occur (secret is >= 8 chars by authoring rule) but guard anyway.
    variants.retain(|v| !v.is_empty());
    dedup_bytes(variants)
}

/// Deduplicate a list of byte vectors, preserving first-seen order.
fn dedup_bytes(mut variants: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut seen: Vec<Vec<u8>> = Vec::with_capacity(variants.len());
    variants.retain(|v| {
        if seen.iter().any(|s| s == v) {
            false
        } else {
            seen.push(v.clone());
            true
        }
    });
    variants
}

/// The body of a serde_json string literal (surrounding quotes removed).
///
/// We use serde_json itself so this exactly tracks how the envelope would encode
/// the secret if it ever leaked into a JSON field, rather than reimplementing
/// the escape table.
fn json_escaped_body(raw: &[u8]) -> Vec<u8> {
    // serde_json only strings valid UTF-8; for non-UTF-8 secret bytes there is no
    // JSON-string form (JSON strings are Unicode), so fall back to the exact
    // bytes — the exact-form variant already covers detection in that case.
    match std::str::from_utf8(raw) {
        Ok(s) => {
            let quoted = serde_json::to_string(s).unwrap_or_else(|_| String::new());
            // Strip the surrounding quotes serde_json added.
            let bytes = quoted.into_bytes();
            if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
                bytes[1..bytes.len() - 1].to_vec()
            } else {
                raw.to_vec()
            }
        }
        Err(_) => raw.to_vec(),
    }
}

/// Hex-case selector for percent encoding.
#[derive(Clone, Copy)]
enum HexCase {
    Upper,
    Lower,
}

/// Whether a byte is a percent-encoding *unreserved* character (RFC 3986):
/// `A-Z a-z 0-9 - _ . ~`. These stay literal; every other byte is escaped.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Percent-encode every non-unreserved byte as `%XX` in the requested hex case.
fn percent_encode(raw: &[u8], case: HexCase) -> Vec<u8> {
    let digits: &[u8; 16] = match case {
        HexCase::Upper => b"0123456789ABCDEF",
        HexCase::Lower => b"0123456789abcdef",
    };
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if is_unreserved(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(digits[(b >> 4) as usize]);
            out.push(digits[(b & 0x0f) as usize]);
        }
    }
    out
}

/// The body between the outer single quotes of an `sh` single-quoted string.
///
/// In POSIX sh a single-quoted string cannot contain a literal `'`; the idiom to
/// embed one is to close the quote, emit an escaped quote, and reopen: `'\''`.
/// So a secret quoted as `'...'` has each embedded `'` rendered as `'\''` in the
/// bytes between the outer quotes. Secrets without a quote are unchanged (and
/// dedup drops the duplicate).
fn shell_single_quoted_body(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if b == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(b);
        }
    }
    out
}

/// The secret with shell metacharacters backslash-escaped.
///
/// Mirrors the unquoted `printf %q` style: each shell-special byte is prefixed
/// with a backslash; ordinary bytes pass through. For typical opaque tokens this
/// equals the exact bytes (dedup removes it); it only diverges for secrets that
/// contain shell metacharacters.
fn shell_backslash_escaped(raw: &[u8]) -> Vec<u8> {
    // The set of bytes an unquoted shell word treats specially.
    const SPECIAL: &[u8] = b" \t\n\"'\\$`!*?[]{}()<>|&;#~=%^";
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        if SPECIAL.contains(&b) {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

// ---------------------------------------------------------------------------
// Redaction + fail-closed scan
// ---------------------------------------------------------------------------

/// Replace every occurrence of any variant with [`REDACTION_MARKER`], iterating
/// to a fixpoint (bounded by [`MAX_REDACTION_PASSES`]).
///
/// Returns the redacted bytes and a `clean` flag: `true` iff a final re-scan
/// finds no surviving variant occurrence. `clean == false` is the fail-closed
/// trigger — the caller suppresses all output.
///
/// Iterating handles overlapping self-similar secrets: a single non-overlapping
/// left-to-right pass over `ababab` with secret `abab` replaces the first
/// `abab`, leaving `ab` + the tail — but a case like `abababab` with secret
/// `abab` can leave a residual `abab` straddling the replaced region's edge,
/// which the next pass removes. The bound guarantees termination.
fn redact_bounded(input: &[u8], variants: &[Vec<u8>], bound: usize) -> (Vec<u8>, bool) {
    let mut current = input.to_vec();
    for _ in 0..bound {
        let (next, replaced) = replace_all_variants(&current, variants);
        current = next;
        if !replaced {
            // A pass that changed nothing means we have reached a fixpoint.
            break;
        }
    }
    let clean = !contains_any_variant(&current, variants);
    (current, clean)
}

/// Redact at the production iteration bound. Thin wrapper over
/// [`redact_bounded`] so call sites read clearly.
#[cfg(test)]
fn redact(input: &[u8], variants: &[Vec<u8>]) -> (Vec<u8>, bool) {
    redact_bounded(input, variants, MAX_REDACTION_PASSES)
}

/// One replacement pass: scan left-to-right, and at each position replace the
/// first variant that matches, advancing past the inserted marker. Returns the
/// new buffer and whether any replacement happened.
fn replace_all_variants(input: &[u8], variants: &[Vec<u8>]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut replaced = false;
    while i < input.len() {
        let mut matched = false;
        for v in variants {
            if !v.is_empty() && input[i..].starts_with(v.as_slice()) {
                out.extend_from_slice(REDACTION_MARKER);
                i += v.len();
                matched = true;
                replaced = true;
                break;
            }
        }
        if !matched {
            out.push(input[i]);
            i += 1;
        }
    }
    (out, replaced)
}

/// Whether `input` contains any variant occurrence (the fail-closed re-scan).
fn contains_any_variant(input: &[u8], variants: &[Vec<u8>]) -> bool {
    for v in variants {
        if v.is_empty() {
            continue;
        }
        if input.windows(v.len()).any(|w| w == v.as_slice()) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Byte limiting (marker-safe)
// ---------------------------------------------------------------------------

/// Truncate `bytes` to at most `max` bytes without ever splitting an embedded
/// [`REDACTION_MARKER`]. Returns the (owned) truncated slice and whether
/// truncation occurred.
///
/// If the naive cut at `max` would fall *inside* a marker occurrence, we pull the
/// cut back to just before that marker so a partial `[REDACTED:kpexec]` never
/// appears in emitted output. A `max` of 0 means "no output" but still records
/// truncation if there were any bytes.
fn truncate_no_split_marker(bytes: &[u8], max: u64) -> (Vec<u8>, bool) {
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    if bytes.len() <= max {
        return (bytes.to_vec(), false);
    }
    // Naive cut point.
    let mut cut = max;
    // If a marker straddles `cut` (starts before it and ends after it), move the
    // cut back to the marker's start. Markers are short and rare, so a bounded
    // scan of the window near the cut is cheap.
    let m = REDACTION_MARKER;
    if !m.is_empty() {
        // The earliest byte a marker overlapping `cut` could start at.
        let scan_start = cut.saturating_sub(m.len() - 1);
        let mut j = scan_start;
        while j < cut {
            if bytes[j..].starts_with(m) {
                // This marker starts at j (< cut). If it also ends after cut, the
                // naive cut would split it: pull back to j.
                if j + m.len() > cut {
                    cut = j;
                }
                break;
            }
            j += 1;
        }
    }
    (bytes[..cut].to_vec(), true)
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

    /// A secret guaranteed to appear literally in output (no metacharacters), so
    /// tests that only care about the exact form stay simple.
    fn plain_secret() -> Secret {
        Secret::new("s3cr3t-EXAMPLE-token".to_string())
    }

    // ---- passthrough / truncation (M4 behavior preserved) ------------------

    #[test]
    fn passes_through_under_limit() {
        let cap = Captured {
            stdout: b"hello".to_vec(),
            stderr: b"warn".to_vec(),
        };
        let p = process(cap, &limits(100, 100), &plain_secret());
        assert_eq!(p.stdout, "hello");
        assert_eq!(p.stderr, "warn");
        assert!(!p.stdout_truncated);
        assert!(!p.stderr_truncated);
        assert!(!p.redaction_failed);
    }

    #[test]
    fn truncates_stdout_with_marker() {
        let cap = Captured {
            stdout: vec![b'x'; 50],
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(10, 100), &plain_secret());
        assert!(p.stdout_truncated);
        assert!(p.stdout.starts_with("xxxxxxxxxx"));
        assert!(p.stdout.contains("truncated"));
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
        let p = process(cap, &limits(100, 20), &plain_secret());
        assert!(!p.stdout_truncated);
        assert!(p.stderr_truncated);
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
        let p = process(cap, &limits(100, 100), &plain_secret());
        assert!(p.stdout.contains('a'));
    }

    #[test]
    fn zero_limit_suppresses_but_marks() {
        let cap = Captured {
            stdout: b"anything".to_vec(),
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(0, 0), &plain_secret());
        assert!(p.stdout_truncated);
        assert!(p.stdout.starts_with("\n[kpexec]"));
    }

    // ---- variant generation ------------------------------------------------

    #[test]
    fn variants_typical_token_dedup_to_one() {
        // An opaque token of unreserved chars: exact == json == url == shell, so
        // dedup collapses to a single variant.
        let s = Secret::new("abcDEF123-token_value".to_string());
        let v = secret_variants(&s);
        assert_eq!(
            v.len(),
            1,
            "typical token should dedup to one variant: {v:?}"
        );
        assert_eq!(v[0], b"abcDEF123-token_value");
    }

    #[test]
    fn variants_distinct_forms_for_special_chars() {
        // Contains chars that force distinct encodings: space, +, /, =, :, @, '.
        let s = Secret::new("a b+c/d=e:f@g'h".to_string());
        let v = secret_variants(&s);

        let exact = b"a b+c/d=e:f@g'h".to_vec();
        // URL upper: space->%20 + ->%2B / ->%2F = ->%3D : ->%3A @ ->%40 ' ->%27
        let url_upper = b"a%20b%2Bc%2Fd%3De%3Af%40g%27h".to_vec();
        let url_lower = b"a%20b%2bc%2fd%3de%3af%40g%27h".to_vec();
        // JSON: only the single quote and others are literal; ' is NOT escaped in
        // JSON, so json body == exact here (dedup drops it).
        // shell single-quoted body: ' -> '\''
        let shell_sq = b"a b+c/d=e:f@g'\\''h".to_vec();
        // shell backslash form: only bytes in the metacharacter set are escaped.
        // Here that is space, '=', and '\'' (SPECIAL excludes +, /, :, @).
        let shell_bs = b"a\\ b+c/d\\=e:f@g\\'h".to_vec();

        assert!(v.contains(&exact), "exact missing: {v:?}");
        assert!(v.contains(&url_upper), "url-upper missing: {v:?}");
        assert!(v.contains(&url_lower), "url-lower missing: {v:?}");
        assert!(
            v.contains(&shell_sq),
            "shell single-quote body missing: {v:?}"
        );
        assert!(v.contains(&shell_bs), "shell backslash form missing: {v:?}");
        // All variants distinct (dedup worked).
        let mut sorted = v.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), v.len(), "variants not deduplicated: {v:?}");
    }

    #[test]
    fn json_escaped_variant_for_quote_and_backslash() {
        // A secret containing a double-quote and a backslash: JSON escapes both.
        let s = Secret::new("tok\"en\\value".to_string());
        let v = secret_variants(&s);
        let json_body = b"tok\\\"en\\\\value".to_vec();
        assert!(v.contains(&json_body), "json-escaped form missing: {v:?}");
    }

    // ---- redaction ---------------------------------------------------------

    #[test]
    fn redacts_exact_on_both_streams() {
        let s = plain_secret();
        let out = format!("prefix {} suffix", "s3cr3t-EXAMPLE-token");
        let err = format!("err={}", "s3cr3t-EXAMPLE-token");
        let cap = Captured {
            stdout: out.into_bytes(),
            stderr: err.into_bytes(),
        };
        let p = process(cap, &limits(1000, 1000), &s);
        assert!(!p.redaction_failed);
        assert!(
            !p.stdout.contains("s3cr3t"),
            "stdout leaked: {:?}",
            p.stdout
        );
        assert!(
            !p.stderr.contains("s3cr3t"),
            "stderr leaked: {:?}",
            p.stderr
        );
        assert!(p.stdout.contains("[REDACTED:kpexec]"));
        assert!(p.stderr.contains("[REDACTED:kpexec]"));
    }

    #[test]
    fn redacts_url_encoded_forms() {
        let s = Secret::new("a b+c/d=e".to_string());
        // Emit both hex cases.
        let body = "before a%20b%2Bc%2Fd%3De and a%20b%2bc%2fd%3de after";
        let cap = Captured {
            stdout: body.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(1000, 1000), &s);
        assert!(!p.redaction_failed);
        assert!(
            !p.stdout.contains("%2B"),
            "url-upper leaked: {:?}",
            p.stdout
        );
        assert!(
            !p.stdout.contains("%2f"),
            "url-lower leaked: {:?}",
            p.stdout
        );
        assert_eq!(p.stdout.matches("[REDACTED:kpexec]").count(), 2);
    }

    #[test]
    fn redacts_json_escaped_form() {
        let s = Secret::new("tok\"en".to_string());
        // The JSON-escaped body of the secret as it would sit in a JSON string.
        let body = r#"{"k":"tok\"en"}"#;
        let cap = Captured {
            stdout: body.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(1000, 1000), &s);
        assert!(!p.redaction_failed);
        assert!(
            !p.stdout.contains("tok\\\"en"),
            "json-escaped form leaked: {:?}",
            p.stdout
        );
        assert!(p.stdout.contains("[REDACTED:kpexec]"));
    }

    #[test]
    fn redacts_secret_in_non_utf8_output() {
        // Secret bytes surrounded by invalid UTF-8 (0xff). Redaction runs on raw
        // bytes, so the secret is caught before the lossy decode could mangle it.
        let s = plain_secret();
        let mut cap_bytes = vec![0xff, 0xfe];
        cap_bytes.extend_from_slice(b"s3cr3t-EXAMPLE-token");
        cap_bytes.extend_from_slice(&[0xff, 0x00]);
        let cap = Captured {
            stdout: cap_bytes,
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(1000, 1000), &s);
        assert!(!p.redaction_failed);
        assert!(
            !p.stdout.contains("s3cr3t"),
            "non-utf8 leaked: {:?}",
            p.stdout
        );
        assert!(p.stdout.contains("[REDACTED:kpexec]"));
    }

    // ---- redact-before-truncate ordering -----------------------------------

    #[test]
    fn secret_straddling_byte_limit_is_not_partially_leaked() {
        // The secret occurrence straddles the byte cap. If truncation ran FIRST it
        // would cut the secret in half and the tail-half would be masked but the
        // head-half emitted verbatim. Redact-first means the whole occurrence is
        // replaced by the marker before any cut, so no partial secret survives.
        let s = plain_secret();
        let secret = "s3cr3t-EXAMPLE-token";
        // Put 5 filler bytes, then the secret, so a cap of 10 lands mid-secret.
        let body = format!("AAAAA{secret}TRAILING");
        let cap = Captured {
            stdout: body.into_bytes(),
            stderr: Vec::new(),
        };
        let p = process(cap, &limits(10, 1000), &s);
        assert!(!p.redaction_failed);
        assert!(
            !p.stdout.contains("s3cr3t"),
            "partial secret leaked: {:?}",
            p.stdout
        );
    }

    #[test]
    fn truncation_never_splits_the_marker() {
        // After redaction the buffer is "AAAAA[REDACTED:kpexec]...". A cap landing
        // inside the marker must pull back to before it, never emit a fragment.
        let s = plain_secret();
        let secret = "s3cr3t-EXAMPLE-token";
        let body = format!("AAAAA{secret}ZZZZZ");
        let cap = Captured {
            stdout: body.into_bytes(),
            stderr: Vec::new(),
        };
        // Cap of 8 lands inside "[REDACTED:kpexec]" which begins at index 5.
        let p = process(cap, &limits(8, 1000), &s);
        assert!(p.stdout_truncated);
        let payload = p.stdout.strip_suffix(TRUNCATION_MARKER).unwrap();
        // The cut was pulled back to before the marker: only the "AAAAA" filler
        // survives — no fragment of "[REDACTED:kpexec]" is present.
        assert_eq!(payload, "AAAAA");
        assert!(
            !payload.contains('['),
            "marker fragment leaked: {payload:?}"
        );
    }

    // ---- redaction is single-pass-complete with this marker ----------------

    #[test]
    fn one_greedy_pass_clears_overlapping_self_similar() {
        // Justification for the fixpoint being defensive: because the marker
        // contains none of the pattern's bytes, a single greedy left-to-right,
        // non-overlapping pass consumes every occurrence and cannot manufacture a
        // new one. Even a maximally self-similar pattern clears in one pass.
        let variants = vec![b"abababab".to_vec()]; // period-2, 8 bytes
        let input = b"ababababababababab"; // 18 bytes of the same run
        let (once, _replaced) = replace_all_variants(input, &variants);
        assert!(
            !contains_any_variant(&once, &variants),
            "a single pass should leave no residual: {:?}",
            String::from_utf8_lossy(&once)
        );
        // And the production redactor reports clean.
        let (_bytes, clean) = redact(input, &variants);
        assert!(clean);
    }

    // ---- fail-closed branch (exercised via a reduced iteration bound) -------

    // With the production marker and greedy replacement, a single pass provably
    // removes every constructible occurrence (see the test above), so the
    // fail-closed branch is unreachable with any real >=8-char secret at the
    // production bound. To cover the branch *honestly* — rather than fabricating a
    // secret that could never arise from authoring — we drive `process_with_bound`
    // with `bound == 0`: no replacement pass runs, the re-scan still finds the
    // secret, and the suppression path fires exactly as it would for a genuine
    // survivor. This tests the reaction to "material survived", which is the part
    // that matters, without pretending an unconstructible input.
    #[test]
    fn fail_closed_suppresses_both_streams_and_flags_failure() {
        let s = plain_secret();
        let cap = Captured {
            stdout: b"leak: s3cr3t-EXAMPLE-token here".to_vec(),
            stderr: b"clean line".to_vec(),
        };
        // bound == 0 -> the secret is never replaced -> re-scan finds it -> suppress.
        let p = process_with_bound(cap, &limits(1000, 1000), &s, 0);
        assert!(p.redaction_failed, "material survived, must fail closed");
        // BOTH streams collapse to the single suppression line — even the stderr
        // that had no secret is suppressed.
        assert_eq!(p.stdout, SUPPRESSION_LINE);
        assert_eq!(p.stderr, SUPPRESSION_LINE);
        assert!(!p.stdout.contains("s3cr3t"));
        assert!(!p.stderr.contains("clean line"));
    }

    #[test]
    fn no_fail_closed_when_redaction_succeeds() {
        // Same input, production bound: redaction succeeds, no suppression.
        let s = plain_secret();
        let cap = Captured {
            stdout: b"leak: s3cr3t-EXAMPLE-token here".to_vec(),
            stderr: b"clean line".to_vec(),
        };
        let p = process(cap, &limits(1000, 1000), &s);
        assert!(!p.redaction_failed);
        assert!(p.stdout.contains("[REDACTED:kpexec]"));
        assert_eq!(p.stderr, "clean line");
    }
}
