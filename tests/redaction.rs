//! M5 integration tests: unconditional output redaction + fail-closed
//! suppression, driven end-to-end through the run path against temp vaults.
//!
//! NEVER touches the real login keychain. Child targets are helper scripts in
//! the test temp dir, pinned exactly as `entry add` would. Output is captured via
//! in-memory [`kpexec::cmd_run::Emit`] sinks.
//!
//! This is a *separate* test binary from `run_path.rs` on purpose: it installs a
//! process-global `tracing` subscriber (via `kpexec::logging::init_at`) pointed
//! at a temp audit log, so the A4 test can grep the log file and prove the secret
//! never reached it. The global subscriber can only be set once per process, so
//! it lives in its own binary and is initialised once here.
//!
//! Coverage (docs/milestones.md):
//! * A4 — the raw secret appears NOWHERE: not in stdout, stderr, the `--json`
//!   envelope, nor the audit log file (both streams echoed, then grepped).
//! * A5 — URL-encoded (upper + lower hex) and JSON-escaped forms are all masked.
//! * fail-closed — a genuine survivor is not constructible with a real secret at
//!   the production iteration bound (the marker contains none of any variant's
//!   bytes, so one greedy pass removes every occurrence). The honest fail-closed
//!   branch coverage therefore lives in the `src/output.rs` unit test
//!   `fail_closed_suppresses_both_streams_and_flags_failure`, which drives the
//!   suppression path with a reduced bound. Here we assert the complementary
//!   end-to-end property: a normal run does NOT spuriously fail closed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock};
use std::time::Duration;

use kpexec::cli::RunArgs;
use kpexec::cmd_run::{self, Emit, RunOptions};
use kpexec::error::Result as KpResult;
use kpexec::keychain::{FileKeychain, KeychainStore, VaultCredential, account_for};
use kpexec::lock::VaultLock;
use kpexec::pin;
use kpexec::policy::{Command, EnvSpec, OutputSpec, Policy};
use kpexec::secret::Secret;
use kpexec::status::Outcome;
use kpexec::vault::{Vault, canonical_or_lexical};

static LOG_INIT: Once = Once::new();
/// The one shared audit-log path for this test binary. Because the `tracing`
/// subscriber is process-global and can be installed only once, all tests in
/// this binary log to a single file; we keep it in a binary-lifetime temp dir
/// (leaked on purpose) so it survives every per-test `TempDir` being dropped.
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
/// Serializes audit-log reads with the writes tests trigger, so a grep sees a
/// consistent snapshot.
static LOG_LOCK: Mutex<()> = Mutex::new(());

/// Initialise (once) the process-global audit log to a binary-wide temp file and
/// return its path. Every `Harness` shares this same path.
fn init_audit_log() -> PathBuf {
    LOG_INIT.call_once(|| {
        let dir = std::env::temp_dir().join(format!("kpexec-m5-audit-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("kpexec.log");
        // Generous cap + keep so a single test run never rotates.
        kpexec::logging::init_at(path.clone(), 50 * 1024 * 1024, 3);
        let _ = LOG_PATH.set(path);
    });
    LOG_PATH.get().expect("log path set by init").clone()
}

struct Harness {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    keychain: FileKeychain,
    vault_path: PathBuf,
    log_path: PathBuf,
}

struct RunResult {
    outcome: KpResult<Outcome>,
    stdout: String,
    stderr: String,
}

impl RunResult {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("stdout was not a JSON envelope ({e}): {:?}", self.stdout))
    }
    fn ok(&self) -> Outcome {
        match &self.outcome {
            Ok(o) => *o,
            Err(e) => panic!("expected Ok outcome, got error: {}", e.message()),
        }
    }
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let log_path = init_audit_log();
        let keychain = FileKeychain::new(root.join("kc")).unwrap();
        let vault_path = root.join("vault.kdbx");
        let master = Secret::new("master-EXAMPLE-pw-1234".to_string());

        let mut vault = Vault::create(vault_path.clone(), master.clone());
        vault.save_atomic().unwrap();
        keychain
            .set(
                &account_for(&vault_path),
                &VaultCredential {
                    password: master.clone(),
                    db_path: canonical_or_lexical(&vault_path).to_string_lossy().into(),
                },
            )
            .unwrap();

        Harness {
            _dir: dir,
            dir: root,
            keychain,
            vault_path,
            log_path,
        }
    }

    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[allow(clippy::too_many_arguments)]
    fn add_entry(
        &self,
        id: &str,
        secret: &str,
        inject: &str,
        exe: &Path,
        prefix: &[&str],
        env: Option<EnvSpec>,
        output: Option<OutputSpec>,
    ) {
        let mut policy = Policy::new(format!("desc {id}"), inject.to_string(), env);
        if let Some(o) = output {
            policy.output = o;
        }
        let sha = Some(pin::compute(exe.to_str().unwrap()).unwrap().sha256);
        policy.commands.push(Command {
            name: "cmd".to_string(),
            exe: exe.to_string_lossy().into_owned(),
            exe_sha256: sha,
            argv_prefix: prefix.iter().map(|s| s.to_string()).collect(),
        });

        let cred = self
            .keychain
            .get(&account_for(&self.vault_path))
            .unwrap()
            .unwrap();
        let mut vault = Vault::open_with_credential(&self.vault_path, cred, None).unwrap();
        let _lock = VaultLock::acquire(&self.vault_path).unwrap();
        vault
            .insert_entry(id, id, &Secret::new(secret.to_string()), &policy)
            .unwrap();
        vault.save_atomic().unwrap();
    }

    fn run_args(&self, entry: &str, command: &str) -> RunArgs {
        RunArgs {
            entry: entry.to_string(),
            command: command.to_string(),
            dry_run: false,
            timeout: None,
            json: false,
            trailing: Vec::new(),
        }
    }

    fn run(&self, args: &RunArgs, opts: &RunOptions) -> RunResult {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let outcome = {
            let mut emit = Emit::new(&mut out, &mut err);
            cmd_run::run_with(
                args,
                &self.vault_path,
                &self.keychain,
                None,
                opts,
                &mut emit,
            )
        };
        RunResult {
            outcome,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
        }
    }

    /// Read the audit log file's full contents (flushing tracing first).
    fn audit_log(&self) -> String {
        // tracing writes synchronously through our RotatingWriter. Hold the shared
        // lock so a concurrent test's write does not race our read. If the file
        // does not exist, logging was disabled — treat as empty.
        let _g = LOG_LOCK.lock().unwrap();
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

fn default_opts() -> RunOptions {
    RunOptions {
        timeout: Duration::from_secs(30),
        kill_grace: Duration::from_secs(5),
    }
}

// ---------------------------------------------------------------------------
// A4 — the raw secret never appears anywhere (stdout, stderr, envelope, log)
// ---------------------------------------------------------------------------

#[test]
fn a4_secret_never_appears_anywhere() {
    let h = Harness::new();
    // The secret must be >= 8 chars; keep it alphanumeric-with-dashes so it also
    // appears literally (no encoding needed) on both streams.
    let secret = "A4-s3cr3t-KEY-abcdef123456";
    // Echo the injected env var to BOTH stdout and stderr.
    let exe = h.script(
        "echoer.sh",
        "#!/bin/sh\nprintf 'out=%s\\n' \"$THE_TOKEN\"\nprintf 'err=%s\\n' \"$THE_TOKEN\" 1>&2\n",
    );
    h.add_entry("e4", secret, "THE_TOKEN", &exe, &[], None, None);

    // Run once in --json (envelope) and once in passthrough, so both emission
    // paths are covered by the grep.
    let mut json_args = h.run_args("e4", "cmd");
    json_args.json = true;
    let rj = h.run(&json_args, &default_opts());
    assert_eq!(rj.ok(), Outcome::ChildExit(0));

    let v = rj.json();
    let env_stdout = v["stdout"].as_str().unwrap();
    let env_stderr = v["stderr"].as_str().unwrap();
    // Both streams show the marker; neither shows the secret.
    assert!(
        env_stdout.contains("[REDACTED:kpexec]"),
        "stdout: {env_stdout:?}"
    );
    assert!(
        env_stderr.contains("[REDACTED:kpexec]"),
        "stderr: {env_stderr:?}"
    );
    assert!(!rj.stdout.contains(secret), "secret in --json stdout");
    assert!(!rj.stderr.contains(secret), "secret in --json stderr");

    // Passthrough path.
    let rp = h.run(&h.run_args("e4", "cmd"), &default_opts());
    assert_eq!(rp.ok(), Outcome::ChildExit(0));
    assert!(rp.stdout.contains("[REDACTED:kpexec]"));
    assert!(rp.stderr.contains("[REDACTED:kpexec]"));
    assert!(!rp.stdout.contains(secret), "secret in passthrough stdout");
    assert!(!rp.stderr.contains(secret), "secret in passthrough stderr");

    // The audit log (never carries the secret by design; grep to prove it).
    let log = h.audit_log();
    assert!(!log.is_empty(), "audit log should have run records");
    assert!(!log.contains(secret), "secret leaked into the audit log");
    // Sanity: the run WAS logged.
    assert!(log.contains("run"), "expected a run record in the log");
}

// ---------------------------------------------------------------------------
// A5 — URL-encoded (upper + lower hex) and JSON-escaped forms are masked
// ---------------------------------------------------------------------------

#[test]
fn a5_encoded_variant_forms_are_masked() {
    let h = Harness::new();
    // A secret containing chars that force distinct encodings: space, +, /, =, :,
    // @. Still >= 8 chars.
    let secret = "a b+c/d=e:f@ghij";
    // The target emits the secret in several encodings computed by /bin/sh, so we
    // don't hardcode them and risk drift: exact, URL-upper, URL-lower, and a
    // JSON-escaped form. We build them with printf and a tiny hex loop.
    let exe = h.script(
        "encoder.sh",
        r#"#!/bin/sh
s="$THE_TOKEN"
# exact
printf 'exact=%s\n' "$s"
# RFC-3986 percent-encode: unreserved bytes (A-Z a-z 0-9 - _ . ~) stay literal,
# everything else becomes %XX. `up` selects upper/lower hex. Iterate byte by byte
# via od so this matches kpexec's own percent_encode() form exactly.
urlenc() {
  printf '%s' "$1" | od -An -tx1 -v | tr ' ' '\n' | while read -r h; do
    [ -z "$h" ] && continue
    c=$(printf "\\$(printf '%03o' 0x$h)")
    case "$c" in
      [A-Za-z0-9_.~-]) printf '%s' "$c" ;;
      *) if [ "$2" = 1 ]; then printf '%%%s' "$(printf '%s' "$h" | tr 'a-f' 'A-F')"; \
         else printf '%%%s' "$(printf '%s' "$h" | tr 'A-F' 'a-f')"; fi ;;
    esac
  done
  printf '\n'
}
printf 'urlU='; urlenc "$s" 1
printf 'urlL='; urlenc "$s" 0
# json form: emit the secret inside a JSON string literal.
printf 'json={"t":"%s"}\n' "$s"
"#,
    );
    h.add_entry("e5", secret, "THE_TOKEN", &exe, &[], None, None);

    let mut args = h.run_args("e5", "cmd");
    args.json = true;
    let r = h.run(&args, &default_opts());
    assert_eq!(r.ok(), Outcome::ChildExit(0));

    let v = r.json();
    let out = v["stdout"].as_str().unwrap();

    // No exact secret.
    assert!(!out.contains(secret), "exact secret leaked: {out:?}");
    // No URL-encoded fragments (the distinctive escaped bytes for + / = : @ space).
    for frag in [
        "%2B", "%2F", "%3D", "%3A", "%40", "%20", "%2b", "%2f", "%3d", "%3a",
    ] {
        assert!(!out.contains(frag), "url fragment {frag} leaked: {out:?}");
    }
    // At least the exact and both url lines were masked.
    assert!(
        out.matches("[REDACTED:kpexec]").count() >= 3,
        "expected several masked occurrences: {out:?}"
    );

    // Also confirm the secret is nowhere in the raw envelope text or the log.
    assert!(!r.stdout.contains(secret));
    assert!(!h.audit_log().contains(secret));
}

// ---------------------------------------------------------------------------
// fail-closed end-to-end: a target whose output cannot be fully cleaned
// suppresses both streams and returns RedactionFailure (105).
// ---------------------------------------------------------------------------

#[test]
fn fail_closed_end_to_end_via_zero_limit_is_unit_covered() {
    // NOTE on constructibility: with the production marker (which contains none of
    // any variant's bytes) a single greedy replacement pass provably removes every
    // occurrence, so no *real* >=8-char secret + child output can survive the
    // bounded fixpoint. The honest fail-closed branch coverage therefore lives in
    // the `src/output.rs` unit test `fail_closed_suppresses_both_streams_and_
    // flags_failure`, which drives `process_with_bound(.., 0)` so the re-scan finds
    // unreplaced material and the suppression path fires exactly as it would for a
    // genuine survivor. Here we assert the complementary end-to-end property: a
    // normal run does NOT spuriously fail closed.
    let h = Harness::new();
    let secret = "steady-s3cr3t-value-01";
    let exe = h.script(
        "ok.sh",
        "#!/bin/sh\nprintf 'value is %s done\\n' \"$THE_TOKEN\"\n",
    );
    h.add_entry("e6", secret, "THE_TOKEN", &exe, &[], None, None);

    let mut args = h.run_args("e6", "cmd");
    args.json = true;
    let r = h.run(&args, &default_opts());
    // A clean redaction is not a redaction failure.
    assert_eq!(r.ok(), Outcome::ChildExit(0));
    assert_ne!(r.json()["kpexec_status"], "redaction-failure");
    assert!(
        r.json()["stdout"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:kpexec]")
    );
    assert!(!r.stdout.contains(secret));
}
