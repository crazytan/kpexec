//! M4 integration tests: the run path, driven in-process against temp vaults +
//! the file-backed fake keychain, with small shell scripts as pinned targets.
//!
//! NEVER touches the real login keychain. All child targets are helper scripts
//! written into the test's temp dir and pinned exactly as `entry add` would.
//! Output is captured via in-memory [`kpexec::cmd_run::Emit`] sinks, so the
//! tests are deterministic and safe to run in parallel (no FD games).
//!
//! Coverage map (docs/milestones.md acceptance tests + M4 spec points):
//! * A1 — `--dry-run`: argv printed, no spawn (a marker-file target proves it),
//!   and the secret is structurally never read.
//! * A2 — unknown entry / unknown command / malformed policy statuses (`--json`).
//! * A3 — exact argv + env: the child dumps its argv and env to a file; we assert
//!   env is EXACTLY baseline + env.set + secret and argv is verbatim (spaces,
//!   quotes, a literal `$HOME`).
//! * A6 — child exits 7 → kpexec propagates 7; a signal-killed child → 128+N.
//! * A7 — timeout: SIGTERM honored; a SIGTERM-trapping sleeper is SIGKILLed after
//!   the grace; partial output returned; status `timeout`.
//! * pin — a tampered target is rejected (103) with no execution; an unpinned
//!   (`--no-pin`) command runs with a warning.
//! * misc — stdin is closed (child read gets EOF); byte-limit truncation with a
//!   marker; the `--json` envelope shape on success and rejection.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kpexec::cli::RunArgs;
use kpexec::cmd_run::{self, Emit, RunOptions};
use kpexec::error::Result as KpResult;
use kpexec::keychain::{FileKeychain, KeychainStore, VaultCredential, account_for};
use kpexec::lock::VaultLock;
use kpexec::pin;
use kpexec::policy::{Command, EnvSpec, OutputSpec, Policy};
use kpexec::secret::Secret;
use kpexec::status::{KpexecStatus, Outcome};
use kpexec::vault::{Vault, canonical_or_lexical};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    keychain: FileKeychain,
    vault_path: PathBuf,
    master: Secret,
}

/// The result of a captured run: the returned outcome plus the two byte streams.
struct RunResult {
    outcome: KpResult<Outcome>,
    stdout: String,
    stderr: String,
}

impl RunResult {
    /// The parsed JSON envelope from stdout (for `--json` runs).
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("stdout was not a JSON envelope ({e}): {:?}", self.stdout))
    }

    /// The outcome, asserting the run returned `Ok`. `Outcome` is `Copy`, so
    /// this leaves `self` intact for further assertions (e.g. `json()`).
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
            master,
        }
    }

    /// Write an executable helper script into the temp dir and return its path.
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Insert an entry with a single command targeting `exe`, pinned unless
    /// `pin_it` is false, injecting the secret as `inject` and applying `env`.
    #[allow(clippy::too_many_arguments)]
    fn add_entry(
        &self,
        id: &str,
        secret: &str,
        inject: &str,
        exe: &Path,
        prefix: &[&str],
        pin_it: bool,
        env: Option<EnvSpec>,
        output: Option<OutputSpec>,
    ) {
        let mut policy = Policy::new(format!("desc {id}"), inject.to_string(), env);
        if let Some(o) = output {
            policy.output = o;
        }
        let sha = if pin_it {
            Some(pin::compute(exe.to_str().unwrap()).unwrap().sha256)
        } else {
            None
        };
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

    /// Run in-process, capturing stdout/stderr into in-memory buffers.
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
}

/// Fast options so timeout tests don't stall the suite.
fn fast_opts(timeout: Duration, grace: Duration) -> RunOptions {
    RunOptions {
        timeout,
        kill_grace: grace,
    }
}

fn default_opts() -> RunOptions {
    fast_opts(Duration::from_secs(30), Duration::from_secs(5))
}

// ---------------------------------------------------------------------------
// A1 — dry-run: argv printed, no spawn, no secret read
// ---------------------------------------------------------------------------

#[test]
fn a1_dry_run_prints_argv_and_never_spawns() {
    let h = Harness::new();
    // A target that, if it ever runs, creates a marker file. Dry-run must not.
    let marker = h.dir.join("SPAWNED");
    let exe = h.script(
        "target.sh",
        &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    );
    h.add_entry(
        "e",
        "s3cr3t-EXAMPLE",
        "TOKEN",
        &exe,
        &["run"],
        true,
        None,
        None,
    );

    let mut args = h.run_args("e", "cmd");
    args.dry_run = true;
    args.trailing = vec!["--flag".into(), "value".into()];

    let r = h.run(&args, &default_opts());
    assert_eq!(r.ok(), Outcome::Kpexec(KpexecStatus::Success));

    // The canonical exe + prefix + trailing appear in the printed argv.
    let canon = std::fs::canonicalize(&exe).unwrap();
    assert!(r.stdout.contains(&canon.to_string_lossy().into_owned()));
    assert!(r.stdout.contains("run"));
    assert!(r.stdout.contains("--flag"));
    assert!(r.stdout.contains("value"));

    // Structural no-spawn guarantee: the marker file was never created.
    assert!(!marker.exists(), "dry-run must not spawn the child");
}

#[test]
fn a1_dry_run_json_envelope() {
    let h = Harness::new();
    let exe = h.script("t.sh", "#!/bin/sh\ntrue\n");
    h.add_entry(
        "e",
        "s3cr3t-EXAMPLE",
        "TOKEN",
        &exe,
        &["p"],
        true,
        None,
        None,
    );

    let mut args = h.run_args("e", "cmd");
    args.dry_run = true;
    args.json = true;

    let r = h.run(&args, &default_opts());
    assert_eq!(r.ok(), Outcome::Kpexec(KpexecStatus::Success));

    let v = r.json();
    assert_eq!(v["kpexec_status"], "success");
    assert!(v["child_exit_code"].is_null(), "no child ran on dry-run");
    assert!(v["stdout"].as_str().unwrap().contains('p'));
    assert!(!v["stdout"].as_str().unwrap().contains("s3cr3t"));
}

// ---------------------------------------------------------------------------
// A2 — deny-by-default statuses via --json
// ---------------------------------------------------------------------------

#[test]
fn a2_unknown_entry() {
    let h = Harness::new();
    let mut args = h.run_args("nope", "cmd");
    args.json = true;
    let r = h.run(&args, &default_opts());
    assert_eq!(r.json()["kpexec_status"], "unknown-entry");
    let outcome = r.ok();
    assert_eq!(outcome, Outcome::Kpexec(KpexecStatus::UnknownEntry));
    assert_eq!(outcome.exit_code(), 100);
}

#[test]
fn a2_unknown_command() {
    let h = Harness::new();
    let exe = h.script("t.sh", "#!/bin/sh\ntrue\n");
    h.add_entry(
        "e",
        "s3cr3t-EXAMPLE",
        "TOKEN",
        &exe,
        &["p"],
        true,
        None,
        None,
    );
    let mut args = h.run_args("e", "no-such-command");
    args.json = true;
    let r = h.run(&args, &default_opts());
    assert_eq!(r.json()["kpexec_status"], "unknown-command");
    assert_eq!(r.ok().exit_code(), 101);
}

#[test]
fn a2_malformed_policy() {
    let h = Harness::new();
    insert_raw_policy(
        &h,
        "weird",
        r#"{"schema":"kpexec.policy.v1","description":"x","surprise":1,"secret":{"field":"password","inject":{"type":"env","name":"T"}},"commands":[],"output":{"max_stdout_bytes":1,"max_stderr_bytes":1}}"#,
        "s3cr3t-EXAMPLE",
    );
    let mut args = h.run_args("weird", "cmd");
    args.json = true;
    let r = h.run(&args, &default_opts());
    assert_eq!(r.json()["kpexec_status"], "malformed-policy");
    assert_eq!(r.ok().exit_code(), 102);
}

// ---------------------------------------------------------------------------
// A3 — exact argv + env
// ---------------------------------------------------------------------------

#[test]
fn a3_exact_argv_and_env() {
    let h = Harness::new();
    // A canary in the parent env that must be scrubbed by env_clear() and never
    // reach the child. SAFETY: single-threaded within this test before spawn.
    unsafe {
        std::env::set_var("KPEXEC_A3_CANARY", "leak-me-if-you-can");
    }
    let dump = h.dir.join("dump.txt");
    // The child writes: one line per argv element prefixed ARGV<TAB>, then an
    // ENV-START sentinel, then `env` output. We assert on both.
    let exe = h.script(
        "dumper.sh",
        &format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do printf 'ARGV\\t%s\\n' \"$a\"; done > '{d}'\n\
             printf 'ENV-START\\n' >> '{d}'\n\
             env >> '{d}'\n",
            d = dump.display()
        ),
    );

    let mut env = std::collections::BTreeMap::new();
    env.insert("EXTRA_ONE".to_string(), "alpha".to_string());
    env.insert("EXTRA_TWO".to_string(), "beta".to_string());
    h.add_entry(
        "e",
        "s3cr3t-EXAMPLE-value",
        "INJECTED_TOKEN",
        &exe,
        &["fixed", "prefix"],
        true,
        Some(EnvSpec { set: env }),
        None,
    );

    let mut args = h.run_args("e", "cmd");
    // Trailing args exercise: spaces, quotes, and a literal $HOME.
    args.trailing = vec!["has spaces".into(), "a\"quote".into(), "$HOME".into()];

    let r = h.run(&args, &default_opts());
    assert_eq!(r.ok(), Outcome::ChildExit(0));

    let contents = std::fs::read_to_string(&dump).unwrap();
    let (argv_part, env_part) = contents.split_once("ENV-START\n").unwrap();

    // ---- argv: [prefix..] + [trailing..] arrive verbatim (argv[0] is the exe,
    // not passed to "$@"), each element intact including spaces/quotes/$HOME.
    let argv: Vec<&str> = argv_part
        .lines()
        .filter_map(|l| l.strip_prefix("ARGV\t"))
        .collect();
    assert_eq!(
        argv,
        vec!["fixed", "prefix", "has spaces", "a\"quote", "$HOME"],
        "argv elements must arrive verbatim, no shell interpolation"
    );

    // ---- env: parse `env` output into a key set.
    let mut keys: Vec<String> = env_part
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string()))
        .collect();
    keys.sort();
    keys.dedup();

    // The injected secret is present under its env var, with the exact value.
    let injected = env_part
        .lines()
        .find_map(|l| l.strip_prefix("INJECTED_TOKEN="))
        .expect("secret must be injected as INJECTED_TOKEN");
    assert_eq!(injected, "s3cr3t-EXAMPLE-value");

    // PATH is exactly the fixed minimal PATH.
    let path = env_part
        .lines()
        .find_map(|l| l.strip_prefix("PATH="))
        .expect("PATH must be set");
    assert_eq!(path, "/usr/bin:/bin");

    // The child env must be EXACTLY baseline + env.set + secret. We check this
    // two ways, because the observation channel (`env` run *inside* /bin/sh)
    // adds a few shell-internal names (`PWD`, `SHLVL`, `_`) that kpexec never
    // set — those are the shell's, not a parent-env leak.
    //
    // (1) The allowed kpexec-set keys are all present.
    let allowed_kpexec = {
        let mut a: Vec<String> = ["HOME", "TMPDIR", "LANG"]
            .into_iter()
            .filter(|k| std::env::var(k).is_ok())
            .map(str::to_string)
            .collect();
        a.extend(
            ["PATH", "EXTRA_ONE", "EXTRA_TWO", "INJECTED_TOKEN"]
                .into_iter()
                .map(str::to_string),
        );
        a
    };
    for k in &allowed_kpexec {
        assert!(keys.contains(k), "expected env var {k} to be present");
    }

    // (2) Nothing beyond the allowed kpexec keys plus the shell's own internals
    // leaked. In particular, parent-process vars (CARGO_*, USER, and the canary
    // below) must be absent — proving `env_clear()` took effect.
    let shell_internal = ["PWD", "SHLVL", "_"];
    let stray: Vec<&String> = keys
        .iter()
        .filter(|k| !allowed_kpexec.contains(k) && !shell_internal.contains(&k.as_str()))
        .collect();
    assert!(
        stray.is_empty(),
        "child env leaked non-baseline keys: {stray:?}"
    );

    // The canary is set in this parent process but must NOT reach the child.
    assert!(
        std::env::var("KPEXEC_A3_CANARY").is_ok(),
        "test bug: canary should be set in the parent"
    );
    assert!(
        !keys.contains(&"KPEXEC_A3_CANARY".to_string()),
        "a parent env var reached the child — env_clear() failed"
    );
}

// ---------------------------------------------------------------------------
// pin verification
// ---------------------------------------------------------------------------

#[test]
fn pin_mismatch_rejects_without_executing() {
    let h = Harness::new();
    let marker = h.dir.join("RAN");
    let exe = h.script(
        "t.sh",
        &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    );
    h.add_entry(
        "e",
        "s3cr3t-EXAMPLE",
        "TOKEN",
        &exe,
        &["p"],
        true,
        None,
        None,
    );

    // Tamper the target after pinning.
    std::fs::write(&exe, "#!/bin/sh\necho tampered\n").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut args = h.run_args("e", "cmd");
    args.json = true;
    let r = h.run(&args, &default_opts());
    assert_eq!(r.json()["kpexec_status"], "exe-hash-mismatch");
    assert_eq!(r.ok().exit_code(), 103);
    assert!(
        !marker.exists(),
        "a hash mismatch must not execute the child"
    );
}

#[test]
fn unpinned_runs_with_warning() {
    let h = Harness::new();
    let exe = h.script("t.sh", "#!/bin/sh\nexit 0\n");
    h.add_entry(
        "e",
        "s3cr3t-EXAMPLE",
        "TOKEN",
        &exe,
        &["p"],
        false,
        None,
        None,
    );

    let args = h.run_args("e", "cmd");
    let r = h.run(&args, &default_opts());
    assert_eq!(r.ok(), Outcome::ChildExit(0));
    assert!(
        r.stderr.contains("unpinned"),
        "an unpinned command must warn on stderr: {:?}",
        r.stderr
    );
}

// ---------------------------------------------------------------------------
// A6 — exit code propagation
// ---------------------------------------------------------------------------

#[test]
fn a6_child_exit_code_propagated() {
    let h = Harness::new();
    let exe = h.script("seven.sh", "#!/bin/sh\nexit 7\n");
    h.add_entry("e", "s3cr3t-EXAMPLE", "TOKEN", &exe, &[], true, None, None);

    let r = h.run(&h.run_args("e", "cmd"), &default_opts());
    assert_eq!(r.ok(), Outcome::ChildExit(7));
}

#[test]
fn a6_signal_killed_child_is_128_plus_n() {
    let h = Harness::new();
    // The child kills itself with SIGKILL (9) -> exit code should be 128+9=137.
    let exe = h.script("selfkill.sh", "#!/bin/sh\nkill -9 $$\n");
    h.add_entry("e", "s3cr3t-EXAMPLE", "TOKEN", &exe, &[], true, None, None);

    let r = h.run(&h.run_args("e", "cmd"), &default_opts());
    assert_eq!(r.ok(), Outcome::ChildExit(137));
}

// ---------------------------------------------------------------------------
// A7 — timeout
// ---------------------------------------------------------------------------

#[test]
fn a7_timeout_sigterm_terminates_and_returns_partial_output() {
    let h = Harness::new();
    // Emits a line, then sleeps; default SIGTERM handling kills it promptly. The
    // partial line goes to stderr, which C stdio leaves unbuffered, so it is
    // reliably flushed to the pipe before the child blocks in `sleep` — proving
    // captured-so-far output survives the timeout kill.
    let exe = h.script(
        "sleeper.sh",
        "#!/bin/sh\necho partial-line 1>&2\nsleep 30\n",
    );
    h.add_entry("e", "s3cr3t-EXAMPLE", "TOKEN", &exe, &[], true, None, None);

    let mut args = h.run_args("e", "cmd");
    args.json = true;
    // A generous-but-still-short timeout: long enough that the shell reliably
    // reaches the `echo` (even under parallel-test CPU contention) before the
    // deadline, short enough that the run doesn't stall the suite. The `sleep 30`
    // guarantees the timeout fires regardless.
    let opts = fast_opts(Duration::from_secs(1), Duration::from_secs(2));

    let r = h.run(&args, &opts);
    // Timeout -> kpexec-level status (exit 106), not the child's code.
    assert_eq!(r.ok(), Outcome::Kpexec(KpexecStatus::Timeout));

    let v = r.json();
    assert_eq!(v["kpexec_status"], "timeout");
    assert!(
        v["stderr"].as_str().unwrap().contains("partial-line"),
        "captured-so-far output must be returned on timeout"
    );
    // Killed by SIGTERM (15) -> child_exit_code 128+15 = 143.
    assert_eq!(v["child_exit_code"], 143);
}

#[test]
fn a7_sigterm_trapping_child_is_sigkilled_after_grace() {
    let h = Harness::new();
    // Traps (ignores) SIGTERM and sleeps. kpexec must escalate to SIGKILL after
    // the grace. SIGKILL (9) -> 128+9 = 137. The timeout must be generous enough
    // that the `trap` builtin is reliably installed before SIGTERM is sent —
    // otherwise (under parallel-test contention) an early SIGTERM would lawfully
    // kill the not-yet-trapping shell with 143, which is correct kpexec behavior
    // but not what this test means to exercise.
    let exe = h.script(
        "stubborn.sh",
        "#!/bin/sh\ntrap '' TERM\necho alive\nsleep 30\n",
    );
    h.add_entry("e", "s3cr3t-EXAMPLE", "TOKEN", &exe, &[], true, None, None);

    let mut args = h.run_args("e", "cmd");
    args.json = true;
    let opts = fast_opts(Duration::from_secs(1), Duration::from_millis(400));

    let r = h.run(&args, &opts);
    assert_eq!(r.ok(), Outcome::Kpexec(KpexecStatus::Timeout));

    let v = r.json();
    assert_eq!(v["kpexec_status"], "timeout");
    assert_eq!(
        v["child_exit_code"], 137,
        "a SIGTERM-trapping child must be SIGKILLed after the grace"
    );
}

// ---------------------------------------------------------------------------
// stdin closed
// ---------------------------------------------------------------------------

#[test]
fn stdin_is_closed_child_reads_eof() {
    let h = Harness::new();
    // Reads stdin; with a closed stdin it gets immediate EOF and prints EOF-OK.
    // If stdin were inherited this could block, so a clean exit proves closure.
    let exe = h.script(
        "reader.sh",
        "#!/bin/sh\nhead -c 100 >/dev/null 2>&1 && echo EOF-OK\n",
    );
    h.add_entry("e", "s3cr3t-EXAMPLE", "TOKEN", &exe, &[], true, None, None);

    let opts = fast_opts(Duration::from_secs(5), Duration::from_secs(2));
    let r = h.run(&h.run_args("e", "cmd"), &opts);
    assert_eq!(r.ok(), Outcome::ChildExit(0));
    assert!(
        r.stdout.contains("EOF-OK"),
        "child should see stdin EOF: {:?}",
        r.stdout
    );
}

// ---------------------------------------------------------------------------
// byte-limit truncation
// ---------------------------------------------------------------------------

#[test]
fn byte_limit_truncates_with_marker() {
    let h = Harness::new();
    let exe = h.script("chatty.sh", "#!/bin/sh\nprintf 'AAAAAAAAAAAAAAAAAAAA'\n");
    h.add_entry(
        "e",
        "s3cr3t-EXAMPLE",
        "TOKEN",
        &exe,
        &[],
        true,
        None,
        Some(OutputSpec {
            max_stdout_bytes: 5,
            max_stderr_bytes: 100,
        }),
    );

    let mut args = h.run_args("e", "cmd");
    args.json = true;
    let r = h.run(&args, &default_opts());
    assert_eq!(r.ok(), Outcome::ChildExit(0));

    let v = r.json();
    let child_stdout = v["stdout"].as_str().unwrap();
    assert!(child_stdout.starts_with("AAAAA"));
    assert!(
        child_stdout.contains("truncated"),
        "truncation marker expected: {child_stdout:?}"
    );
    // Only 5 payload 'A's survive (the marker itself has none).
    let payload = child_stdout.split("\n[kpexec]").next().unwrap();
    assert_eq!(payload.matches('A').count(), 5);
}

// ---------------------------------------------------------------------------
// --json success envelope shape
// ---------------------------------------------------------------------------

#[test]
fn json_success_envelope_shape() {
    let h = Harness::new();
    let exe = h.script(
        "hi.sh",
        "#!/bin/sh\necho out-line\necho err-line 1>&2\nexit 0\n",
    );
    h.add_entry("e", "s3cr3t-EXAMPLE", "TOKEN", &exe, &[], true, None, None);

    let mut args = h.run_args("e", "cmd");
    args.json = true;
    let r = h.run(&args, &default_opts());
    assert_eq!(r.ok(), Outcome::ChildExit(0));

    let v = r.json();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 4, "envelope has exactly four keys");
    assert_eq!(v["kpexec_status"], "success");
    assert_eq!(v["child_exit_code"], 0);
    assert!(v["stdout"].as_str().unwrap().contains("out-line"));
    assert!(v["stderr"].as_str().unwrap().contains("err-line"));
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Insert an entry whose policy JSON is provided verbatim (to simulate a
/// KeePassXC hand-edit the run path must reject).
fn insert_raw_policy(h: &Harness, id: &str, policy_json: &str, secret: &str) {
    use keepass::db::fields;
    use keepass::{Database, DatabaseKey};

    let master = h.master.expose().to_string();
    let mut file = std::fs::File::open(&h.vault_path).unwrap();
    let mut db = Database::open(&mut file, DatabaseKey::new().with_password(&master)).unwrap();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, id);
        entry.set_protected(fields::PASSWORD, secret);
        entry.set_unprotected("kpexec.id", id);
        entry.set_unprotected("kpexec.policy.v1", policy_json);
    }
    db.config.version = keepass::config::DatabaseVersion::KDB4(1);
    let tmp = h.vault_path.with_extension("kdbx.tmp");
    {
        let mut out = std::fs::File::create(&tmp).unwrap();
        db.save(&mut out, DatabaseKey::new().with_password(&master))
            .unwrap();
    }
    std::fs::rename(&tmp, &h.vault_path).unwrap();
}
