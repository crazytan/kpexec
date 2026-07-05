//! `kpexec run` — the run path (M4). The most security-critical code in the
//! project: argv and env construction *is* the security boundary.
//!
//! This module implements security-design invariants 1–7. In one place, in the
//! documented order, it:
//!
//! 1. **Resolves** the request: open the vault (identity-bound), find the entry
//!    by `kpexec.id` (unknown-entry → 100), find the command template by name
//!    (unknown-command → 101), parse the policy (malformed-policy → 102). Deny
//!    by default on every failure (invariant 1).
//! 2. **Verifies the pin** (invariant 4/5): canonicalize `command.exe` (absolute,
//!    exists, regular file, executable — else reject), then hash the canonical
//!    target's bytes *immediately before spawn* and compare to `exe_sha256`.
//!    Mismatch → exe-hash-mismatch (103). An unpinned command (`--no-pin`) runs
//!    but prints a WARN line.
//! 3. **Builds argv** (invariants 2/3): exactly `[canonical_exe] + argv_prefix +
//!    trailing_args`, each element passed verbatim — no shell, no interpolation.
//! 4. **Builds the child env from scratch** (invariants 6/7): `env_clear()`, then
//!    HOME/TMPDIR/LANG passed through if set, a fixed `PATH=/usr/bin:/bin`, the
//!    policy `env.set` entries, and finally the injected secret var. Nothing
//!    else is inherited. cwd inherits the caller's; stdin is closed.
//! 5. **Spawns**, capturing stdout/stderr fully buffered, then redacting them
//!    (invariant 10, in [`crate::output`]: mask the secret and its variant forms,
//!    fail closed if any survive), enforcing the timeout (SIGTERM → SIGKILL after
//!    a grace period), and propagating the child's exit code verbatim (signals as
//!    128+N, shell convention).
//!
//! Every path — success or rejection, dry-run or spawn — logs exactly once via
//! [`crate::logging::log_run_result`] with an argv hash over the *full* final
//! argv, and never logs raw args or the secret.
//!
//! # The no-secret-on-dry-run guarantee
//!
//! The secret is read only by [`Vault::read_secret`], and that call lives on a
//! single line in [`spawn_and_wait`], reachable only after the `--dry-run`
//! early-return. Resolution ([`resolve`]) and pin verification never touch the
//! Password field. So `--dry-run` structurally cannot read the secret — it is
//! not a matter of an untaken branch inside the spawn code, it is a call the
//! dry-run path never reaches.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::cli::RunArgs;
use crate::error::{KpexecError, Result};
use crate::keychain::KeychainStore;
use crate::logging;
use crate::output::{self, Captured};
use crate::pin;
use crate::policy::{Command as PolicyCommand, EnvSpec, Policy};
use crate::secret::Secret;
use crate::status::{JsonEnvelope, KpexecStatus, Outcome};
use crate::vault::Vault;
use crate::{config, vaultctx};

/// The fixed minimal PATH given to every child (invariant 7).
const FIXED_PATH: &str = "/usr/bin:/bin";

/// Environment variables passed through from the parent *if set* (invariant 7).
const PASSTHROUGH_ENV: [&str; 3] = ["HOME", "TMPDIR", "LANG"];

/// Grace period between SIGTERM and SIGKILL on timeout (spec: 5 s). Overridable
/// internally so tests stay fast; the production path always uses this default.
const DEFAULT_KILL_GRACE: Duration = Duration::from_secs(5);

/// Where the run path writes child output and diagnostics.
///
/// Threading the two streams through the emit path (rather than using the
/// `println!`/`eprintln!` globals) keeps emission testable: production wires
/// the process's stdout/stderr, tests wire in-memory buffers so assertions are
/// deterministic and never depend on process-global FD state.
pub struct Emit<'a> {
    /// The "stdout" channel: child stdout (non-`--json`) or the JSON envelope.
    pub out: &'a mut dyn Write,
    /// The "stderr" channel: child stderr plus all `[kpexec]` diagnostics.
    pub err: &'a mut dyn Write,
}

impl<'a> Emit<'a> {
    /// Construct a sink over two writers.
    pub fn new(out: &'a mut dyn Write, err: &'a mut dyn Write) -> Self {
        Emit { out, err }
    }
}

/// Production entry point for `kpexec run`.
pub fn run(args: RunArgs) -> Result<Outcome> {
    let cfg = config::load()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    let opts = RunOptions {
        timeout: effective_timeout(&args, &cfg),
        kill_grace: DEFAULT_KILL_GRACE,
    };
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let mut emit = Emit::new(&mut out, &mut err);
    run_with(
        &args,
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
        &opts,
        &mut emit,
    )
}

/// Tunables the production path fixes but tests vary (fast timeouts/grace).
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    /// Wall-clock timeout for the child.
    pub timeout: Duration,
    /// SIGTERM → SIGKILL grace.
    pub kill_grace: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            timeout: Duration::from_secs(config::DEFAULT_TIMEOUT_SEC),
            kill_grace: DEFAULT_KILL_GRACE,
        }
    }
}

/// The effective timeout: `--timeout` overrides the config default.
fn effective_timeout(args: &RunArgs, cfg: &config::Config) -> Duration {
    let secs = args.timeout.unwrap_or(cfg.default_timeout_sec);
    Duration::from_secs(secs)
}

/// Testable core of `run`: everything but which config/keychain to consult.
///
/// The flow is deliberately linear so the security-critical ordering is visible:
/// resolve → verify pin → (dry-run stops here) → read secret → build env →
/// spawn. Every exit point routes through [`emit`], which logs exactly once.
pub fn run_with(
    args: &RunArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
    opts: &RunOptions,
    emit: &mut Emit<'_>,
) -> Result<Outcome> {
    // ---- resolve (no secret touched) --------------------------------------
    let resolved = match resolve(
        vault_path,
        keychain,
        config_hint,
        &args.entry,
        &args.command,
    ) {
        Ok(r) => r,
        Err(err) => {
            // A resolution failure may occur before we know the canonical exe;
            // log with what we have (the argv is not yet known, so hash the
            // request shape: entry + command only would leak nothing useful, so
            // we hash an empty argv placeholder — the status carries the reason).
            return emit_error(
                emit,
                args,
                &args.entry,
                &args.command,
                Path::new(""),
                &[],
                err,
            );
        }
    };

    let Resolved {
        vault,
        policy,
        command,
    } = resolved;

    // ---- verify the pin (invariant 4/5) -----------------------------------
    let verified = match verify_exe(&command) {
        Ok(v) => v,
        Err(err) => {
            let argv = build_argv(
                Path::new(&command.exe),
                &command.argv_prefix,
                &args.trailing,
            );
            return emit_error(
                emit,
                args,
                &args.entry,
                &args.command,
                Path::new(&command.exe),
                &argv,
                err,
            );
        }
    };
    let canonical_exe = verified.canonical.clone();

    // The full, final argv — used for the audit hash on EVERY remaining path.
    let argv = build_argv(&canonical_exe, &command.argv_prefix, &args.trailing);

    if verified.unpinned {
        let _ = writeln!(
            emit.err,
            "[kpexec] WARNING: command {:?} is unpinned (--no-pin) - executable bytes are not verified",
            command.name
        );
    }

    // ---- dry-run stops here: NO secret read, NO subprocess ----------------
    if args.dry_run {
        return emit_dry_run(
            emit,
            args,
            &args.entry,
            &args.command,
            &canonical_exe,
            &argv,
        );
    }

    // ---- spawn path -------------------------------------------------------
    match spawn_and_wait(&vault, &args.entry, &policy, &canonical_exe, &argv, opts) {
        Ok(spawned) => emit_spawned(
            emit,
            args,
            &args.entry,
            &args.command,
            &canonical_exe,
            &argv,
            spawned,
        ),
        Err(err) => emit_error(
            emit,
            args,
            &args.entry,
            &args.command,
            &canonical_exe,
            &argv,
            err,
        ),
    }
}

// ---------------------------------------------------------------------------
// Resolution (invariant 1) — never touches the secret
// ---------------------------------------------------------------------------

/// The resolved request: an opened vault plus the selected policy + command.
struct Resolved {
    vault: Vault,
    policy: Policy,
    command: PolicyCommand,
}

/// Open the vault and resolve entry → command → policy. Deny by default: an
/// unknown entry, unknown command, or malformed policy each rejects with the
/// matching status. Reads no secret.
fn resolve(
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
    entry_id: &str,
    command_name: &str,
) -> Result<Resolved> {
    let vault = Vault::open(vault_path, keychain, config_hint)?;
    // find_entry already maps a missing policy / bad JSON / duplicate id to
    // MalformedPolicy, and returns Ok(None) for an absent id.
    let view = vault.find_entry(entry_id)?.ok_or_else(|| {
        KpexecError::new(
            KpexecStatus::UnknownEntry,
            format!("no entry with id {entry_id:?}"),
        )
    })?;
    let command = view.policy.command(command_name).cloned().ok_or_else(|| {
        KpexecError::new(
            KpexecStatus::UnknownCommand,
            format!("entry {entry_id:?} has no command {command_name:?}"),
        )
    })?;
    Ok(Resolved {
        vault,
        policy: view.policy,
        command,
    })
}

// ---------------------------------------------------------------------------
// Pin verification (invariants 4 & 5)
// ---------------------------------------------------------------------------

/// A verified executable: its canonical path and whether it was unpinned.
#[derive(Debug)]
struct Verified {
    canonical: PathBuf,
    unpinned: bool,
}

/// Canonicalize + validate the executable, then (if pinned) hash it and compare
/// to `exe_sha256` — the hash is the *last* thing done before the caller spawns,
/// to minimize the TOCTOU window.
///
/// Canonicalization + regular-file check comes from [`pin::compute`], which also
/// produces the fresh hash; we additionally require the target to be executable.
fn verify_exe(command: &PolicyCommand) -> Result<Verified> {
    let fresh = pin::compute(&command.exe)?;

    if !is_executable(&fresh.canonical) {
        return Err(KpexecError::new(
            KpexecStatus::MalformedPolicy,
            format!("{} is not executable", fresh.canonical.display()),
        ));
    }

    match &command.exe_sha256 {
        Some(recorded) => {
            if !fresh.sha256.eq_ignore_ascii_case(recorded) {
                return Err(KpexecError::new(
                    KpexecStatus::ExeHashMismatch,
                    format!(
                        "executable {} has changed since it was pinned; run `kpexec entry repin` to re-approve it",
                        fresh.canonical.display()
                    ),
                ));
            }
            Ok(Verified {
                canonical: fresh.canonical,
                unpinned: false,
            })
        }
        None => Ok(Verified {
            canonical: fresh.canonical,
            unpinned: true,
        }),
    }
}

/// Whether the file has any execute bit set (owner/group/other). On Unix we read
/// the mode; the canonicalized path is already known to be a regular file.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    // Non-Unix: no mode bits to check; the regular-file check in `pin::compute`
    // is the best we can do. The run path targets Unix.
    true
}

// ---------------------------------------------------------------------------
// argv & env construction (invariants 2, 3, 6, 7)
// ---------------------------------------------------------------------------

/// Build the full argv exactly as `[canonical_exe] + argv_prefix + trailing`,
/// each element verbatim. This is the single argv-construction site; the audit
/// hash and both the dry-run print and the real spawn all use its output.
fn build_argv(canonical_exe: &Path, argv_prefix: &[String], trailing: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(1 + argv_prefix.len() + trailing.len());
    argv.push(canonical_exe.to_string_lossy().into_owned());
    argv.extend(argv_prefix.iter().cloned());
    argv.extend(trailing.iter().cloned());
    argv
}

/// Configure a `Command`'s environment from scratch per invariants 6 & 7.
///
/// Order: clear everything, pass through HOME/TMPDIR/LANG if present in the
/// parent, set the fixed PATH, apply the policy `env.set` block, then inject the
/// secret last. The secret is exposed exactly once, here, at the single
/// injection point, and is not retained beyond this call.
fn apply_env(cmd: &mut Command, env: Option<&EnvSpec>, inject_name: &str, secret: &Secret) {
    cmd.env_clear();

    for name in PASSTHROUGH_ENV {
        if let Ok(value) = std::env::var(name) {
            cmd.env(name, value);
        }
    }
    cmd.env("PATH", FIXED_PATH);

    if let Some(env) = env {
        for (k, v) in &env.set {
            cmd.env(k, v);
        }
    }

    // The one and only injection point (invariant 6).
    cmd.env(inject_name, secret.expose());
}

// ---------------------------------------------------------------------------
// Spawn + timeout + capture
// ---------------------------------------------------------------------------

/// The result of a completed (or timed-out) child run.
struct Spawned {
    /// Child exit code, already mapped (signal N → 128+N; timeout → the killing
    /// signal's 128+N as well). This is what kpexec propagates.
    child_exit_code: i32,
    /// Whether the child was killed for exceeding the timeout.
    timed_out: bool,
    /// Fully processed (byte-limited) output.
    processed: output::Processed,
}

/// Read the secret, build the command, spawn it, and drive it to completion or
/// timeout. This is the ONLY function that reads the secret (see the module
/// docs' no-secret-on-dry-run guarantee).
fn spawn_and_wait(
    vault: &Vault,
    entry_id: &str,
    policy: &Policy,
    canonical_exe: &Path,
    argv: &[String],
    opts: &RunOptions,
) -> Result<Spawned> {
    // >>> The single secret read on the entire run path. <<<
    let secret = vault.read_secret(entry_id)?;

    let mut cmd = Command::new(canonical_exe);
    // argv[0] is the exe itself; the rest are the actual arguments.
    cmd.args(&argv[1..]);
    apply_env(
        &mut cmd,
        policy.env.as_ref(),
        &policy.secret.inject.name,
        &secret,
    );
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Put the child in its own process group (it becomes the group leader, so
    // pgid == pid). On timeout we signal the whole group, not just the direct
    // child: a shell target spawns grandchildren (e.g. `sleep`) that inherit the
    // stdout/stderr pipes, so signalling only the leader would leave them alive,
    // holding the pipes open and blocking our readers until they exit on their
    // own — defeating the timeout. Signalling the group tears down the whole
    // tree and closes the pipes promptly. (invariant: bounded, enforceable
    // timeout.)
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }

    let mut child = cmd.spawn().map_err(|e| {
        KpexecError::new(
            KpexecStatus::Internal,
            format!("failed to spawn {}: {e}", canonical_exe.display()),
        )
    })?;

    // The secret is now in the child's environment. We keep our copy alive only
    // until output redaction has run ([`output::process`] needs it to compute the
    // variant forms it scans for); it is dropped immediately after, and is
    // zeroized on drop. It is NEVER stored beyond this function.

    // Read stdout/stderr on separate threads so a chatty child cannot deadlock on
    // a full pipe buffer while we wait for exit.
    let stdout_handle = child.stdout.take().map(spawn_reader);
    let stderr_handle = child.stderr.take().map(spawn_reader);

    // Wait for exit on a helper thread so the main thread can enforce a timeout
    // while retaining the pid for signalling. The waiter owns `child`, calls
    // `wait()` (which reaps the process and closes its pipes), and returns the
    // real `ExitStatus` — even after we SIGTERM/SIGKILL it, so the propagated
    // exit code always reflects what actually happened (128+signal).
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let r = child.wait();
        let _ = tx.send(());
        r
    });

    let timed_out = match rx.recv_timeout(opts.timeout) {
        // Child exited (or the send happened) within the timeout.
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => false,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SIGTERM the whole process group, wait up to the grace period, then
            // SIGKILL the group if the direct child is still alive.
            signal_group(pid, libc_sigterm());
            if rx.recv_timeout(opts.kill_grace).is_err() {
                signal_group(pid, libc_sigkill());
            }
            true
        }
    };

    // Join the waiter for the authoritative exit status (post-kill on timeout).
    let status = waiter
        .join()
        .map_err(|_| KpexecError::new(KpexecStatus::Internal, "waiter thread panicked"))?
        .map_err(|e| KpexecError::new(KpexecStatus::Internal, format!("wait failed: {e}")))?;

    // Join reader threads (children have exited or been killed, so pipes close).
    let stdout = join_reader(stdout_handle);
    let stderr = join_reader(stderr_handle);

    // Redaction runs here, while the secret is still in scope. `process` exposes
    // the secret only to compute its variant forms; it stores nothing.
    let processed = output::process(Captured { stdout, stderr }, &policy.output, &secret);
    // Done with the secret: drop (and zeroize) it before returning.
    drop(secret);
    let child_exit_code = exit_code_of(&status);

    Ok(Spawned {
        child_exit_code,
        timed_out,
        processed,
    })
}

/// Spawn a thread that reads a pipe to EOF, returning the bytes.
fn spawn_reader<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

/// Join a reader thread (or return empty bytes if there was no pipe).
fn join_reader(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    handle
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default()
}

/// Signal the child's entire process group.
///
/// The child was spawned as a group leader (`process_group(0)`), so its pgid
/// equals its pid; `kill(-pgid, sig)` delivers `sig` to every process in that
/// group — the child and any descendants it forked (a shell's `sleep`, etc.).
/// This is what makes the timeout enforceable even against targets that spawn
/// long-running grandchildren holding the output pipes open.
#[cfg(unix)]
fn signal_group(pid: u32, sig: i32) {
    // SAFETY: kill(2) with a negated pid (process group) and a valid signal
    // number; failure (e.g. the group already fully reaped) is ignored — it
    // means the job is already done.
    unsafe {
        let _ = libc::kill(-(pid as libc::pid_t), sig);
    }
}

#[cfg(not(unix))]
fn signal_group(_pid: u32, _sig: i32) {}

#[cfg(unix)]
fn libc_sigterm() -> i32 {
    libc::SIGTERM
}
#[cfg(unix)]
fn libc_sigkill() -> i32 {
    libc::SIGKILL
}
#[cfg(not(unix))]
fn libc_sigterm() -> i32 {
    15
}
#[cfg(not(unix))]
fn libc_sigkill() -> i32 {
    9
}

/// Map a completed child's status to the exit code kpexec propagates.
///
/// Normal exit → the child's code. Killed by signal N → 128+N (shell
/// convention), so a caller can tell "exited 3" from "killed by SIGTERM (143)".
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(1)
}

// ---------------------------------------------------------------------------
// Result emission (single-log discipline)
// ---------------------------------------------------------------------------

/// Emit a successful/timed-out spawn result and log exactly once.
fn emit_spawned(
    emit: &mut Emit<'_>,
    args: &RunArgs,
    entry_id: &str,
    command_name: &str,
    canonical_exe: &Path,
    argv: &[String],
    spawned: Spawned,
) -> Result<Outcome> {
    // Status precedence: fail-closed redaction (105) wins over timeout (106) and
    // success — if secret material survived, the run is a redaction failure
    // regardless of how the child exited. Timeout then outranks success.
    let status = if spawned.processed.redaction_failed {
        KpexecStatus::RedactionFailure
    } else if spawned.timed_out {
        KpexecStatus::Timeout
    } else {
        KpexecStatus::Success
    };
    logging::log_run_result(
        entry_id,
        command_name,
        canonical_exe,
        &logging::argv_hash(argv),
        status,
    );

    let child_code = spawned.child_exit_code;
    let out = &spawned.processed;

    if args.json {
        // On timeout, the child_exit_code reflects the killing signal (128+N). On
        // redaction failure the child's real exit code is still reported here,
        // while stdout/stderr carry only the suppression line (never the secret).
        let envelope = JsonEnvelope {
            kpexec_status: status,
            child_exit_code: Some(child_code),
            stdout: out.stdout.clone(),
            stderr: out.stderr.clone(),
        };
        let _ = writeln!(emit.out, "{}", envelope.to_json());
    } else {
        // Child streams go to the corresponding kpexec streams verbatim. On
        // fail-closed suppression both `out.stdout` and `out.stderr` are the
        // single suppression line, so nothing sensitive is emitted.
        let _ = write!(emit.out, "{}", out.stdout);
        let _ = write!(emit.err, "{}", out.stderr);
        if spawned.timed_out {
            let _ = writeln!(emit.err, "[kpexec] child timed out and was terminated");
        }
    }

    // Exit-code precedence mirrors the status:
    // * redaction failure -> the 105 band (defense-in-depth: the run failed even
    //   though the child may have exited 0);
    // * timeout -> the 106 band (kpexec killed it, distinguishable from a child
    //   that chose to exit);
    // * otherwise -> propagate the child's own exit code verbatim.
    if spawned.processed.redaction_failed {
        Ok(Outcome::Kpexec(KpexecStatus::RedactionFailure))
    } else if spawned.timed_out {
        Ok(Outcome::Kpexec(KpexecStatus::Timeout))
    } else {
        Ok(Outcome::ChildExit(child_code))
    }
}

/// Emit a `--dry-run`: print the exact argv, log, return success. No secret, no
/// subprocess.
fn emit_dry_run(
    emit: &mut Emit<'_>,
    args: &RunArgs,
    entry_id: &str,
    command_name: &str,
    canonical_exe: &Path,
    argv: &[String],
) -> Result<Outcome> {
    logging::log_run_result(
        entry_id,
        command_name,
        canonical_exe,
        &logging::argv_hash(argv),
        KpexecStatus::Success,
    );
    if args.json {
        // The argv is surfaced in stdout of the envelope so agents can inspect
        // it; no child ran, so child_exit_code is null.
        let envelope = JsonEnvelope {
            kpexec_status: KpexecStatus::Success,
            child_exit_code: None,
            stdout: render_argv(argv),
            stderr: String::new(),
        };
        let _ = writeln!(emit.out, "{}", envelope.to_json());
    } else {
        let _ = writeln!(
            emit.err,
            "[kpexec] entry {entry_id}, command {command_name}"
        );
        let _ = writeln!(emit.out, "[kpexec] dry-run argv:");
        for a in argv {
            let _ = writeln!(emit.out, "  {a}");
        }
    }
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

/// Emit a kpexec-level rejection and log exactly once. `argv` may be empty when
/// the failure occurred before the argv was known (resolution failure).
#[allow(clippy::too_many_arguments)]
fn emit_error(
    emit: &mut Emit<'_>,
    args: &RunArgs,
    entry_id: &str,
    command_name: &str,
    canonical_exe: &Path,
    argv: &[String],
    err: KpexecError,
) -> Result<Outcome> {
    logging::log_run_result(
        entry_id,
        command_name,
        canonical_exe,
        &logging::argv_hash(argv),
        err.status(),
    );
    if args.json {
        let envelope =
            JsonEnvelope::kpexec_with_stderr(err.status(), format!("[kpexec] {}", err.message()));
        let _ = writeln!(emit.out, "{}", envelope.to_json());
        Ok(Outcome::Kpexec(err.status()))
    } else {
        // Let `main` print the `[kpexec] ...` line and set the exit code.
        Err(err)
    }
}

/// Render an argv as a single, newline-free line for the JSON envelope's stdout.
/// Each element is shown on its own space-separated token; this is informational
/// only (never re-parsed) and never contains the secret.
fn render_argv(argv: &[String]) -> String {
    argv.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(exe: &str, prefix: &[&str], hash: Option<&str>) -> PolicyCommand {
        PolicyCommand {
            name: "c".into(),
            exe: exe.into(),
            exe_sha256: hash.map(str::to_string),
            argv_prefix: prefix.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn argv_is_exe_prefix_trailing_verbatim() {
        let exe = Path::new("/usr/bin/tool");
        let argv = build_argv(
            exe,
            &["pr".into(), "create".into()],
            &["--title".into(), "has spaces".into(), "$HOME".into()],
        );
        assert_eq!(
            argv,
            vec![
                "/usr/bin/tool",
                "pr",
                "create",
                "--title",
                "has spaces",
                "$HOME"
            ]
        );
    }

    #[test]
    fn env_is_built_from_scratch() {
        let mut c = Command::new("/bin/true");
        let env = EnvSpec {
            set: std::collections::BTreeMap::from([("EXTRA".to_string(), "1".to_string())]),
        };
        apply_env(&mut c, Some(&env), "TOKEN", &Secret::new("s3cr3t".into()));
        // The Command's env map should contain exactly our keys plus any of the
        // passthrough vars that happen to be set in this test process.
        let mut keys: Vec<String> = c
            .get_envs()
            .filter_map(|(k, v)| v.map(|_| k.to_string_lossy().into_owned()))
            .collect();
        keys.sort();
        assert!(keys.contains(&"PATH".to_string()));
        assert!(keys.contains(&"EXTRA".to_string()));
        assert!(keys.contains(&"TOKEN".to_string()));
        // No stray parent var leaks: pick one that is almost certainly set in
        // the parent but not in our allowlist.
        assert!(!keys.contains(&"CARGO".to_string()) || std::env::var("CARGO").is_err());
    }

    #[test]
    fn verify_rejects_missing_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\ntrue\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Wrong recorded hash → ExeHashMismatch.
        let c = cmd(exe.to_str().unwrap(), &[], Some("deadbeef"));
        let err = verify_exe(&c).unwrap_err();
        assert_eq!(err.status(), KpexecStatus::ExeHashMismatch);
    }

    #[test]
    fn verify_accepts_matching_hash() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\ntrue\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let good = pin::compute(exe.to_str().unwrap()).unwrap().sha256;
        let c = cmd(exe.to_str().unwrap(), &[], Some(&good));
        let v = verify_exe(&c).unwrap();
        assert!(!v.unpinned);
    }

    #[test]
    fn verify_flags_unpinned() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\ntrue\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let c = cmd(exe.to_str().unwrap(), &[], None);
        let v = verify_exe(&c).unwrap();
        assert!(v.unpinned);
    }

    #[test]
    fn verify_rejects_non_executable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("data");
        std::fs::write(&exe, b"not a program").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o644)).unwrap();
            let c = cmd(exe.to_str().unwrap(), &[], None);
            let err = verify_exe(&c).unwrap_err();
            assert_eq!(err.status(), KpexecStatus::MalformedPolicy);
        }
    }
}
