# Coding-agent guide

This guide is the operational map for agents changing kpexec. The normative
security claims and limitations live in [security.md](security.md); the design
and execution model live in [design.md](design.md); release handling lives in
[release.md](release.md).

## Purpose and adversary

kpexec lets a coding agent invoke a small set of commands with a credential
injected into the child environment without giving the credential to the agent.
Its primary adversary is an agent influenced by prompt injection and equipped
with a shell on the user's Mac. The agent may control the checkout, arguments,
current directory, configuration, environment, and subprocess output.

This is a constrained broker, not a sandbox. An approved policy may be invoked
repeatedly without per-run approval. Policy authors must therefore pin both the
executable and endpoint-sensitive fixed arguments. Rollback protection, local
malware resistance, and protection after vault-password disclosure are outside
the v1 guarantee. In particular, injecting a credential into a child environment
does **not** keep it confidential from an unrestricted same-UID process: an
ordinary `KERN_PROCARGS2` query (including `ps -E`/`ps eww`) can expose a
non-`CS_RESTRICT` child's initial environment without debugger access. Hardened
runtime separately limits some debugger/task-port access to memory; it does not
hide that environment. Never describe kpexec as a secret boundary against an
agent that has unrestricted same-user execution.

## Security boundary: preserve these properties

1. Resolve entry and command names strictly; malformed, duplicate, ambiguous,
   or unknown data fails closed.
2. Construct argv as the policy's absolute executable plus its fixed prefix and
   trailing argv. Never use a shell, interpolate a command string, or perform a
   `PATH` lookup.
3. Canonicalize and hash the executable before explicitly extracting the
   selected credential from the parsed vault.
   Pinned paths and every ancestor must be outside the current user's write and
   ownership control. `--no-pin` is an explicit, visible loss of protection.
4. Read the vault named by the ACL-protected Keychain record, not the untrusted
   config hint. Preserve exact code-requirement and singleton partition-list
   checks before protected bytes enter the process.
5. Gate every vault mutation, pin change, and recovery-password display with a
   local graphical Security-session preflight and LocalAuthentication. The gate
   must run before the handler touches Keychain, opens the vault, creates a lock,
   or writes state.
6. Inject the secret only as the policy-named child environment variable. The
   child receives the defined minimal environment and closed stdin; it does not
   inherit the caller's ambient credentials or execution hooks.
7. Buffer only bounded output, drain both pipes, redact exact and supported
   encoded forms before emission, and suppress output on a residual match.
   Redaction is defense in depth, not permission to run an unsafe command.
8. Never print, serialize, panic with, or log a secret or raw trailing argv.
   Audit through `logging::log_run_result`, which accepts only pre-approved
   fields and an argv hash.
9. Serialize vault writes, write a new KDBX 4.1 file to a nonempty temporary
   file, preserve the original across failure, then atomically replace it.
10. Keep production signing isolated. Mutable code and probes must never be
    signed into the Developer ID trust domain accepted by production Keychain
    access.

If a task appears to require weakening one of these properties, stop and make
the tradeoff explicit rather than implementing a shortcut.

## Repository map

| Area | Responsibility and review concern |
| --- | --- |
| `src/cli.rs`, `src/commands.rs` | CLI shape and the exhaustive authorization boundary. Every new command needs an explicit gated/ungated decision. |
| `src/cmd_run.rs`, `src/output.rs` | Resolve-before-selected-credential extraction, argv/env construction, child lifecycle, bounded capture, and fail-closed redaction. |
| `src/keychain.rs`, `src/vaultctx.rs` | Production identity, Keychain ACL/partition verification, and vault-path binding. Highest-risk trust boundary. |
| `src/user_presence.rs`, `src/user_presence_shim.m` | Local graphical-session rejection and LocalAuthentication bridge. Interactive platform validation is required. |
| `src/pin.rs`, `src/policy.rs` | Canonical executable hashes, immutable ancestry, strict versioned policy parsing, and unknown-field rejection. |
| `src/vault.rs`, `src/lock.rs`, `src/masterpw.rs`, `src/secret.rs` | KDBX lifecycle, atomic replacement, concurrency, recovery password, and zeroizing secret types. |
| `src/cmd_init.rs`, `src/cmd_entry.rs`, `src/cmd_db.rs` | User-authorized state changes. Maintain authorize-before-access ordering and backup safety. |
| `src/config.rs`, `src/paths.rs`, `src/doctor.rs`, `src/cmd_check.rs` | Untrusted hints, fixed local paths, and diagnostics. Warnings must not be confused with enforcement. |
| `src/logging.rs`, `src/status.rs`, `src/error.rs` | Secret-free audit schema and stable CLI/JSON failure semantics. |
| `tests/` | CLI, redaction, run-path, vault lifecycle, and supervised platform validation. Prefer behavior-level tests for security claims. |
| `tests/platform/` | Prompt-bearing Keychain and LocalAuthentication matrices. These isolated probes are not production entry points or a signing oracle. |
| `scripts/release.sh`, `scripts/test-release.sh` | Source-bound release build, package layout/signature/notarization verification, and parser defenses. |
| `.github/workflows/ci.yml` | Required macOS 15/Rust 1.96 and current-macOS/stable gates. Preserve required job names when branch protection depends on them. |

## Change procedure

Before editing:

```sh
git status --short --branch
git diff --check
cargo metadata --locked --no-deps --format-version 1 >/dev/null
```

Identify which invariant and acceptance case the change touches. Read the
complete relevant module and its tests, not just the target function. For a bug
or security fix, first add or identify a test that demonstrates the failure.
Use synthetic values only; never put a real token, vault password, signing key,
Keychain value, or identifying acceptance artifact in source or captured test
output. For changes to security behavior or security-facing documentation,
cross-check the adversary, guarantees, exclusions, and residual risks in
`docs/security.md`; explicitly preserve the same-UID process-inspection
limitation.

After editing, run the narrowest useful test while iterating, then the complete
non-interactive gate before handoff:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
RUST_LOG=warn cargo test --locked --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
./scripts/test-release.sh
git diff --check
```

CI additionally tests the release profile, the lockfile with RustSec, the
isolated platform-test trust domain, the Swift Keychain probe, Objective-C
warnings, ShellCheck, production framework linkage, and unsigned release preparation.
Run the matching commands from `.github/workflows/ci.yml` when changing those
areas. Do not describe CI as passing until the remote required checks have
finished successfully.

## Risk-triggered validation

- **CLI or mutation changes:** prove authorization denial happens before all
  access or mutation, and that every enum variant is classified exhaustively.
- **Policy, vault, or pinning changes:** test malformed/duplicate input, stale
  pins, writable ancestry, interrupted writes, backup behavior, and KeePassXC
  interoperability as applicable.
- **Runner or output changes:** test no-spawn failures, exact argv, minimal env,
  closed stdin, exit propagation, timeout escalation, output caps, every
  supported encoding, and absence of raw secrets from stdout, stderr, JSON, and
  logs.
- **Keychain or LocalAuthentication changes:** run the supervised T1–T5 and
  interactive-console/SSH matrices described in [testing.md](testing.md). These
  checks need a present user; do not automate approval or manufacture success.
- **Signing, identity, package, or deployment-target changes:** perform a clean,
  source-bound prepare, sign, notarize, staple, package verification, clean
  install, same-identity upgrade, `doctor`, and installed acceptance pass.

## Release constraints

The supported artifact is arm64 for macOS 15 or newer. The production binary
identifier is `dev.crazytan.kpexec`, Team ID `V82M9YX8BR`, and the installer
identifier is `dev.crazytan.kpexec.pkg`. A shippable binary must be built from an
exact clean commit, match the staged source-bound rebuild, use hardened runtime
and a secure timestamp, and be distributed only in a Developer ID Installer
package accepted and stapled by Apple's notarization service. The payload must
contain only the documented binary, README, and license with the verified
root-owned modes.

Never pass signing credentials through source, arguments, logs, or agent
context. `prepare` and `preflight` are the safe unattended stages. Credentialed
signing/notarization and interactive installed acceptance require explicit user
authorization. Preserve exact identities and package layout checks rather than
making the release script more permissive.

## Prohibited shortcuts

- No `sh -c`, shell-string construction, implicit `PATH` resolution, inherited
  ambient environment, open stdin, or executable supplied by the requester.
- No secret-bearing CLI flag, config value, fixture, snapshot, debug output,
  panic, tracing field, or raw argv audit record.
- No fallback from a failed ACL, signing, session, policy, canonicalization, or
  hash check to a warning-and-continue path.
- No direct truncate-in-place vault writes, silent parsing of unknown fields,
  or mutation before LocalAuthentication.
- No Developer ID signing of workspace binaries or general-purpose probe input.
- No deletion of a failing test, lowering of output checks, or broad ignore to
  hide a security regression.

## Cleanup and handoff

Keep source history useful: remove superseded experiments rather than leaving
dead branches in production paths, but preserve probes and evidence that are
still referenced by CI, the release runbook, or a security claim. Before
handoff, inspect `git status`, remove task-created build/package/vault scratch
data from the checkout, and verify no credential-shaped material entered the
diff. Do not delete user data, an installed release, durable release evidence,
or signing infrastructure under the label of cleanup.

Report the exact tests run, anything that remains supervised or unverified,
security behavior changed, and generated artifacts intentionally retained.
