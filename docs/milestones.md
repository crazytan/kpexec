# kpexec — Milestones & Acceptance Tests

## Milestone 0: de-risking validations (before feature code)

These validate assumptions the design leans on. If one fails, the design changes — so they come first.

1. **KDBX4 write round-trip: ✅ VALIDATED (2026-07-05,** `spikes/kdbx-roundtrip`**).** All legs pass with `keepass` 0.13.13 + KeePassXC 2.7.12, including repeated crate-save → KeePassXC-edit → crate-save ping-pong with custom fields and the protected password byte-intact. Two hard requirements fell out and are now in the CLI design's KDBX rules: (a) KeePassXC rewrites the file as KDBX 4.0 on every save while the crate's dumper only accepts 4.1, so every kpexec save must pin `DatabaseVersion::KDB4(1)`; (b) writes must be temp-file + rename — the naive truncate-in-place pattern destroyed the test vault when a save errored.
2. **Keychain ACL behavior for a CLI tool: ✅ VALIDATED (2026-08-15,**
   `spikes/keychain-acl`**).** T1–T4 proved silent genuine access, rejection of a
   differently signed reader, silent same-identity upgrade access, and rejection of an
   agent-planted `apple-tool:` item. T5 exercised the real Rust backend implementation's
   create, non-secret ACL verification, read, update, reread, and delete lifecycle with
   no dialog; cleanup confirmed the isolated item was absent. The original harnesses
   signed mutable probes with Developer ID; current harnesses isolate them under Apple
   Development identifiers/services and must be rerun before ship acceptance.
3. **LocalAuthentication from a CLI: ✅ VALIDATED (2026-08-15,**
   `spikes/local-auth`**).** The Rust/Objective-C production path
   authorized through the account-password sheet in a console terminal (rc0). An initial
   SSH run revealed that macOS can route LocalAuthentication UI to the active console,
   so the design was corrected to reject remote/non-graphical Security sessions before
   creating `LAContext`; the rerun returned UNAVAILABLE immediately (rc2) with no sheet.
   The current safe harness uses an Apple Development `.spike` identifier and must be
   rerun before ship acceptance.
4. **Signing pipeline:** Developer ID (`dev.crazytan.kpexec`, Team ID `V82M9YX8BR`) + hardened runtime + notarization on a release artifact; verify a self-built (differently signed) binary degrades the ACL as documented rather than silently appearing to work.

## Implementation milestones

- **M1 — CLI skeleton:** clap command tree, config loading (untrusted-hint semantics), structured errors, logging with the never-log rules, `doctor` (config + filesystem checks only).
- **M2 — vault lifecycle:** `init` (create kdbx, Keychain item with `{password, db_path}` value, one-time recovery key), `entry add/add-command/rm-command/set-secret/edit/rm/list/show/repin` (pins computed at authoring), `check` incl. stale-pin detection, write locking + atomic replace, KeePassXC-lockfile detection.
- **M3 — hardening:** LocalAuthentication gate on all mutating commands, Keychain ACL/partition-list binding, signed + hardened-runtime + notarized build of kpexec itself, `doctor` checks for ACL binding and code signature.
- **M4 — run path:** template resolution, argv construction, `exe_sha256` verification with mutable-path rejection before exec, defined env baseline + `env.set`, no-shell subprocess execution, closed stdin, timeout (SIGTERM → SIGKILL), exit-code propagation, `--dry-run`, `--json`.
- **M5 — output handling:** bounded retained capture while draining to EOF, byte limits, redaction (exact/JSON/shell/URL-encoded forms), fail-closed suppression.
- **M6 — end-to-end demo & release:** real-CLI walkthrough (e.g. `gh` with a minimally scoped token), full acceptance suite green, notarized release artifact.

## Acceptance tests

Functional:

- **A1** `run --dry-run` resolves entry + command and prints the exact argv; no secret read, no subprocess.
- **A2** Unknown entry, unknown command, malformed policy, duplicate `kpexec.id`, and unknown policy fields are each rejected with the right `--json` status (deny by default, deterministic).
- **A3** An allowed run executes `[exe] + argv_prefix + trailing_args` exactly, with the secret present only in the child's environment (child test-helper asserts the env var; its echo of the value must come back redacted).
- **A4** The raw secret never appears in stdout, stderr, the `--json` envelope, or the log file (grep after a full run).
- **A5** Redaction masks exact, JSON-escaped, and URL-encoded forms; a child emitting a deliberately un-maskable variant triggers fail-closed suppression.
- **A6** Child exit codes propagate verbatim; kpexec-level failures use the 100+ band and are distinguishable via `--json`.
- **A7** Timeout: child gets SIGTERM, then SIGKILL after 5 s; partial output is redacted and returned with a timeout status.
- **A8** Concurrent mutation is serialized by the write lock; a stale lock (dead PID) is reclaimed; a crash mid-write leaves the original vault intact.
- **A9** `doctor` warns on credential env var names in project `.env*` files,
  unpinned (`--no-pin`) commands, and stale pins; config/Keychain `db_path`
  disagreement fails closed. `check` fails legacy or hand-edited pins whose
  paths the current principal can replace.
- **A10** A tampered target binary (bytes changed since pinning) is rejected with `exe-hash-mismatch`; no secret is read, no subprocess runs.
- **A11** After a legitimate binary upgrade, `entry repin` (Touch ID) shows old → new hash and restores runs; repinning without user presence fails.

Hardening (require the signed binary):

- **A12** Any mutating command whose local graphical Security-session preflight or
  LocalAuthentication approval fails (including SSH/headless invocation) makes no vault
  change.
- **A13** A differently-signed or unsigned binary cannot read the Keychain item without a user-visible prompt.
- **A14** Vault substitution fails: an agent-planted Keychain item + `config.toml` pointing at an attacker vault is not honored — the run is rejected, not silently served from the attacker vault.
- **A15** After a kpexec version upgrade (new binary, same Team ID + identifier), runs proceed with no new Keychain prompt.

Documented-limitation checks (not preventable, must be visible):

- **A16** Restoring an older vault file (rollback) is not blocked, but the run is logged with the entry/command it executed — confirm the audit line exists.

## Post-MVP

Deliberately out of V1 scope, in rough priority order:

1. **Trailing-argument + cwd constraints** — closes the endpoint-redirection exfiltration path; schema hook reserved (`args`, `cwd`).
2. **Remote approval** — per-run human gate (Telegram or similar); restores the human-in-the-loop for execution, not just authoring.
3. **Secure Enclave policy signing** — authorization integrity that survives master-password leakage.
4. **Streaming output emission** — V1 drains continuously but emits only after bounded capture and redaction complete.
5. **Daemon / short-lived unlock sessions** — amortizes the per-invocation Argon2 cost if it proves painful in practice.
6. **MCP server mode**, non-KeePass vaults, non-macOS platforms.
