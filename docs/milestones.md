# kpexec — Milestones & Acceptance Tests

## Milestone 0: de-risking validations (before feature code)

These validate assumptions the design leans on. If one fails, the design changes — so they come first.

1. **KDBX4 write round-trip:** create/modify a vault with the Rust `keepass` crate, open and edit it in KeePassXC, read it back with custom fields and protected password intact. Write support is younger than read support.
   *Preliminary observation (2026-07-05): a vault created with `keepass` 0.13.13 (`save_kdbx4`) opened cleanly in keepassxc-cli with `kpexec.id` / `kpexec.policy.v1` custom fields and the protected password intact. The KeePassXC-edit → crate-read-back leg has not been run yet.*
2. **Keychain ACL behavior for a CLI tool:** confirm the Team ID + identifier partition list lets the signed kpexec read the item silently, prompts for any other process, and survives a kpexec version upgrade without re-prompting. **Must include:** an item created *by another process* (simulating the agent, e.g. via `security add-generic-password -T`) is **not** silently readable by kpexec — this property is what blocks the vault-substitution attack (see security-design.md).
3. **LocalAuthentication from a CLI:** confirm the Touch ID / account-password sheet can be invoked from a signed, hardened-runtime command-line binary in a normal terminal session, and fails closed over SSH / headless.
4. **Signing pipeline:** Developer ID (`dev.crazytan.kpexec`, Team ID `V82M9YX8BR`) + hardened runtime + notarization on a release artifact; verify a self-built (differently signed) binary degrades the ACL as documented rather than silently appearing to work.

## Implementation milestones

- **M1 — CLI skeleton:** clap command tree, config loading (untrusted-hint semantics), structured errors, logging with the never-log rules, `doctor` (config + filesystem checks only).
- **M2 — vault lifecycle:** `init` (create kdbx, Keychain item with `{password, db_path}` value, one-time recovery key), `entry add/add-command/rm-command/set-secret/edit/rm/list/show`, `check`, write locking + atomic replace, KeePassXC-lockfile detection.
- **M3 — hardening:** LocalAuthentication gate on all mutating commands, Keychain ACL/partition-list binding, signed + hardened-runtime + notarized build of kpexec itself, `doctor` checks for ACL binding and code signature.
- **M4 — run path:** template resolution, argv construction, defined env baseline + `env.set`, no-shell subprocess execution, closed stdin, timeout (SIGTERM → SIGKILL), exit-code propagation, `--dry-run`, `--json`.
- **M5 — output handling:** buffered capture, byte limits, redaction (exact/JSON/shell/URL-encoded forms), fail-closed suppression.
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
- **A9** `doctor` warns on: credential env var names in project `.env*` files, project-local or user-writable policy executables, config/Keychain `db_path` disagreement.

Hardening (require the signed binary):

- **A10** Any mutating command with the LocalAuthentication prompt denied (or unavailable, e.g. over SSH) makes no vault change.
- **A11** A differently-signed or unsigned binary cannot read the Keychain item without a user-visible prompt.
- **A12** Vault substitution fails: an agent-planted Keychain item + `config.toml` pointing at an attacker vault is not honored — the run is rejected, not silently served from the attacker vault.
- **A13** After a kpexec version upgrade (new binary, same Team ID + identifier), runs proceed with no new Keychain prompt.

Documented-limitation checks (not preventable, must be visible):

- **A14** Restoring an older vault file (rollback) is not blocked, but the run is logged with the entry/command it executed — confirm the audit line exists.
