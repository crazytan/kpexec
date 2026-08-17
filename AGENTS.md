# Agent instructions

This file applies to the entire repository. Read
[`docs/agent-guide.md`](docs/agent-guide.md) and
[`docs/security.md`](docs/security.md) before changing code.

## Working rules

- kpexec is a security boundary, not a general command runner. Preserve deny-by-default behavior, direct execution without a shell, executable pinning, the minimal child environment, user-presence authorization for every mutation, and secret-free output and logs.
- Do not claim credential confidentiality from an unrestricted same-UID process. Such a process can read a non-`CS_RESTRICT` child's initial environment through `KERN_PROCARGS2` (including `ps -E`/`ps eww`) without debugger access; hardened runtime separately limits some debugger/task-port access to memory but does not hide that environment. Preserve this limitation and re-check the threat model whenever documentation or a security boundary changes.
- Treat the checkout, configuration, ambient environment, CLI arguments, vault path hints, and subprocess output as attacker-controlled. Never use a secret from an argument, environment variable, fixture committed to Git, log, or error message.
- Preserve the user's working tree. Inspect `git status` before editing; do not discard or rewrite unrelated work.
- Use `cargo` with `--locked`. Do not update dependencies or either lockfile unless the task explicitly requires it.
- A new or renamed mutating command must be classified exhaustively in `src/commands.rs` and authorized before its handler opens the vault, takes a lock, accesses Keychain, or changes state.
- Do not weaken a validation, redaction, ACL, code-signing, path-ownership, or release check to make a test pass. Add a regression test that fails before the fix.
- Do not use production Developer ID credentials for mutable probes or ad hoc builds. Supervised probes must stay in their isolated Apple Development trust domain.
- Keep generated binaries, packages, temporary vaults, credentials, and probe output out of Git. Clean task-specific artifacts after verification; preserve durable release evidence and user-owned data.
- Commits must carry a DCO sign-off (`git commit -s`). Do not push, publish, sign, notarize, mutate a real vault, or invoke an interactive security prompt unless the user has authorized that action.

## Required validation

For documentation-only changes, check links, commands, threat-model consistency,
and `git diff --check`. For code changes, run the focused tests plus the
non-interactive gates in `docs/agent-guide.md`. Changes to Keychain,
LocalAuthentication, signing, installer, or other macOS trust boundaries also
require the supervised acceptance procedure; automated unit tests alone are not
sufficient.

Supported release scope is Apple silicon, macOS 15 or newer. Production identity is `dev.crazytan.kpexec`, Team ID `V82M9YX8BR`; the package identifier is `dev.crazytan.kpexec.pkg`. Treat any change to those values as a security migration, not routine configuration.
