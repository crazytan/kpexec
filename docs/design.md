# Why kpexec exists and how it works

Coding agents are most useful when they can call real developer tools. Those
tools often expect a credential in an environment variable, but giving the
credential to the agent makes authorization indistinguishable from possession:
the agent can read, repeat, log, or redirect it. Prompt injection then turns a
useful integration into a credential-handling problem.

kpexec separates those concerns. A person stores a credential together with a
small set of command templates. An agent refers to a template by name. kpexec
opens the vault, verifies the selected executable, constructs the process, and
injects the credential into that child. The agent does not need the credential
value or the executable path.

This is useful only with an honest boundary statement: an unrestricted process
running as the same macOS user can inspect a non-`CS_RESTRICT` child's initial
environment through `KERN_PROCARGS2` (including `ps -E`/`ps eww`) without a
debugger. Hardened runtime does not hide that environment, although it separately
limits some debugger/task-port access to memory. The process may also signal or
otherwise influence the child. kpexec is designed for agents constrained by an
OS/application sandbox or tool permission boundary verified to block these
paths. It reduces credential distribution and accidental disclosure; it is not
a same-user process sandbox. See [Security and threat model](security.md) before
adopting it.

## Design goals

- Keep the credential out of agent prompts, tool arguments, normal output, and
  kpexec logs.
- Let a person approve capabilities such as “run this executable with this
  fixed prefix,” rather than hand over a reusable credential.
- Keep ordinary runs non-interactive while requiring local user presence for
  policy or secret changes.
- Fail closed on ambiguous policy, vault substitution, or a changed pinned
  executable.
- Use a standard, recoverable vault format rather than inventing a secret
  database.

V1 deliberately does not provide per-run approval, constrain trailing
arguments or the working directory, stop same-UID process inspection, prevent
vault rollback, or secure a credential after the approved child receives it.

## The model

A dedicated KDBX4 vault contains entries. Each entry holds one credential and
one policy. A policy has a stable entry ID, an environment-variable injection
name, output limits, and one or more named command templates. A template fixes:

- an absolute executable path;
- normally, the SHA-256 of that executable;
- a leading argument vector.

The agent supplies only the entry ID, command name, and optional trailing
arguments:

```text
agent request
    |
    v
entry ID + command name + trailing argv
    |
    v
open identity-bound KDBX vault -> parse policy -> canonicalize and hash exe
    |
    v
build argv directly (no shell) -> build minimal environment -> inject secret
    |
    v
child process -> bounded capture -> redact -> agent-visible result
```

For example, a `github` entry could contain separate `pr-list` and `pr-create`
templates backed by the same token. Adding or removing a template changes the
agent's authority without copying or rotating the token.

## Execution sequence

For `kpexec run`, the implementation performs these operations in order:

1. Load `~/.config/kpexec/config.toml` as an untrusted path hint.
2. Resolve the Keychain item and require its protected vault path to agree with
   that hint.
3. Open the KDBX vault and resolve exactly one entry and command. Malformed
   JSON, unknown fields, duplicate IDs, and duplicate command names reject.
4. Canonicalize the absolute executable path. For a pinned command, require
   the file hash to match and require the file and every ancestor to be outside
   the current user's ownership and write control.
5. Build `[executable] + fixed prefix + trailing arguments` as an argv vector.
   No shell parses or interpolates the values.
6. For a dry run, stop here; the vault has been parsed, but the selected
   credential is not explicitly extracted or injected and no process is started.
7. Otherwise, read the selected credential, clear the inherited environment,
   add a small baseline (`HOME`, `TMPDIR`, `LANG`, and
   `PATH=/usr/bin:/bin`), apply policy-defined non-secret variables, and add
   the credential variable.
8. Start the child with closed stdin and the caller's working directory.
9. Drain stdout and stderr while retaining only policy-bounded prefixes. On
   timeout, send `SIGTERM`, then `SIGKILL` after five seconds.
10. Redact exact, JSON-escaped, shell-escaped, and URL-encoded forms before
    emitting output. If the final check still finds secret material, suppress
    output and fail closed.

Child exit codes are propagated. kpexec failures use structured status values;
agents should use `--json` rather than infer the source of a failure from the
numeric exit code alone.

## Why these components

**KDBX4** provides authenticated encryption, a standard format, and optional
KeePassXC interoperability. kpexec writes through a same-directory temporary
file, syncs it, retains a backup of the previous file, and atomically renames
the new vault. Its own PID/start-time lock serializes writers, and a detected
KeePassXC lock prevents concurrent editing.

**macOS Keychain** holds only the generated vault password. The item embeds the
canonical vault path and is restricted to the release Team ID and
`dev.crazytan.kpexec` signing identifier. Config cannot substitute another
vault. The KDBX entries—not Keychain—hold the brokered credentials.

**LocalAuthentication** gates initialization, entry and command mutations,
repinning, password rotation, and password display. A kernel Security-session
preflight rejects remote or non-graphical callers before a sheet is created.
Runs, discovery, checks, and dry runs remain unattended.

**Executable pinning** detects changed bytes before reading the selected
credential or spawning the child. The path-ownership rules address the lack of
a public descriptor-based `exec` on macOS. Pinning is intentionally opt-out;
`--no-pin` remains available but is reported by `check` and `doctor`.

**Deferred redaction** is a last defense against accidental echoing, not a
confidentiality boundary. A malicious child already has the credential and can
encode it, send it over the network, or expose it to same-user processes.

## Data and recovery

The default vault is `~/Secrets/kpexec-agent.kdbx`; configuration lives at
`~/.config/kpexec/config.toml`; audit logs live under
`~/Library/Logs/kpexec/`. The log records entry ID, command name, canonical
executable, a hash of the full argv, and status—never raw arguments or the
credential. It is same-user-writable and therefore advisory, not tamper-proof.

Initialization prints the generated vault password once. Store it outside the
agent's reach, such as in a separate password manager or on paper. Losing both
that recovery copy and the Keychain item makes the vault unrecoverable. Leaking
the password removes both vault confidentiality and the mutation boundary.
