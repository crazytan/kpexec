# kpexec — CLI Design (condensed, generalized)

Design stance: the user may have never used KeePass. kpexec owns the full lifecycle — it creates and manages a dedicated `.kdbx` vault (standard format, still openable in KeePassXC), so KeePass is an implementation detail the user can ignore. Secrets are never accepted as CLI arguments; policies are authored through prompts, never hand-written JSON in a KeePass GUI. Every command that mutates the vault ends in a Touch ID / account-password check (see [security-design.md](security-design.md)); read and run paths never prompt.

## Data model

```
Vault (one dedicated .kdbx file)
 └── Entry (N per vault) — one credential + its policy
      ├── id            stable agent-facing identifier (e.g. "github")
      ├── description   shown in listings and logs
      ├── secret        the credential value
      ├── injection     env var name to inject (e.g. "GH_TOKEN")
      ├── env.set       optional non-secret env vars for the child (e.g. PATH extension)
      ├── output        max stdout/stderr bytes
      └── Command (N per entry) — one allowed command template
           ├── name         agent-facing name (e.g. "pr-create", "deploy")
           ├── exe          absolute path, validated at authoring time
           └── argv_prefix  fixed leading arguments
```

Naming: **`--entry <id>` selects the credential bundle; `--command <name>` selects one allowed action under it.** `id` is the `kpexec.id` custom-field value — a stable handle decoupled from the KeePass entry Title, so retitling in a GUI never breaks agents. Two levels exist because one credential commonly backs several allowed actions — a single GitHub token might permit `gh pr list`, `gh pr create`, and `gh issue comment`, each expressed as its own command template on the same entry (each with its own name, exe, and prefix). `id` must be unique across the vault; `name` must be unique within its entry. Granting a new action = adding a template; revoking one = removing it — the secret itself is stored once and never touched.

A run request is `(entry id, command name, trailing args)`. kpexec executes:

```
argv = [command.exe] + command.argv_prefix + trailing_args
env  = defined baseline (HOME, TMPDIR, LANG, minimal PATH)
       + policy env.set
       + { injection.name: secret }
cwd  = caller's cwd; stdin closed
```

## Translation to KeePass (KDBX4)

| kpexec concept | KDBX representation |
|---|---|
| Vault | one dedicated `.kdbx` file (KDBX4), e.g. `~/Secrets/kpexec-agent.kdbx` |
| Entry | one KeePass entry |
| `id` | custom string field `kpexec.id` (the single source of identity) |
| `secret` | standard `Password` field (memory-protected) |
| description, injection, env, commands, output limits | custom string field `kpexec.policy.v1` — one JSON document (unprotected, so it is reviewable/editable in KeePassXC) |
| human label | standard `Title` (display only; agents never reference it) |

Example policy JSON stored in `kpexec.policy.v1`:

```json
{
  "schema": "kpexec.policy.v1",
  "description": "GitHub token for agent PR/issue workflows",
  "secret": { "field": "password",
              "inject": { "type": "env", "name": "GH_TOKEN" } },
  "env": { "set": { "PATH": "/opt/homebrew/bin:/usr/bin:/bin" } },
  "commands": [
    { "name": "pr-list",
      "exe": "/opt/homebrew/bin/gh",
      "argv_prefix": ["pr", "list"] },
    { "name": "pr-create",
      "exe": "/opt/homebrew/bin/gh",
      "argv_prefix": ["pr", "create"] },
    { "name": "issue-comment",
      "exe": "/opt/homebrew/bin/gh",
      "argv_prefix": ["issue", "comment"] }
  ],
  "output": { "max_stdout_bytes": 200000,
              "max_stderr_bytes": 50000 }
}
```

Rules:

- Entries without `kpexec.id` are ignored (coexistence is possible, but a dedicated vault is the default).
- Identity lives only in the `kpexec.id` field; the policy JSON carries no duplicate id. Duplicate `kpexec.id` values across the vault, malformed JSON, or unknown fields ⇒ the run is rejected (deny by default, deterministic — never "pick first").
- Redaction is always on; there is no policy field to disable it.
- Schema is versioned via the `"schema"` field; future revisions add `kpexec.policy.v2` rather than mutating v1.
- kpexec reads and writes the vault itself (KDBX4 save). Writes take a kpexec-level lock, are atomic (write-temp-then-rename with a backup of the previous file), and refuse to proceed if a KeePassXC lockfile is present. The kpexec lock records PID + start time; a lock whose holder is no longer running is reclaimed. A crash mid-write leaves a temp file behind and the original vault intact. Hand-editing in KeePassXC is supported — close it first, run `kpexec check` afterwards.
- Keychain: service `dev.crazytan.kpexec`, account `db-password:<fp>` where `<fp>` = first 12 hex chars of SHA-256 of the canonical vault path. The item's ACL is bound to the developer's Team ID + identifier `dev.crazytan.kpexec` (see security-design.md). The item *value* is a small JSON document `{"password": "...", "db_path": "..."}` — the vault's identity lives inside the ACL-protected item, and `config.toml` (agent-writable) is only a hint that must agree with it; kpexec never opens a vault the protected item doesn't name.
- Every invocation — including `entry list` — pays a full Argon2id unlock; there is no daemon or session cache by design. KDF parameters are tuned at `init` to ~0.5 s on the local machine; agents should budget roughly a second of overhead per call.

Reserved extensions (recorded now so the schema doesn't need a breaking redesign; will ship under a bumped `schema` string, since v1 rejects unknown fields): per-command `args` constraints (flag allow/deny lists, positional caps), a `cwd` restriction, and `exe_sha256` binary pinning paired with a Touch ID–gated `kpexec entry repin <id>` flow for legitimate upgrades of the target binary.

## User journey

1. **Set up once** — `kpexec init` (stores recovery key somewhere safe) → `kpexec doctor`
2. **Add a credential + policy** — `kpexec entry add` (Touch ID)
3. **Verify** — `kpexec check`, `kpexec run --dry-run`
4. **Hand to the agent** — agent calls `kpexec run`; policy match executes, anything else is rejected.

## Subcommands

Mutating commands are marked **[Touch ID]** — each ends in a user-presence prompt summarizing the change.

### Setup

- `kpexec init [--db <path>] [--use-existing]` **[Touch ID]**
  Default: creates `~/Secrets/kpexec-agent.kdbx` with a generated master password stored in macOS Keychain (ACL-bound to kpexec), plus `~/.config/kpexec/config.toml`. Prints the master password **once** as a recovery key, with instructions to store it outside the agent's reach (personal password manager or paper). `--use-existing` adopts an existing kdbx (prompts for its password once, stores it in Keychain).
- `kpexec doctor`
  Validates config (including that `db_path` agrees with the path embedded in the Keychain item), the Keychain item and its ACL binding, DB openability, and kpexec's own code signature; warns if project `.env*` files near cwd contain any env var name that a policy injects, and when a policy executable lives inside a project tree (e.g. `node_modules/.bin`) or another location writable by the current user — the scenario binary hash pinning will eventually close.

### Entry & policy management (secrets never printed)

- `kpexec entry add [<id>]` **[Touch ID]** — wizard; writes the KeePass entry and generates the policy JSON. Loops so one entry can collect any number of command templates. Prefix input is parsed with shell-word rules (quoting supported); the wizard warns when a prefix is empty or a single word, since short prefixes grant broad surface. Secrets shorter than 8 characters are refused — redacting very short strings is unreliable and shreds output with false positives.
- `kpexec entry add-command <id>` **[Touch ID]** — append another command template (grant a new action without re-entering the secret).
- `kpexec entry rm-command <id> <name>` **[Touch ID]** — revoke a single action.
- `kpexec entry set-secret <id>` **[Touch ID]** — rotate the stored credential without touching the policy.
- `kpexec entry edit <id>` **[Touch ID]** — re-runs wizard fields; `kpexec entry rm <id>` **[Touch ID]**.
- `kpexec entry list [--json]` — table of entries and their commands; doubles as the agent's discovery mechanism (agents should use `--json`).
- `kpexec entry show <id> [--json]` — full policy, secret always masked.
- `kpexec check [--entry <id>]` — validates policies: JSON parses, schema known, no unknown fields, ids unique, command names unique per entry, exe exists and canonicalizes.

#### Example: authoring (one credential, several allowed actions)

```
$ kpexec entry add github
Description: GitHub token for agent PR/issue workflows
Secret (hidden, or pipe via --secret-stdin): ********
Inject as env var: GH_TOKEN
Command template 1
  Name: pr-list
  Executable (absolute path): /opt/homebrew/bin/gh
  Fixed argument prefix: pr list
Add another command template? [y/N] y
Command template 2
  Name: pr-create
  Executable [/opt/homebrew/bin/gh]:
  Fixed argument prefix: pr create
Add another command template? [y/N] y
Command template 3
  Name: issue-comment
  Executable [/opt/homebrew/bin/gh]:
  Fixed argument prefix: issue comment
Add another command template? [y/N] n
[Touch ID] Approve: create entry 'github' with 3 commands
✓ entry 'github' (3 commands) written to ~/Secrets/kpexec-agent.kdbx
```

```
$ kpexec entry list
ENTRY   COMMAND        EXECUTABLE            PREFIX
github  pr-list        /opt/homebrew/bin/gh  pr list
github  pr-create      /opt/homebrew/bin/gh  pr create
github  issue-comment  /opt/homebrew/bin/gh  issue comment
```

```
$ kpexec entry show github
id:          github
description: GitHub token for agent PR/issue workflows
secret:      ******** (Password field)
inject:      env GH_TOKEN
commands:
  pr-list       → /opt/homebrew/bin/gh pr list [trailing args...]
  pr-create     → /opt/homebrew/bin/gh pr create [trailing args...]
  issue-comment → /opt/homebrew/bin/gh issue comment [trailing args...]
output:      stdout ≤ 200000 B, stderr ≤ 50000 B
```

Granting a new action later:

```
$ kpexec entry add-command github
  Name: release-list
  Executable [/opt/homebrew/bin/gh]:
  Fixed argument prefix: release list
[Touch ID] Approve: add command 'release-list' to entry 'github'
✓ entry 'github' now has 4 commands
```

### Execution (the only agent-facing command; never prompts)

- `kpexec run --entry <id> --command <name> [--dry-run] [--timeout <sec>] [--json] [-- trailing args...]`
  - The policy supplies executable + prefix; the agent supplies only trailing arguments. *(Deviation from spec §7, which had the agent pass the full absolute command for kpexec to match — the template model is a strictly smaller attack surface and avoids per-machine paths in agent prompts.)*
  - `--command` is always required, even for single-template entries — optionality would make existing invocations break the moment a second template is added.
  - `--dry-run`: resolves entry + command and prints the exact argv that would run — no secret read, no subprocess.
  - `--timeout` default 300 s; on expiry the child gets SIGTERM, then SIGKILL after 5 s; partial output is redacted and returned with a timeout status.
  - Output is fully buffered: nothing is emitted until the child exits (or times out), and redaction runs over the complete output. V1 has no streaming mode — streaming would require chunk-boundary-safe secret scanning and is deferred.
  - `--json` emits a structured result: `{ "kpexec_status": "...", "child_exit_code": N, "stdout": "...", "stderr": "..." }`. This is the authoritative way for agents to distinguish kpexec-level failures from child failures.
  - Exit codes: child's exit code propagated verbatim on execution. kpexec-level failures use a reserved band (100+: unknown-entry, unknown-command, malformed-policy, unlock-failed, redaction-failure, timeout, config-error, internal). Children can legitimately exit 100–125, so the band is a convenience — `--json` is the reliable channel.

#### Example: execution

```
$ kpexec run --entry github --command pr-create -- --title "Fix build" --base main
[kpexec] entry github, command pr-create
[kpexec] exec: /opt/homebrew/bin/gh pr create --title "Fix build" --base main
... redacted subprocess output ...
```

```
$ kpexec run --entry github --command repo-delete -- my-org/my-repo
[kpexec] rejected: entry 'github' has no command 'repo-delete'   (exit 101)
```

```
$ kpexec run --entry github -- pr list
[kpexec] rejected: --command is required
```

### Maintenance

- `kpexec db rotate-password` **[Touch ID]** — regenerates the vault master password, re-encrypts the vault, updates Keychain, prints the new recovery key once.
- `kpexec db show-password` **[Touch ID]** — re-displays the master password (e.g. to open the vault in KeePassXC, or to store a recovery copy).

## Agent contract

- Request by entry id + command name + trailing args after `--`.
- Receives: redacted stdout/stderr (byte-limited) + exit code, or the `--json` envelope. Never the secret — and never a requirement to know where the executable lives.
- `entry list --json` / `--dry-run` let the agent discover what is allowed and pre-validate a request before running it.
- `run` never blocks on a prompt: no Touch ID, no stdin.

## Config file & logs

```toml
# ~/.config/kpexec/config.toml — untrusted hints only; never secrets
db_path = "/Users/tan/Secrets/kpexec-agent.kdbx"  # must agree with the path inside the Keychain item
default_timeout_sec = 300
```

The config file is agent-writable and therefore untrusted input: it can point kpexec at things, but the ACL-protected Keychain item decides which vault is real (see the KDBX translation rules above and security-design.md).

Logs: `~/Library/Logs/kpexec/kpexec.log`, size-capped rotation (e.g. 5 MB × 3). Each run logs entry id, command name, canonical exe, a hash of the full argv, and the result — never the secret, never raw trailing args, and never the full command line by default (paths, branch names, and titles can themselves be sensitive).

## Milestones & acceptance tests

See [milestones.md](milestones.md) for the de-risking spikes (milestone zero), the implementation milestones, and the acceptance test list.
