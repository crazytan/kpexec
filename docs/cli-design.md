# kpexec — CLI Design (condensed, generalized)

Design stance: the user may have never used KeePass. kpexec owns the full lifecycle — it creates and manages a dedicated `.kdbx` vault (standard format, still openable in KeePassXC), so KeePass is an implementation detail the user can ignore. Secrets are never accepted as CLI arguments; policies are authored through prompts, never hand-written JSON in a KeePass GUI.

## Data model

```
Vault (one dedicated .kdbx file)
 └── Entry (N per vault) — one credential + its policy
      ├── id            stable agent-facing identifier (e.g. "github")
      ├── description   shown in listings and logs
      ├── secret        the credential value
      ├── injection     env var name to inject (e.g. "GH_TOKEN")
      ├── output        max stdout/stderr bytes, redaction on
      └── Command (N per entry) — one allowed command template
           ├── name         agent-facing name (e.g. "pr-create", "deploy")
           ├── exe          absolute path, validated at authoring time
           └── argv_prefix  fixed leading arguments
```

Naming: **`--entry <id>` selects the credential bundle; `--command <name>` selects one allowed action under it.** `id` is the `kpexec.id` value — a stable handle decoupled from the KeePass entry Title, so retitling in a GUI never breaks agents. Two levels exist because one credential commonly backs several allowed actions — a single GitHub token might permit `gh pr list`, `gh pr create`, and `gh issue comment`, each expressed as its own command template on the same entry (each with its own name, exe, and prefix). `id` must be unique across the vault; `name` must be unique within its entry. Granting a new action = adding a template; revoking one = removing it — the secret itself is stored once and never touched.

A run request is `(entry id, command name, trailing args)`. kpexec executes:

```
argv = [command.exe] + command.argv_prefix + trailing_args
env  = clean baseline + { injection.name: secret }
```

## Translation to KeePass (KDBX4)

| kpexec concept | KDBX representation |
|---|---|
| Vault | one dedicated `.kdbx` file (KDBX4), e.g. `~/Secrets/kpexec-agent.kdbx` |
| Entry | one KeePass entry |
| `id` | custom string field `kpexec.id` |
| `secret` | standard `Password` field (memory-protected) |
| description, injection, commands, output limits | custom string field `kpexec.policy.v1` — one JSON document (unprotected, so it is reviewable/editable in KeePassXC) |
| human label | standard `Title` (display only; agents never reference it) |

Example policy JSON stored in `kpexec.policy.v1`:

```json
{
  "schema": "kpexec.policy.v1",
  "id": "github",
  "description": "GitHub token for agent PR/issue workflows",
  "secret": { "field": "password",
              "inject": { "type": "env", "name": "GH_TOKEN" } },
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
              "max_stderr_bytes": 50000,
              "redact_secret": true }
}
```

Rules:

- Entries without `kpexec.id` are ignored (coexistence is possible, but a dedicated vault is the default).
- `kpexec.id` must equal the policy's `id`; mismatch, malformed JSON, unknown fields, or duplicate ids across the vault ⇒ entry rejected.
- Schema is versioned via the `"schema"` field; future revisions add `kpexec.policy.v2` rather than mutating v1.
- kpexec reads and writes the vault itself (KDBX4 save); hand-editing in KeePassXC is supported — run `kpexec check` afterwards.
- Keychain: service `dev.kpexec`, account `db-password:<fp>` where `<fp>` = first 12 hex chars of SHA-256 of the canonical vault path.

## User journey

1. **Set up once** — `kpexec init` → `kpexec doctor`
2. **Add a credential + policy** — `kpexec entry add`
3. **Verify** — `kpexec check`, `kpexec run --dry-run`
4. **Hand to the agent** — agent calls `kpexec run`; policy match executes, anything else is rejected.

## Subcommands

### Setup

- `kpexec init [--db <path>] [--use-existing]`
  Default: creates `~/Secrets/kpexec-agent.kdbx` with a generated master password stored in macOS Keychain, plus `~/.config/kpexec/config.toml`. `--use-existing` adopts an existing kdbx (prompts for its password once, stores it in Keychain). The user never has to know a KeePass password exists.
- `kpexec doctor`
  Validates config, Keychain items, and DB openability; warns if project `.env*` files near cwd contain any env var name that a policy injects.

### Entry & policy management (all local; secrets never printed)

- `kpexec entry add [<id>]` — wizard; writes the KeePass entry and generates the policy JSON. Loops so one entry can collect any number of command templates.
- `kpexec entry add-command <id>` — append another command template to an existing entry (grant a new action without re-entering the secret).
- `kpexec entry rm-command <id> <name>` — revoke a single action.
- `kpexec entry list` — table of entries and their commands; doubles as the agent's discovery mechanism.
- `kpexec entry show <id>` — full policy, secret always masked.
- `kpexec entry edit <id>` — re-runs wizard fields; `kpexec entry rm <id>`.
- `kpexec check [--entry <id>]` — validates policies: JSON parses, schema/id match, ids unique, command names unique per entry, exe exists and canonicalizes.

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
output:      stdout ≤ 200000 B, stderr ≤ 50000 B, redaction on
```

Granting a new action later:

```
$ kpexec entry add-command github
  Name: release-list
  Executable [/opt/homebrew/bin/gh]:
  Fixed argument prefix: release list
✓ entry 'github' now has 4 commands
```

### Execution (the only agent-facing command)

- `kpexec run --entry <id> [--command <name>] [--dry-run] [--timeout <sec>] [-- trailing args...]`
  - The policy supplies executable + prefix; the agent supplies only trailing arguments. *(Deviation from spec §7, which had the agent pass the full absolute command for kpexec to match — the template model is a strictly smaller attack surface and avoids per-machine paths in agent prompts.)*
  - `--command` is optional when the entry defines exactly one command template.
  - `--dry-run`: resolves entry + command and prints the exact argv that would run — no secret read, no subprocess.
  - Exit codes: child's exit code propagated verbatim; kpexec-level failures use a reserved high band (100+: unknown-entry, unknown-command, malformed-policy, unlock-failed, redaction-failure, config-error, internal) so they can't collide with child exit codes. *(Deviation from spec §13's 0–10 table, which collides with child codes.)*

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
[kpexec] rejected: entry 'github' has 4 commands; --command is required
```

(An entry with exactly one command template can omit `--command`.)

### Maintenance

- `kpexec db rotate-password` — regenerates the vault master password and updates Keychain (replaces the spec's `keychain set-db-password`).

## Agent contract

- Request by entry id (+ command name if the entry has several) + trailing args after `--`.
- Receives: redacted stdout/stderr (byte-limited) + exit code. Never the secret — and never a requirement to know where the executable lives.
- `entry list` / `--dry-run` let the agent discover what is allowed and pre-validate a request before running it.
