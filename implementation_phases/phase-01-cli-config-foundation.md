# Phase 01 - CLI and Config Foundation

Source spec sections: 1, 7, 10, 11, 13, 14.1-14.3, 15.

## Goal

Create the local Rust CLI foundation for `kpexec` without touching secrets yet. This phase should leave a buildable, testable command-line application with config loading, structured errors, stable exit codes, and safe logging defaults.

## Starting Point

The repository may contain only the MVP spec. If no Rust project exists, initialize one. Keep this phase focused on the skeleton and infrastructure needed by later phases.

## Deliverables

- A Rust binary named `kpexec`.
- CLI commands:
  - `kpexec init --db <path>`
  - `kpexec doctor`
  - `kpexec run --entry <kpexec.id> [--dry-run] -- <absolute-exe> [args...]`
  - placeholder command groups for later phases:
    - `kpexec keychain set-db-password`
    - `kpexec telegram setup`
    - `kpexec check --entry <kpexec.id>`
- Config file support at `~/.config/kpexec/config.toml`.
- Structured error type mapped to the MVP exit-code table.
- Logging initialized for `~/Library/Logs/kpexec/kpexec.log`.
- Unit tests for CLI parsing and config behavior.

## Implementation Tasks

1. Create or confirm the Rust project layout.
2. Add baseline dependencies:
   - `clap`
   - `serde`
   - `toml`
   - `thiserror`
   - `tracing`
   - `tracing-subscriber`
   - `dirs` or equivalent home/config path helper
3. Model config:
   - `db_path`
   - `approval_transport`
   - `approval_timeout_sec`
4. Implement `kpexec init --db <path>`:
   - expand `~` if the project uses an existing helper for that;
   - write `~/.config/kpexec/config.toml`;
   - set `approval_transport = "telegram"`;
   - set `approval_timeout_sec = 300`;
   - do not store secrets.
5. Implement `kpexec doctor` as a non-secret baseline check:
   - config file exists;
   - `db_path` exists or emits a clear warning if missing;
   - log directory is writable;
   - no Keychain, Telegram, KeePass, or Wrangler checks yet.
6. Implement `kpexec run` argument splitting:
   - require `--entry`;
   - require subprocess argv after `--`;
   - capture requested executable and trailing argv as structured data;
   - do not perform policy matching yet.
7. Add typed errors and exit-code mapping:
   - `0` success
   - `1` subprocess failed
   - `2` denied by policy
   - `3` denied by user
   - `4` approval timeout
   - `5` KeePass unlock failed
   - `6` entry not found
   - `7` malformed policy
   - `8` output redaction failure
   - `9` configuration error
   - `10` internal error
8. Initialize logging without logging full command lines by default.

## Out of Scope

- Keychain access.
- KeePass parsing.
- Policy validation or matching.
- Telegram API calls.
- Secret injection.
- Subprocess execution.
- Redaction.

## Tests

Add tests for:

- `init` writes the expected TOML fields.
- missing config maps to configuration error.
- `run --entry id -- /abs/exe arg` parses into executable plus argv.
- `run` with no subprocess argv is rejected.
- placeholder commands fail with a clear "not implemented in this phase" style error, not a panic.

## Acceptance Criteria

- `cargo test` passes.
- `cargo run -- init --db ~/Secrets/kpexec-agent.kdbx` writes config without secrets.
- `cargo run -- doctor` reports baseline config/log status.
- `cargo run -- run --entry cloudflare-pages-prod -- /bin/echo pages deploy` parses cleanly and reports later-phase behavior is not implemented.
- Logs contain no secret-shaped placeholders or full Keychain/Telegram values.

## Handoff Notes

Later phases should reuse the typed config, error, logging, and parsed command structures from this phase instead of creating parallel implementations.

