# Phase 07 - Demo, Doctor, and Validation

Source spec sections: 7, 8.2-8.3, 10, 12, 16, 17, 19.

## Goal

Make the MVP usable and verifiable: finish `doctor` and `check`, add Wrangler example policies, document setup, and implement validation tests that prove the security properties from the spec.

## Starting Point

Phase 06 has the complete approved execution path with redaction.

## Deliverables

- Full `kpexec doctor`.
- Full `kpexec check --entry <id>`.
- Example KeePass entry documentation.
- Example Pages deploy policy.
- Example Workers deploy policy.
- README quickstart.
- Validation test script or integration test plan for T1-T6.
- Negative tests for executable mismatch and prefix mismatch.

## Implementation Tasks

1. Expand `doctor`:
   - config file exists and parses;
   - configured database path exists;
   - Keychain database password item exists;
   - Telegram bot token item exists;
   - Telegram allowed user ID item exists;
   - log directory is writable;
   - current working directory and nearby project files are scanned for `.env*` files containing Cloudflare credential variable names.
2. Implement `.env*` scanning warnings:
   - warn on `CLOUDFLARE_API_TOKEN`;
   - warn on `CF_API_TOKEN`;
   - warn on `CLOUDFLARE_API_KEY`;
   - warn on `CF_API_KEY`;
   - do not print values from `.env*` files.
3. Expand `check --entry <id>`:
   - opens KeePass;
   - finds the entry;
   - validates `kpexec.id`;
   - parses and validates `kpexec.policy.v1`;
   - canonicalizes each policy executable;
   - confirms the password field is present without printing it;
   - reports command names and high-level status only.
4. Add example policy files or README snippets:
   - Pages deploy:
     - executable: concrete local Wrangler path;
     - prefix: `["pages", "deploy"]`;
   - Workers deploy:
     - executable: concrete local Wrangler path;
     - prefix: `["deploy"]`;
   - use `CLOUDFLARE_API_TOKEN`;
   - do not use `CF_API_TOKEN`;
   - do not use `npx`, `npm`, `pnpm`, or `yarn` as the demo policy executable.
5. Add README quickstart:
   - create dedicated KeePass database;
   - add entry with `password`, `kpexec.id`, and `kpexec.policy.v1`;
   - run `kpexec init --db ...`;
   - run `kpexec keychain set-db-password`;
   - run `kpexec telegram setup`;
   - run `kpexec doctor`;
   - run `kpexec check --entry ...`;
   - run dry-run;
   - run approved Wrangler deploy.
6. Add validation tests or scripts for:
   - T1 dry-run match succeeds;
   - T2 executable mismatch denied;
   - T3 prefix mismatch denied;
   - T4 approved run injects token only into child process;
   - T5 raw token never appears in output or logs;
   - T6 `.env` credential warning.
7. Document manual Cloudflare demo precautions:
   - use a dedicated token with minimal permissions;
   - set an expiration where practical;
   - avoid relying on `wrangler login`;
   - remove Cloudflare credential variables from project `.env*` files.

## Out of Scope

- Post-MVP policy extensions.
- Cwd restrictions.
- Trailing argument constraints.
- Branch or project allowlists.
- Binary hash pinning.
- MCP server mode.
- Daemon/session cache.
- Non-KeePass vaults.

## Tests

Run:

- `cargo test`
- any integration tests added in this phase
- manual dry-run commands from the README
- a fake-helper approved run that proves token injection and redaction without requiring Cloudflare network access

If a real Wrangler deploy is performed, keep it as a documented manual validation path rather than a required automated test.

## Acceptance Criteria

- `doctor` catches missing config, missing DB, missing Keychain values, missing Telegram setup, and `.env*` Cloudflare credential names.
- `check --entry` validates entries and policies without printing secrets.
- README gives a fresh user enough steps to run the MVP safely.
- The validation suite covers all hard success and hard failure criteria from the source spec.
- The final MVP summary remains true:
  - macOS only;
  - dedicated KeePass;
  - Keychain unlock;
  - Telegram approval;
  - KeePass-stored policy;
  - Wrangler target;
  - env injection only;
  - `CLOUDFLARE_API_TOKEN`;
  - absolute executable plus argv-prefix matching;
  - no PATH lookup;
  - no shell;
  - redacted stdout/stderr;
  - no daemon or session cache.

## Handoff Notes

After this phase, the next useful work is probably a post-MVP design phase for cwd and trailing-argument constraints. Do not fold those into the MVP validation work unless the product scope is explicitly changed.

