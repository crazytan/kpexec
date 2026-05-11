# Phase 02 - Keychain and KeePass Read Path

Source spec sections: 2.2, 4, 10, 11, 14.1, 15.

## Goal

Add the secure read path for the dedicated KeePass database: store the database password in macOS Keychain, open the configured `.kdbx`, find entries by `kpexec.id`, and read the `kpexec.policy.v1` custom field.

## Starting Point

Phase 01 is complete. The CLI, config loader, error mapping, and logging already exist.

## Deliverables

- `kpexec keychain set-db-password`
- Keychain read/write helpers for the KeePass database password.
- KeePass database open helper.
- Entry lookup by custom field `kpexec.id`.
- Policy custom field read as raw JSON.
- `kpexec check --entry <id>` basic entry inspection.

## Implementation Tasks

1. Add dependencies:
   - `keepass`
   - `security-framework` or `keyring`
   - `rpassword` or another no-echo prompt helper
   - `zeroize`
   - `secrecy`
2. Implement a small Keychain abstraction:
   - service: `dev.kpexec`;
   - account for the database password derived by one helper, for example `db-password:<db-fingerprint>`;
   - no logs containing account values if they may reveal sensitive local paths.
3. Implement `kpexec keychain set-db-password`:
   - load config;
   - prompt for the KeePass database password without echo;
   - store it in Keychain;
   - confirm success without printing the password.
4. Implement KeePass database open:
   - load `db_path` from config;
   - retrieve database password from Keychain;
   - open the dedicated `.kdbx`;
   - map unlock failures to exit code `5`.
5. Implement entry traversal:
   - find exactly one entry whose custom field `kpexec.id` equals the requested entry ID;
   - return entry-not-found exit code `6` if none exist;
   - reject duplicates as configuration or internal error, with no secret output.
6. Read custom fields:
   - require `kpexec.id`;
   - require `kpexec.policy.v1`;
   - return the policy field as raw JSON text for Phase 03.
7. Implement `kpexec check --entry <id>` basic behavior:
   - opens the database;
   - finds the entry;
   - confirms required custom fields exist;
   - optionally confirms the password field is present without printing it;
   - does not perform command matching yet.

## Out of Scope

- Full policy schema validation.
- Canonical executable matching.
- Telegram approval.
- Subprocess execution.
- Redaction beyond not printing secrets at all.

## Tests

Add unit tests around abstractions wherever possible:

- Keychain account naming helper is deterministic.
- entry traversal finds entries by `kpexec.id`;
- missing `kpexec.id` is rejected;
- missing `kpexec.policy.v1` is rejected;
- duplicate `kpexec.id` is rejected.

If creating a real `.kdbx` fixture is awkward, isolate KeePass traversal behind a small adapter so most behavior can be tested without requiring a real unlocked database.

## Acceptance Criteria

- `cargo test` passes.
- `kpexec keychain set-db-password` stores the password in Keychain without echoing it.
- `kpexec check --entry cloudflare-pages-prod` can find a configured entry and report that required kpexec fields exist.
- The entry password and raw policy are never written to logs.
- Missing database, missing Keychain value, unlock failure, missing entry, and missing policy produce stable typed errors.

## Handoff Notes

Phase 03 should consume the raw policy JSON returned here and turn it into a validated policy model. Keep the KeePass entry API narrow: callers should ask for entry metadata, policy JSON, and eventually the secret field, not the entire database object.

