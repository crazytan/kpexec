# Phase 03 - Policy Matcher and Dry Run

Source spec sections: 4, 5, 6, 7, 13, 15, 16, 17.

## Goal

Implement the V1 policy schema, canonical executable matching, exact argv-prefix matching, and `--dry-run` policy evaluation. This is the core security boundary of the MVP.

## Starting Point

Phase 02 can open the configured KeePass database, find entries by `kpexec.id`, and return the raw `kpexec.policy.v1` JSON.

## Deliverables

- Strongly typed `kpexec.policy.v1` model.
- Policy parser and validator.
- Requested command canonicalization.
- Exact executable path matching.
- Exact argv-prefix matching.
- No-match and multi-match rejection.
- `kpexec run --entry <id> --dry-run -- <absolute-exe> [args...]`.

## Implementation Tasks

1. Add `serde_json`.
2. Model the policy schema:
   - `schema`
   - `id`
   - `description`
   - `secret.field`
   - `secret.inject.type`
   - `secret.inject.name`
   - `commands[]`
   - `output.max_stdout_bytes`
   - `output.max_stderr_bytes`
   - `output.redact_secret`
3. Validate policy:
   - `schema == "kpexec.policy.v1"`;
   - policy `id` matches KeePass custom field `kpexec.id`;
   - `secret.field == "password"`;
   - `secret.inject.type == "env"`;
   - `secret.inject.name == "CLOUDFLARE_API_TOKEN"`;
   - each command has an absolute `exe`;
   - output byte limits are present and reasonable;
   - malformed JSON or unsupported values map to exit code `7`.
4. Canonicalize executables:
   - reject non-absolute requested executables;
   - reject missing executable paths;
   - reject directories;
   - reject paths not executable by the current user;
   - resolve symlinks where macOS permits;
   - compare canonical path strings exactly.
5. Implement prefix matching:
   - requested argv must be at least as long as `argv_prefix`;
   - each prefix element must match exactly and positionally;
   - trailing args after the prefix are allowed;
   - zero matching commands maps to exit code `2`;
   - more than one matching command maps to exit code `2`.
6. Implement `--dry-run`:
   - skip Telegram approval;
   - open KeePass only as needed to read entry metadata and policy;
   - do not read the password field;
   - do not inject any environment variable;
   - do not execute a subprocess;
   - print a concise match result.
7. Add diagnostics that avoid full command logging by default. It is acceptable for explicit dry-run output to show the requested command representation because that is the requested operation, but logs should remain conservative.

## Out of Scope

- Required flags.
- Allowed flags.
- Flag value constraints.
- Regex, glob, or shell matching.
- Wrangler-specific command parsing.
- Telegram approval.
- Secret reading or injection.
- Subprocess execution.

## Tests

Add tests for:

- valid Pages deploy policy parses.
- valid Workers deploy policy parses.
- unsupported secret field is rejected.
- unsupported injection target is rejected.
- policy ID mismatch is rejected.
- requested executable must be absolute.
- bare `wrangler` is denied.
- `npx wrangler ...` is denied for a Wrangler executable policy.
- executable mismatch is denied.
- argv prefix mismatch is denied.
- trailing args after a matching prefix are allowed.
- multiple matching command blocks are denied.
- dry-run success does not call the secret-read path.

## Acceptance Criteria

- T1 dry-run match succeeds.
- T2 executable mismatch is denied.
- T3 prefix mismatch is denied.
- `npx`, `npm`, `pnpm`, and `yarn` are not accepted unless a policy explicitly points to their absolute executable path; the demo policy must not do that.
- No normal run can receive a secret yet because secret injection is still out of scope.

## Handoff Notes

This phase defines the core authorization primitive. Later phases may add approval, redaction, and execution around it, but should not widen matching semantics.

