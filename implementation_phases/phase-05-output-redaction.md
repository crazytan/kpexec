# Phase 05 - Output Redaction

Source spec sections: 5.5, 12, 14.3, 15, 16, 17.

## Goal

Build and test the output redaction layer before any real credentialed subprocess execution is enabled. This keeps Phase 06 from ever printing raw secret material.

## Starting Point

Phase 04 has approval flow and policy matching for non-dry-run requests, but does not yet run the child process.

## Deliverables

- Redaction module for stdout, stderr, and diagnostics.
- Exact secret redaction.
- JSON-escaped secret redaction.
- Shell-escaped secret redaction.
- URL-encoded secret redaction.
- Output byte limits.
- Fail-closed detection.
- Tests with representative secret variants.

## Implementation Tasks

1. Define a redaction API that accepts:
   - output bytes or text;
   - a secret wrapper type;
   - output policy limits;
   - stream label, such as stdout or stderr.
2. Implement redaction forms:
   - exact secret;
   - JSON-escaped secret;
   - shell-escaped secret;
   - URL-encoded secret.
3. Optionally redact cheap and reliable derived forms:
   - base64-encoded secret only if the implementation can do so without surprising false confidence.
4. Implement byte limits:
   - truncate stdout above `max_stdout_bytes`;
   - truncate stderr above `max_stderr_bytes`;
   - make truncation visible with a non-secret marker.
5. Implement fail-closed behavior:
   - after redaction, scan for raw secret material;
   - if found, suppress the entire affected output stream;
   - return redaction failure mapped to exit code `8`;
   - log only that redaction failed, never the secret or secret-derived values.
6. Integrate logging helpers:
   - logs may mention redaction occurred;
   - logs must not contain raw command output by default.
7. Keep secret values wrapped in `secrecy` or equivalent and zeroized where practical.

## Out of Scope

- Running Wrangler.
- Injecting environment variables.
- Generic token-looking substring detection unless it is simple and low-risk.
- Any policy expansion.

## Tests

Add tests for:

- exact secret is replaced.
- JSON-escaped secret is replaced.
- shell-escaped secret is replaced.
- URL-encoded secret is replaced.
- output below limits is unchanged except redaction.
- output above limits is truncated.
- raw secret remaining after redaction returns redaction failure.
- redaction failure suppresses affected output.
- empty secret is rejected before redaction.

## Acceptance Criteria

- Redaction tests pass without a real KeePass database or Telegram bot.
- No phase of the codebase can print a secret through the redaction API.
- Phase 06 can call this module directly around captured child output.

## Handoff Notes

This phase intentionally comes before real subprocess execution. The next phase should treat this module as mandatory and should not add any execution path that bypasses it.

