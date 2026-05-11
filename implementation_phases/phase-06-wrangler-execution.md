# Phase 06 - Wrangler Subprocess Execution

Source spec sections: 2.1, 5.3, 6, 8, 12, 13, 15, 16, 17.

## Goal

Complete the approved run path: after Telegram approval and policy match, read the KeePass password field, inject it as `CLOUDFLARE_API_TOKEN` into the matched Wrangler child process, run without a shell, redact output, and return the correct `kpexec` exit code.

## Starting Point

Phase 05 provides a tested redaction layer. Phase 04 provides approval. Phase 03 provides policy matching. Phase 02 provides KeePass entry access.

## Deliverables

- Secret field read from KeePass password only after approval and policy match.
- Conservative child environment construction.
- `CLOUDFLARE_API_TOKEN` injection.
- No-shell child process execution.
- Subprocess timeout.
- Captured stdout/stderr passed through Phase 05 redaction.
- Nonzero child failures mapped to the MVP subprocess-failed exit behavior.

## Implementation Tasks

1. Extend the KeePass entry API:
   - read only the `password` field as the secret;
   - return it as a secret wrapper;
   - reject empty secrets.
2. Build the child environment from an allowlist:
   - start from a minimal clean environment;
   - include only required baseline variables such as `HOME`, `USER`, `LOGNAME`, `TMPDIR`, and a documented minimal `PATH` if needed for `/usr/bin/env node` Wrangler shims;
   - set `CLOUDFLARE_API_TOKEN=<secret>`;
   - set `WRANGLER_LOG_SANITIZE=true`;
   - set `WRANGLER_SEND_METRICS=false`;
   - set `WRANGLER_SEND_ERROR_REPORTS=false`;
   - set `FORCE_COLOR=0`;
   - set `NO_COLOR=1`.
3. Explicitly avoid inheriting or setting:
   - `CLOUDFLARE_API_KEY`
   - `CLOUDFLARE_EMAIL`
   - `CF_API_TOKEN`
   - `CF_API_KEY`
   - `CF_EMAIL`
   - `WRANGLER_LOG`
   - `WRANGLER_LOG_PATH`
   - `CLOUDFLARE_API_BASE_URL`
   - `HTTP_PROXY`
   - `HTTPS_PROXY`
   - `ALL_PROXY`
   - `NODE_OPTIONS`
4. Run the child process:
   - use `std::process::Command` or async equivalent;
   - pass executable and argv as separate values;
   - do not invoke a shell;
   - set current directory to the caller's working directory unless the project already has a more explicit run context;
   - capture stdout and stderr.
5. Add subprocess timeout:
   - choose a conservative default and make it configurable only if already compatible with the config model;
   - kill the child on timeout;
   - report a typed error without printing raw output.
6. Redact output:
   - apply stdout and stderr limits from the policy;
   - redact before writing to parent stdout/stderr;
   - on redaction failure, suppress output and exit `8`.
7. Map exits:
   - child success returns `0`;
   - child failure returns `1` and may include the child exit status in a non-secret diagnostic;
   - policy denial remains `2`;
   - user denial remains `3`;
   - timeout remains `4` for approval timeout; subprocess timeout should use configuration or subprocess failure unless the project defines a separate internal error.

## Out of Scope

- Shell command templates.
- PATH lookup for requested executable.
- Package-runner demo policies.
- Wrangler command grammar.
- Persistent daemon/session cache.

## Tests

Use local helper executables/scripts for tests. Add tests for:

- matching helper command receives `CLOUDFLARE_API_TOKEN`.
- nonmatching executable never receives the token.
- nonmatching argv prefix never receives the token.
- inherited Cloudflare credential variables are not present in the child.
- proxy and `NODE_OPTIONS` variables are not present in the child.
- subprocess is invoked without a shell.
- child stdout/stderr are redacted.
- child nonzero exit maps to `1`.
- redaction failure maps to `8`.

## Acceptance Criteria

- T4 approved run injects token only into the matched child process.
- T5 raw token never appears in stdout, stderr, or logs.
- A bare executable name is still rejected.
- `npx wrangler ...` is still denied by the demo policy.
- `wrangler pages secret ...` is denied when the policy prefix is `["pages", "deploy"]`.

## Handoff Notes

This phase completes the core broker flow. Phase 07 should focus on usability, validation docs, examples, and hardening checks rather than changing the authorization model.

