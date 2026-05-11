# kpexec Implementation Phases

Source spec: [`../kpexec_wrangler_prefix_mvp_spec.md`](../kpexec_wrangler_prefix_mvp_spec.md)

These phase files split the Wrangler-first, prefix-only MVP into coding-agent-sized handoffs. Each phase assumes the previous phases have landed, keeps the MVP security boundary narrow, and leaves post-MVP policy features out of scope.

Core invariants across every phase:

- macOS-only MVP.
- Dedicated KeePass `.kdbx` database.
- KeePass unlock material and Telegram credentials stored in macOS Keychain.
- Agent-facing command uses a full absolute executable path.
- Policy matching is exact canonical executable path plus exact argv prefix.
- No PATH lookup for the requested executable.
- No shell execution.
- No flag grammar, regex matching, shell templates, or command-specific Wrangler parser.
- `CLOUDFLARE_API_TOKEN` is injected only into an approved, matched child process.
- Raw secret material must never be printed, returned, or logged.

## Phase Sequence

1. [`phase-01-cli-config-foundation.md`](phase-01-cli-config-foundation.md) - create the Rust CLI foundation, config, errors, logging, and command skeletons.
2. [`phase-02-keychain-keepass-read-path.md`](phase-02-keychain-keepass-read-path.md) - add Keychain-backed KeePass unlock and entry/policy reads.
3. [`phase-03-policy-matcher-dry-run.md`](phase-03-policy-matcher-dry-run.md) - implement policy validation, canonical executable matching, argv-prefix matching, and `--dry-run`.
4. [`phase-04-telegram-approval.md`](phase-04-telegram-approval.md) - implement Telegram setup, approval prompts, callback validation, timeout, and request locking.
5. [`phase-05-output-redaction.md`](phase-05-output-redaction.md) - build the redaction and byte-limit layer before real credentialed execution.
6. [`phase-06-wrangler-execution.md`](phase-06-wrangler-execution.md) - run approved Wrangler subprocesses with a conservative environment and redacted output.
7. [`phase-07-demo-doctor-validation.md`](phase-07-demo-doctor-validation.md) - finish doctor/check behavior, examples, quickstart docs, and validation tests.

## Handoff Rule

At the end of each phase, the coding agent should report:

- files changed;
- commands/tests run;
- behavior that is now implemented;
- explicit remaining work deferred to later phases.

