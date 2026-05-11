# Phase 04 - Telegram Approval

Source spec sections: 2.1, 9, 10, 11, 13, 15.

## Goal

Add always-on remote approval through Telegram before KeePass unlock and command execution for non-dry-run requests.

## Starting Point

Phase 03 can parse requested commands, load KeePass policy metadata, validate policy, and perform dry-run matching. No non-dry-run command should execute yet.

## Deliverables

- `kpexec telegram setup`.
- Telegram credentials stored in macOS Keychain.
- Approval request message with inline approve/deny buttons.
- Long-poll callback handling.
- Allowed-user validation.
- Approval timeout.
- One-pending-request lock.
- Non-dry-run flow performs approval before KeePass unlock and policy enforcement.

## Implementation Tasks

1. Add async HTTP support:
   - `tokio`
   - `reqwest`
2. Extend the Keychain abstraction for:
   - `telegram-bot-token`
   - `telegram-allowed-user-id`
3. Implement `kpexec telegram setup`:
   - prompt for bot token without echo if possible;
   - prompt for allowed Telegram user ID;
   - store both in Keychain;
   - never print or log the bot token.
4. Implement approval request rendering:
   - entry ID;
   - canonical requested executable;
   - argv as indexed values;
   - current working directory;
   - hostname;
   - no secret values.
5. Implement Telegram send:
   - send message through Bot API;
   - attach inline `Approve` and `Deny` buttons;
   - include an unguessable request nonce in callback data.
6. Implement long-poll callback wait:
   - accept only the configured Telegram user ID;
   - reject malformed callback data;
   - reject stale or wrong nonce;
   - return denied on explicit deny;
   - return timeout after `approval_timeout_sec`, default `300`.
7. Implement one-pending-request lock:
   - path: `~/Library/Application Support/kpexec/kpexec.lock`;
   - deny concurrent requests unless a later phase deliberately changes the behavior;
   - clean up lock on success, denial, timeout, and error.
8. Integrate non-dry-run control flow:
   - parse and canonicalize the requested command enough for display;
   - request Telegram approval;
   - if approved, continue to KeePass unlock and policy match;
   - after policy match, stop with a clear "execution not implemented until Phase 06" error if Phase 06 is not present.

## Out of Scope

- Secret injection.
- Subprocess execution.
- Redaction.
- Multiple concurrent approvals.
- Telegram account compromise mitigation.
- Local biometric approval.

## Tests

Use a fake approval transport for automated tests. Add tests for:

- message rendering includes entry, executable, argv, cwd, and hostname;
- bot token is never included in rendered messages or logs;
- allowed user approval succeeds;
- unknown user is denied;
- malformed callback is denied;
- deny button maps to exit code `3`;
- timeout maps to exit code `4`;
- concurrent request lock denies the second request;
- dry-run still skips approval.

Manual test with a real Telegram bot can be documented, but automated tests should not require external network access.

## Acceptance Criteria

- `kpexec telegram setup` stores Telegram settings in Keychain.
- Non-dry-run `kpexec run` sends an approval prompt before opening KeePass.
- Unknown users, malformed callbacks, explicit denial, timeouts, and concurrent requests deny by default.
- No raw secrets are loaded before approval.

## Handoff Notes

The approval prompt cannot know the matched policy command name before KeePass unlock because policy lives inside the encrypted database. That is expected. Phase 06 should reuse this approval gate before reading the secret and running Wrangler.

