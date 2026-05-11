# kpexec MVP Spec — Wrangler-first, prefix-only policy

**Status:** minimum handoff spec for implementation validation  
**Date:** 2026-05-11  
**Working name:** `kpexec`  
**Primary target command:** Cloudflare Wrangler CLI  
**Policy model:** exact executable path + exact argv prefix only

This is a simplified revision of the original `kpexec` MVP spec. The major changes are:

1. Use **Cloudflare Wrangler CLI** as the first example target instead of GitHub CLI.
2. Inject the credential as `CLOUDFLARE_API_TOKEN` instead of `GH_TOKEN`.
3. Simplify policy matching to:
   - full absolute CLI path; and
   - fixed prefix of arguments after the executable.
4. Remove initial support for:
   - required flags;
   - allowed flags;
   - flag value constraints;
   - regex matching;
   - positional argument grammar;
   - command-specific policy language.

The purpose of this revision is to validate the core broker flow first:

> A coding agent can request a credentialed Wrangler action, the user approves remotely, `kpexec` retrieves a KeePass-backed Cloudflare API token, injects it only into the matched Wrangler subprocess, redacts output, and exits without returning the token to the agent.

---

## 0. Why Wrangler instead of GitHub CLI

The original example used `gh`, but GitHub CLI has its own authentication and local credential behavior, which can make it harder to validate the security property of `kpexec` as the credential injector.

Wrangler is a better first validation target because Cloudflare documents `CLOUDFLARE_API_TOKEN` as a Wrangler-supported environment variable for authentication in automation / CI-style situations.

Wrangler also has concrete deploy commands that are easy to reason about:

- `wrangler deploy` for Workers deployments.
- `wrangler pages deploy [DIRECTORY]` for Pages deployments.

For `kpexec`, avoid policy-matching `npx`, `pnpm`, `yarn`, or `npm`. Those are package runners, not the target CLI. The policy should point to the concrete Wrangler executable or shim path that will actually be executed.

---

## 1. MVP scope

`kpexec` is a local credential-backed command broker for coding agents and agent harnesses running on the user's own Mac.

The V1 target use case is:

- A coding agent runs locally on a user's Mac.
- The agent needs to deploy a Cloudflare Worker or Pages project using Wrangler.
- The user may be away from the machine.
- The user approves the request remotely.
- The Cloudflare API token is injected only into the approved Wrangler subprocess.
- The raw Cloudflare API token is never returned to the agent or placed in the LLM context.

### V1 platform

- macOS only.
- Single-user machine.
- Dedicated local KeePass `.kdbx` database.
- macOS Keychain for KeePass database unlock material and Telegram bot credentials.
- Telegram bot for remote approval.
- Cloudflare Wrangler CLI as the first supported target command.

### Explicit V1 non-goals

- No long-lived daemon.
- No short-lived unlock sessions.
- No local biometric approval requirement.
- No arbitrary secret retrieval.
- No arbitrary command execution.
- No multi-user support.
- No cloud service.
- No browser extension.
- No support for every password manager.
- No general-purpose policy language.
- No shell command templates.
- No flag-level policy in the first implementation.
- No command-specific Wrangler parser in the first implementation.

---

## 2. High-level design

### 2.1 Core concept

`kpexec` is a **credential-backed command broker**.

The agent does not receive a credential. Instead, the agent asks `kpexec` to run a command. `kpexec` asks the user for approval, opens the dedicated KeePass database, reads the selected entry and minimal policy, checks the requested command against the policy, injects the secret into the child process environment, redacts output, and exits.

```text
Agent
  |
  | kpexec run --entry cloudflare-pages-prod -- /absolute/path/to/wrangler pages deploy dist ...
  v
kpexec CLI
  |
  | 1. Parse requested command after `--`
  | 2. Canonicalize the executable path
  | 3. Request remote Telegram approval
  | 4. Read unlock material from macOS Keychain
  | 5. Open dedicated KeePass database
  | 6. Find entry by kpexec.id
  | 7. Read kpexec.policy.v1
  | 8. Match exact executable path + argv prefix
  | 9. Read secret field
  | 10. Inject secret into child process environment as CLOUDFLARE_API_TOKEN
  | 11. Run child process without shell
  | 12. Redact stdout/stderr
  | 13. Exit
  v
Agent receives redacted Wrangler output, not the Cloudflare API token
```

### 2.2 Recommended vault model

V1 should use a dedicated KeePass database for agent-accessible credentials.

Example:

```text
~/Secrets/kpexec-agent.kdbx
```

This database should contain only credentials the user is willing to expose through `kpexec` policies.

The user's main KeePass database should not be the default V1 target.

---

## 3. Trust model

### 3.1 Primary adversary

The primary adversary is prompt injection from untrusted content read by the coding agent, such as:

- repository files;
- issue comments;
- PR descriptions;
- web pages;
- generated code;
- tool output;
- build logs;
- deployment output.

### 3.2 Assumptions

The assumed environment is:

- single-user personal Mac;
- local malware is out of scope for V1;
- OS account compromise is out of scope for V1;
- compromised Telegram account is out of scope for V1;
- malicious prompt/tool content influencing the agent is in scope.

### 3.3 Security boundary

The security boundary is **not**:

> Wrangler is safe.

The actual security boundary is:

> A credential may only be injected into a subprocess invocation whose executable path and argv prefix match the KeePass-stored policy, after remote user approval.

This is a deliberately narrow first property.

### 3.4 Important limitation of the prefix-only policy

The prefix-only policy is intentionally coarse. If the policy allows:

```json
"argv_prefix": ["pages", "deploy"]
```

then every trailing argument after `pages deploy` is allowed.

That means V1 does **not** distinguish between:

```bash
wrangler pages deploy dist --project-name my-site
```

and:

```bash
wrangler pages deploy some-other-dir --project-name some-other-site --branch weird-branch
```

This is acceptable for the first validation milestone, but it is not a final least-privilege policy model.

---

## 4. KeePass entry model

Each agent-accessible KeePass entry contains:

1. The actual secret in the `password` field.
2. A stable `kpexec.id` custom field.
3. A `kpexec.policy.v1` custom field.

Example entry:

```text
Title: Cloudflare Pages Prod Token
Username: jia
Password: <cloudflare api token>

Custom fields:
  kpexec.id = cloudflare-pages-prod
  kpexec.policy.v1 = { ... JSON policy ... }
```

The agent refers to the credential by `kpexec.id`, not by KeePass title.

Example:

```bash
kpexec run --entry cloudflare-pages-prod -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages deploy dist \
  --project-name my-site \
  --branch main
```

V1 should reject entries that:

- do not have `kpexec.id`;
- do not have `kpexec.policy.v1`;
- have malformed JSON policy;
- have a policy whose `id` does not match `kpexec.id`;
- try to inject unsupported fields or destinations.

---

## 5. Minimal policy format

### 5.1 Format requirements

V1 policy is:

- JSON;
- stored inside the KeePass entry;
- small and declarative;
- deny-by-default;
- not a scripting language.

V1 policy does not support:

- YAML;
- shell templates;
- user-defined scripts;
- environment interpolation;
- path globs;
- regex command matching;
- flag parsing;
- required flags;
- allowed flags;
- flag value constraints;
- policy includes/imports;
- remote policy references.

### 5.2 Minimal policy schema

```json
{
  "schema": "kpexec.policy.v1",
  "id": "cloudflare-pages-prod",
  "description": "Allow Wrangler Pages deploy for the configured project",

  "secret": {
    "field": "password",
    "inject": {
      "type": "env",
      "name": "CLOUDFLARE_API_TOKEN"
    }
  },

  "commands": [
    {
      "name": "wrangler-pages-deploy",
      "exe": "/Users/jia/src/my-site/node_modules/.bin/wrangler",
      "argv_prefix": ["pages", "deploy"]
    }
  ],

  "output": {
    "max_stdout_bytes": 200000,
    "max_stderr_bytes": 50000,
    "redact_secret": true
  }
}
```

### 5.3 Secret block

```json
{
  "secret": {
    "field": "password",
    "inject": {
      "type": "env",
      "name": "CLOUDFLARE_API_TOKEN"
    }
  }
}
```

V1 supported secret fields:

```text
password
```

V1 supported injection types:

```text
env
```

V1 unsupported injection types:

```text
stdin
argv
file
template
```

V1 should inject only one secret env var for the Wrangler demo:

```text
CLOUDFLARE_API_TOKEN
```

Deprecated Cloudflare variables such as `CF_API_TOKEN` should not be used for the demo.

### 5.4 Command block

Each command block defines one allowed command prefix.

```json
{
  "name": "wrangler-pages-deploy",
  "exe": "/Users/jia/src/my-site/node_modules/.bin/wrangler",
  "argv_prefix": ["pages", "deploy"]
}
```

Rules:

- `name` is for logs and approval display.
- `exe` must be an absolute path.
- The agent-facing command must also provide an absolute executable path.
- `kpexec` does not perform PATH lookup in the first implementation.
- `argv_prefix` is matched exactly against the arguments after the executable.
- The requested argv must be at least as long as `argv_prefix`.
- All trailing arguments after the prefix are allowed in this minimal policy model.
- No shell is used.
- `npx`, `npm`, `pnpm`, and `yarn` should not be used as the policy executable for V1.

### 5.5 Output block

```json
{
  "output": {
    "max_stdout_bytes": 200000,
    "max_stderr_bytes": 50000,
    "redact_secret": true
  }
}
```

Rules:

- truncate stdout above `max_stdout_bytes`;
- truncate stderr above `max_stderr_bytes`;
- redact exact secret from stdout and stderr;
- redact common escaped forms of the secret;
- fail closed if raw secret material is detected after redaction;
- never write the raw secret to logs.

---

## 6. Policy matching

### 6.1 Matching algorithm

For each `kpexec run` invocation:

```text
1. Parse kpexec CLI args.
2. Split arguments after `--` as the requested subprocess.
3. Require requested subprocess argv to be non-empty.
4. Require requested executable to be an absolute path.
5. Canonicalize requested executable path.
6. Build a canonical command representation.
7. Send Telegram approval prompt using canonical representation.
8. If denied or timed out, exit.
9. Read KeePass DB unlock material from macOS Keychain.
10. Open dedicated KeePass DB.
11. Find entry by kpexec.id.
12. Read and parse kpexec.policy.v1.
13. Check policy schema and ID.
14. For each command block:
    a. Canonicalize policy exe path.
    b. Compare canonical requested executable path to canonical policy exe path.
    c. Compare requested argv prefix to policy argv_prefix.
15. Reject if zero command blocks match.
16. Reject if more than one command block matches.
17. Read secret field.
18. Build child process environment.
19. Inject secret as CLOUDFLARE_API_TOKEN.
20. Run subprocess without shell.
21. Redact stdout/stderr.
22. Return redacted output and subprocess exit code.
```

### 6.2 Prefix matching definition

Given this policy:

```json
{
  "exe": "/Users/jia/src/my-site/node_modules/.bin/wrangler",
  "argv_prefix": ["pages", "deploy"]
}
```

This request matches:

```bash
kpexec run --entry cloudflare-pages-prod -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages deploy dist \
  --project-name my-site
```

This request does not match because the executable is not the full Wrangler path:

```bash
kpexec run --entry cloudflare-pages-prod -- \
  npx wrangler pages deploy dist --project-name my-site
```

This request does not match because the prefix differs:

```bash
kpexec run --entry cloudflare-pages-prod -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages secret put API_KEY
```

This request does not match because the executable is not absolute:

```bash
kpexec run --entry cloudflare-pages-prod -- \
  wrangler pages deploy dist --project-name my-site
```

### 6.3 Canonicalization rules

V1 should canonicalize both the requested executable and the policy executable before comparison.

Minimum behavior:

- reject non-absolute executable paths;
- resolve symlinks where the platform permits it;
- reject missing executable paths;
- reject directories;
- reject paths that are not executable by the current user;
- compare canonical path strings exactly.

If canonicalization fails, deny by default.

---

## 7. Agent-facing CLI

Main command:

```bash
kpexec run --entry <kpexec.id> -- /absolute/path/to/wrangler [args...]
```

### 7.1 Pages deploy example

```bash
kpexec run --entry cloudflare-pages-prod -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages deploy dist \
  --project-name my-site \
  --branch main
```

Policy:

```json
{
  "schema": "kpexec.policy.v1",
  "id": "cloudflare-pages-prod",
  "description": "Allow Wrangler Pages deploy for my-site",
  "secret": {
    "field": "password",
    "inject": {
      "type": "env",
      "name": "CLOUDFLARE_API_TOKEN"
    }
  },
  "commands": [
    {
      "name": "wrangler-pages-deploy",
      "exe": "/Users/jia/src/my-site/node_modules/.bin/wrangler",
      "argv_prefix": ["pages", "deploy"]
    }
  ],
  "output": {
    "max_stdout_bytes": 200000,
    "max_stderr_bytes": 50000,
    "redact_secret": true
  }
}
```

### 7.2 Workers deploy example

```bash
kpexec run --entry cloudflare-worker-prod -- \
  /Users/jia/src/my-worker/node_modules/.bin/wrangler deploy \
  --config wrangler.jsonc \
  --env production
```

Policy:

```json
{
  "schema": "kpexec.policy.v1",
  "id": "cloudflare-worker-prod",
  "description": "Allow Wrangler Worker deploy",
  "secret": {
    "field": "password",
    "inject": {
      "type": "env",
      "name": "CLOUDFLARE_API_TOKEN"
    }
  },
  "commands": [
    {
      "name": "wrangler-worker-deploy",
      "exe": "/Users/jia/src/my-worker/node_modules/.bin/wrangler",
      "argv_prefix": ["deploy"]
    }
  ],
  "output": {
    "max_stdout_bytes": 200000,
    "max_stderr_bytes": 50000,
    "redact_secret": true
  }
}
```

---

## 8. Runtime environment for Wrangler

The policy stays simple, but the execution environment should still be conservative.

### 8.1 Environment construction

V1 should avoid blindly inheriting the agent's full environment.

Recommended behavior:

1. Start from a minimal clean environment.
2. Add only required baseline variables.
3. Inject the Cloudflare API token as `CLOUDFLARE_API_TOKEN`.
4. Add non-secret Wrangler safety/config variables where useful.
5. Explicitly remove old or conflicting Cloudflare credential variables.

Recommended variables to set:

```text
CLOUDFLARE_API_TOKEN=<secret from KeePass password field>
WRANGLER_LOG_SANITIZE=true
WRANGLER_SEND_METRICS=false
WRANGLER_SEND_ERROR_REPORTS=false
FORCE_COLOR=0
NO_COLOR=1
```

Recommended variables to unset or avoid inheriting:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_API_KEY
CLOUDFLARE_EMAIL
CF_API_TOKEN
CF_API_KEY
CF_EMAIL
WRANGLER_LOG
WRANGLER_LOG_PATH
CLOUDFLARE_API_BASE_URL
HTTP_PROXY
HTTPS_PROXY
ALL_PROXY
NODE_OPTIONS
```

Rationale:

- The child process should use the token selected by `kpexec`, not a token already present in the agent environment.
- Deprecated Cloudflare variables should not be part of the demo.
- Debug/log path variables can create extra leakage surfaces.
- Proxy and Node runtime variables can alter execution behavior.

### 8.2 Project `.env` caveat

Wrangler can load environment variables from project `.env` files. For the validation demo, the project should not contain `CLOUDFLARE_API_TOKEN`, `CF_API_TOKEN`, `CLOUDFLARE_API_KEY`, or `CF_API_KEY` in `.env` or `.env.<environment>` files.

`kpexec doctor` should warn if it detects Cloudflare credential variable names in project `.env*` files near the working directory.

### 8.3 Existing Wrangler login caveat

For the cleanest validation, do not rely on `wrangler login` or preexisting local Wrangler auth state. The demo should prove that the credential used by Wrangler comes from the `CLOUDFLARE_API_TOKEN` value injected by `kpexec`.

---

## 9. Approval model

V1 uses always-on remote approval.

Each `kpexec run` request sends a Telegram approval message before KeePass unlock and command execution.

Example approval message:

```text
kpexec request

Entry:
cloudflare-pages-prod

Executable:
/Users/jia/src/my-site/node_modules/.bin/wrangler

Argv:
[0] pages
[1] deploy
[2] dist
[3] --project-name
[4] my-site
[5] --branch
[6] main

Working directory:
/Users/jia/src/my-site

Hostname:
jias-macbook.local

Approve?
[Yes] [No]
```

V1 approval behavior:

- Telegram Bot API long polling.
- Configured allowed Telegram user ID.
- One pending approval at a time.
- Default timeout: 5 minutes.
- Deny on timeout.
- Deny on unknown Telegram user.
- Deny on malformed callback.
- Deny on concurrent request unless explicitly configured later.

Because the policy is stored inside the encrypted KeePass database, the first approval prompt may not know the matched policy command name until after unlock. V1 can show the canonical requested command before unlock, then enforce the policy after unlock.

---

## 10. User setup commands

Initialize config:

```bash
kpexec init --db ~/Secrets/kpexec-agent.kdbx
```

Store KeePass DB password in macOS Keychain:

```bash
kpexec keychain set-db-password
```

Configure Telegram approval:

```bash
kpexec telegram setup
```

Validate config:

```bash
kpexec doctor
```

Validate an entry and its policy:

```bash
kpexec check --entry cloudflare-pages-prod
```

Dry-run policy evaluation without injecting the secret or running the subprocess:

```bash
kpexec run --entry cloudflare-pages-prod --dry-run -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages deploy dist \
  --project-name my-site \
  --branch main
```

---

## 11. Config file

Path:

```text
~/.config/kpexec/config.toml
```

Example:

```toml
db_path = "/Users/jia/Secrets/kpexec-agent.kdbx"
approval_transport = "telegram"
approval_timeout_sec = 300
```

Do not store secrets in this config file.

Suggested Keychain service:

```text
dev.kpexec
```

Suggested Keychain accounts:

```text
db-password:<db-fingerprint>
telegram-bot-token
telegram-allowed-user-id
```

---

## 12. Output behavior

### 12.1 Default output

`kpexec` returns the subprocess output after redaction.

```text
stdout: redacted subprocess stdout
stderr: kpexec diagnostics + redacted subprocess stderr
```

Example stderr:

```text
[kpexec] approval accepted by configured Telegram user
[kpexec] matched policy: wrangler-pages-deploy
```

### 12.2 Redaction requirements

V1 must redact:

- exact secret;
- JSON-escaped secret;
- shell-escaped secret;
- URL-encoded secret.

Optional V1 redaction:

- common token-looking substrings;
- base64-encoded secret, if cheap and reliable.

### 12.3 Fail-closed behavior

If raw secret material appears in subprocess output after redaction, `kpexec` should:

1. suppress the output;
2. return a redaction failure;
3. log that redaction failed without logging the secret.

Example:

```text
[kpexec] output suppressed: secret material detected in subprocess output
```

---

## 13. Exit codes

```text
0   success
1   subprocess failed
2   denied by policy
3   denied by user
4   approval timeout
5   KeePass unlock failed
6   entry not found
7   malformed policy
8   output redaction failure
9   configuration error
10  internal error
```

---

## 14. Rust implementation notes

### 14.1 Suggested crates

Core:

```text
clap              CLI parsing
serde             serialization/deserialization
serde_json        policy parsing
toml              config parsing
keepass           KDBX reading
security-framework or keyring
                  macOS Keychain integration
reqwest           Telegram Bot API HTTP calls
tokio             async runtime
zeroize           best-effort secret cleanup
secrecy           secret wrapper types
thiserror         typed errors
tracing           structured logging
urlencoding       URL-encoded redaction support
```

Subprocess:

```text
std::process::Command
```

Do not invoke a shell.

### 14.2 Filesystem layout

Config:

```text
~/.config/kpexec/config.toml
```

Logs:

```text
~/Library/Logs/kpexec/kpexec.log
```

Lock file:

```text
~/Library/Application Support/kpexec/kpexec.lock
```

Dedicated KeePass DB:

```text
~/Secrets/kpexec-agent.kdbx
```

### 14.3 Logging

Logs must never contain:

- raw Cloudflare API token;
- secret-derived values;
- full Keychain values;
- Telegram bot token;
- KeePass DB password.

Logs may contain:

- timestamp;
- entry ID;
- matched policy command name;
- approval result;
- subprocess exit code;
- redaction occurred: yes/no;
- policy denial reason;
- command hash.

Avoid logging the full command by default because deployment paths, branch names, config paths, or commit messages may contain sensitive information.

---

## 15. Implementation plan

### Milestone 1: local CLI skeleton

Deliver:

- `kpexec init`;
- `kpexec doctor`;
- config loading;
- structured errors;
- basic logging.

### Milestone 2: KeePass read path

Deliver:

- open `.kdbx`;
- read DB password from Keychain;
- find entry by `kpexec.id`;
- read `kpexec.policy.v1`;
- parse policy JSON.

### Milestone 3: prefix-only policy engine

Deliver:

- require absolute requested executable path;
- canonicalize executable path;
- exact executable path matching;
- exact argv prefix matching;
- reject no-match and multi-match;
- `--dry-run`.

### Milestone 4: Telegram approval

Deliver:

- `kpexec telegram setup`;
- send approval message;
- inline approve/deny buttons;
- callback validation;
- timeout behavior;
- one-pending-request lock.

### Milestone 5: Wrangler subprocess execution

Deliver:

- clean/minimal environment construction;
- inject `CLOUDFLARE_API_TOKEN`;
- no-shell execution;
- subprocess timeout;
- stdout/stderr capture;
- exit code propagation.

### Milestone 6: output redaction

Deliver:

- exact secret redaction;
- escaped secret redaction;
- URL-encoded redaction;
- fail-closed detection;
- output byte limits.

### Milestone 7: Wrangler demo

Deliver:

- example KeePass entry;
- example Pages deploy policy;
- example Workers deploy policy;
- README quickstart;
- negative tests for prefix mismatch and executable mismatch.

---

## 16. Validation tests

Use a dedicated Cloudflare API token with minimal permissions and an expiration date where practical.

### T1: dry-run match succeeds

Command:

```bash
kpexec run --entry cloudflare-pages-prod --dry-run -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages deploy dist \
  --project-name my-site
```

Expected:

```text
policy match: wrangler-pages-deploy
no KeePass secret read
no subprocess execution
no token injection
```

### T2: executable mismatch denied

Command:

```bash
kpexec run --entry cloudflare-pages-prod --dry-run -- \
  npx wrangler pages deploy dist --project-name my-site
```

Expected:

```text
denied by policy
reason: requested executable is not absolute or does not match policy exe
```

### T3: prefix mismatch denied

Command:

```bash
kpexec run --entry cloudflare-pages-prod --dry-run -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages secret put API_KEY
```

Expected:

```text
denied by policy
reason: argv prefix does not match ["pages", "deploy"]
```

### T4: approved run injects token only into child process

Command:

```bash
kpexec run --entry cloudflare-pages-prod -- \
  /Users/jia/src/my-site/node_modules/.bin/wrangler pages deploy dist \
  --project-name my-site
```

Expected:

```text
Telegram approval requested
approval accepted
KeePass entry opened
policy matched
CLOUDFLARE_API_TOKEN set only in child env
Wrangler executes
stdout/stderr redacted
raw token not printed
```

### T5: raw token never appears in output or logs

Procedure:

- Run T4.
- Search captured stdout, stderr, and logs for the raw token.

Expected:

```text
no raw token found
```

### T6: project .env credential warning

Procedure:

- Add `CLOUDFLARE_API_TOKEN=example` to a local `.env` file.
- Run `kpexec doctor` from that project.

Expected:

```text
warning: project .env contains Cloudflare credential variable name
```

---

## 17. Acceptance criteria

Hard success criteria:

- The agent-facing command requires a full absolute executable path.
- The policy stores a full absolute executable path.
- Matching uses canonical executable path equality plus exact argv prefix equality.
- `npx wrangler ...` is denied unless the policy explicitly points to `npx`, which the demo must not do.
- `wrangler pages secret ...` is denied by prefix mismatch when the policy prefix is `["pages", "deploy"]`.
- The Cloudflare API token is injected as `CLOUDFLARE_API_TOKEN` only into the matched child process.
- The raw token is never returned to the agent.
- The raw token is never logged.
- The subprocess is executed without a shell.
- Deny by default on malformed policy, no match, multiple matches, approval timeout, or redaction failure.

Hard failure if any of these occur:

- A nonmatching executable receives the Cloudflare API token.
- A nonmatching argv prefix receives the Cloudflare API token.
- The token appears in stdout, stderr, or logs.
- A package runner such as `npx` is used as the demo policy executable.
- The implementation performs shell string execution.
- The implementation accepts a bare executable name through PATH lookup in the first implementation.

---

## 18. Post-MVP policy extensions

These are intentionally out of scope for the first implementation:

- required flags;
- allowed flags;
- flag value constraints;
- project name allowlist;
- branch allowlist;
- cwd restrictions;
- binary hash pinning;
- Wrangler-specific command grammar;
- network allowlisting;
- signed policy versions;
- policy editing UI;
- MCP server mode;
- local biometric approval;
- daemon/session cache;
- non-KeePass vaults.

The next policy step after this MVP should probably be **cwd + trailing-argument constraints**, not a full policy language.

---

## 19. MVP summary

V1 should be exactly this:

```text
Platform: macOS only
Vault: dedicated KeePass .kdbx
Unlock: macOS Keychain
Approval: Telegram, always required
Policy storage: KeePass custom field kpexec.policy.v1
Target command: Cloudflare Wrangler CLI
Injection mode: env only
Injected env var: CLOUDFLARE_API_TOKEN
Matcher: full absolute executable path + argv prefix only
PATH lookup: no
Shell execution: no
Output: redact stdout/stderr
Daemon: none
Session cache: none
```

One-line product description:

> `kpexec` lets local coding agents perform approved Cloudflare Wrangler actions using KeePass-backed credentials, without the agent ever receiving the Cloudflare API token.

---

## Source notes

- Original source spec: user-provided `kpexec_mvp_spec(1).md`.
- Cloudflare Wrangler system environment variables documentation, including `CLOUDFLARE_API_TOKEN`, `WRANGLER_LOG_SANITIZE`, and deprecated `CF_*` variables: https://developers.cloudflare.com/workers/wrangler/system-environment-variables/
- Cloudflare Wrangler commands overview: https://developers.cloudflare.com/workers/wrangler/commands/
- Cloudflare Wrangler Pages commands, including `pages deploy`: https://developers.cloudflare.com/workers/wrangler/commands/pages/
- Cloudflare Wrangler Workers commands, including `deploy`: https://developers.cloudflare.com/workers/wrangler/commands/workers/
- Cloudflare API token permissions and restrictions: https://developers.cloudflare.com/fundamentals/api/reference/permissions/ and https://developers.cloudflare.com/fundamentals/api/how-to/restrict-tokens/
