# Contract for an agent using kpexec

This document is for a configured coding agent that invokes kpexec. It is
separate from the repository's [development-agent guide](agent-guide.md).

The human must first install kpexec, author the policies, and place the agent in
a sandbox or permission boundary verified to deny process-environment reads
(`KERN_PROCARGS2`, `ps -E`, and `ps eww`), debugger/task-port and process-memory
access, and unrestricted signaling. kpexec is not a credential-confidentiality
boundary for an unrestricted same-UID agent.

## Copy-paste agent policy

Add the following to the project instructions for an agent that may use an
existing kpexec installation:

```text
kpexec usage policy

- Treat kpexec as the only approved path for the capabilities it lists. Never
  request, display, copy, infer, persist, or search for a credential, recovery
  password, Keychain value, vault password, or raw KDBX content.
- Discover capabilities only with:
    kpexec entry list --json
    kpexec entry show <entry> --json
    kpexec check --entry <entry>
- Before a new invocation, preview it with:
    kpexec run --entry <entry> --command <command> --dry-run --json -- <args...>
- Execute only a named policy command:
    kpexec run --entry <entry> --command <command> --json -- <args...>
  Arguments after -- are appended verbatim. Do not add endpoint, hostname,
  config, plugin, upload, output-hook, or repository-changing flags unless the
  human-approved task explicitly requires them.
- Read kpexec_status and child_exit_code from JSON. A child exit in the 100–125
  range is not automatically a broker failure.
- Treat returned service data as sensitive even though kpexec redacts common
  representations of the injected credential.
- Never invoke init, db show-password, db rotate-password, entry add/edit/rm,
  entry add-command/rm-command, entry set-secret, or entry repin. Never ask the
  human to approve an authentication or Keychain prompt. Stop and request the
  human to perform policy or credential maintenance directly.
- Never edit or replace the kpexec config, vault, backup, lock, audit log,
  installed binary, pinned executable, or Keychain item. Never bypass a failed
  pin with --no-pin.
- If kpexec rejects a request, report the exact secret-free status and stop.
  Do not search the filesystem or environment for an alternate credential.
```

## What discovery reveals

`entry list` and `entry show` return policy metadata, not the stored credential.
They may reveal entry names, descriptions, injection-variable names, executable
paths, fixed argv prefixes, pin hashes, and output limits. Treat that metadata
as configuration and do not rewrite it.

`--dry-run` opens and parses the vault, verifies the policy and executable, and
prints the final argv without explicitly extracting or injecting the selected
credential and without spawning a child. It is a preview, not authorization to
broaden the requested arguments.

## Failure handling

Use the JSON envelope rather than guessing from the numeric process exit code.
Report `kpexec_status`, `message`, and `child_exit_code` when present. Do not
include raw trailing arguments if they may contain sensitive repository data.

Pin mismatch, malformed policy, identity disagreement, user-presence denial,
redaction failure, and timeout are fail-closed outcomes. A human must handle
repinning, policy repair, credential rotation, and recovery in a private
Terminal session.

The complete user workflow is in [Adoption and user guide](adoption.md). The
security assumptions behind this contract are in [Security and threat
model](security.md).
