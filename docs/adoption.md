# Adoption and user guide

## Decide whether kpexec fits

kpexec v0.1.0 supports Apple silicon Macs running macOS 15 or newer. Use it
when your coding agent has a constrained execution environment and needs to
invoke a small number of trusted CLIs without receiving their reusable
credentials.

Do not rely on it to hide a credential from an unrestricted process running as
your macOS user: that process can inspect a non-`CS_RESTRICT` child's initial
environment through `KERN_PROCARGS2` (including `ps -E`/`ps eww`) without
debugger access. Hardened runtime does not hide that environment, though it
separately limits some debugger/task-port access to memory. Also avoid V1 when
safe use requires strict validation of trailing arguments or the working
directory. Read [Security and threat model](security.md) first.

## Install the release

Download the package and checksum file from the
[v0.1.0 release](https://github.com/crazytan/kpexec/releases/tag/v0.1.0), then
verify and install them:

```sh
cd ~/Downloads
shasum -a 256 -c SHA256SUMS
sudo installer -pkg kpexec-0.1.0-aarch64-apple-darwin.pkg -target /
kpexec --version
kpexec doctor
```

The expected v0.1.0 package SHA-256 is
`bffbd1545a9d89bf2d625867e7c52a660541334be1b2ca838b6b640346a29736`.
Do not substitute a locally built binary: production Keychain access requires
the release's Developer ID Team and exact signing identifier.

## Initialize and recover

Run:

```sh
kpexec init
kpexec doctor
```

Run initialization in a private Terminal window, not through an agent tool:
the one-time recovery password is intentionally printed for you to store.
Approve the local macOS authentication sheet. By default this creates
`~/Secrets/kpexec-agent.kdbx`, stores its generated password and canonical path
in an ACL-restricted Keychain item, and creates an untrusted path hint at
`~/.config/kpexec/config.toml`.

Initialization prints a recovery password once. Store it outside the agent's
readable filesystem. You can display it later with `kpexec db show-password`,
which requires another local authentication. Without either the Keychain item
or a recovery copy, the vault cannot be recovered.

KeePassXC is optional. If you edit the vault there, close KeePassXC before
using a kpexec mutation and run `kpexec check` afterwards.

## Prepare a pinnable CLI

Pinned executables and every directory above them must not be owned or writable
by your login user. User-owned Homebrew installations commonly fail this rule.
A simple pattern is to place a root-owned copy under an admin-owned directory:

```sh
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec/kpexec
sudo install -o root -g wheel -m 0555 "$(command -v gh)" \
  /usr/local/libexec/kpexec/gh
sudo chflags uchg /usr/local/libexec/kpexec/gh
```

Copy self-contained binaries, not scripts or shims that load user-writable code.
The immutable flag is defense in depth; kpexec's enforceability check is based
on ownership and write permissions across the canonical path.

Path ownership and pinning do not make the running process confidential. Keep
the agent inside a sandbox or permission boundary that has been tested to deny
ordinary process-environment reads (`KERN_PROCARGS2`, `ps -E`, and `ps eww`),
debugger/task-port access, and unrestricted signaling. Do not assume that a
generic process-info or sysctl denial covers all of those paths; probe the
deployed boundary end to end with synthetic values.

A self-contained hardened-runtime target without a debug entitlement remains
useful defense in depth against direct memory attachment. It does **not** hide
the target's initial environment. Apple platform and synthetic targets carrying
`CS_RESTRICT` omitted that environment in testing, but this is observed OS
behavior rather than a kpexec-supported contract. kpexec does not enforce or
diagnose the property, and a descendant can have different visibility. Do not
treat target signing as a substitute for the agent boundary.

## Add a credential and capability

The interactive wizard keeps the credential out of shell history:

```sh
kpexec entry add github
```

Example answers might use:

```text
entry id:          github
inject variable:  GH_TOKEN
command name:      pr-list
executable:        /usr/local/libexec/kpexec/gh
fixed prefix:      pr list
```

Choose the least-privileged service credential you can: minimal scopes, limited
repositories or resources, and a short lifetime. Review the CLI's global flags
before deciding that a prefix is narrow. In V1, the agent can append any
arguments and choose the working directory.

Inspect and validate what was stored:

```sh
kpexec entry show github
kpexec check --entry github
kpexec run --entry github --command pr-list --dry-run -- --limit 5
```

The dry run opens and parses the vault, resolves policy, and verifies the
executable. It does not explicitly extract or inject the selected credential or
start a child process. Remove `--dry-run` only after the argv is what you intended.

## Give an agent the narrow contract

For a ready-to-copy instruction block, use [Contract for an agent using
kpexec](consumer-agent.md). The short form is below.

An agent needs only these read/run operations:

```sh
kpexec entry list --json
kpexec entry show github --json
kpexec run --entry github --command pr-list --json -- --limit 5
```

Tell the agent:

- discover capabilities with `entry list --json`;
- call only `run`, naming an entry and command;
- put trailing arguments after `--`;
- use `--dry-run` to inspect argv before a new invocation;
- inspect `kpexec_status` and `child_exit_code` in JSON instead of classifying
  failures by numeric exit code;
- never request, display, or persist the recovery password;
- leave all `init`, entry, repin, and `db` mutations to the user.

`run` never prompts or reads stdin. It returns already-redacted stdout/stderr,
but the agent must still treat results as potentially sensitive service data.

## Operate and revoke

Useful maintenance commands are:

```sh
kpexec doctor
kpexec check
kpexec entry add-command github
kpexec entry rm-command github pr-list
kpexec entry set-secret github
kpexec entry rm github
kpexec db rotate-password
```

All mutations require local authentication. Removing an entry does not revoke
the upstream token; revoke it with the issuing service too.

After a legitimate CLI upgrade, replace the root-owned copy and explicitly
approve its new hash:

```sh
sudo chflags nouchg /usr/local/libexec/kpexec/gh
sudo install -o root -g wheel -m 0555 "$(command -v gh)" \
  /usr/local/libexec/kpexec/gh
sudo chflags uchg /usr/local/libexec/kpexec/gh
kpexec entry repin github
kpexec check --entry github
```

Until repinning, the stale hash fails closed before the credential is read or a
child starts. If you suspect exposure, revoke and replace the upstream
credential rather than merely repinning or editing policy.

## Healthy-state checklist

- `kpexec doctor` has no failures; investigate warnings rather than suppressing
  them.
- `kpexec check` reports current pins and valid policies.
- Service credentials remain minimally scoped and have active expiry/rotation
  plans.
- Authentication or Keychain prompts appear only when you initiated a mutation.
- Recovery material remains outside the agent's accessible files.
- Synthetic probes confirm that agent permissions still prevent
  `KERN_PROCARGS2`/`ps -E` environment reads and debugger/task-port access.
- Policies are reviewed after CLI upgrades and when the target service adds new
  global flags, config behavior, or plugins.
