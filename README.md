# kpexec

**Give a local coding agent permission to run a named action without routinely
handing the credential to the agent.**

kpexec is a small, local credential broker for macOS. A person stores a secret
and defines the commands allowed to receive it. An agent asks for an entry and a
command by name; kpexec resolves the executable, verifies its pinned bytes,
constructs the argument vector, injects the secret into that child process, and
returns bounded, redacted output.

```text
agent ──▶ kpexec run --entry github --command pr-list -- --state open
              │
              ├─ open the dedicated KDBX4 vault
              ├─ resolve a user-approved command template
              ├─ verify the executable path and SHA-256 pin
              ├─ exec it directly with a minimal environment
              └─ return bounded, redacted output and an exit status
```

The first release is available now:
[kpexec v0.1.0](https://github.com/crazytan/kpexec/releases/tag/v0.1.0).

> [!IMPORTANT]
> kpexec is **not** a security boundary against an agent with an unrestricted
> same-user shell. On macOS, such an agent may attach a debugger or obtain a
> task port for an attachable credential-bearing child and read its environment
> or memory. Use kpexec with an agent sandbox or permission system that blocks
> process debugging and inspection. kpexec reduces routine secret exposure and
> constrains how credentials are used; it does not turn unrestricted local code
> into a safe principal. Read the [threat model](https://github.com/crazytan/kpexec/blob/main/docs/security.md) before adoption.

## Why this exists

Coding agents often need to call tools such as `gh`, `aws`, or a deployment CLI.
Putting a token in the agent's environment, prompt, config, or command line gives
the agent the credential itself. It can then use that credential through any
program, send it anywhere, or accidentally reproduce it in tool output.

kpexec changes the interface from “here is a token” to “you may request this
named operation.” The user remains responsible for deciding which executable,
fixed argument prefix, and trailing arguments are safe. The agent can discover
and invoke that policy, but normal operation never asks it to handle the stored
credential.

The project publishes its design, threat model, and test record because a
security claim without an exact boundary and artifact is difficult to evaluate.
Some checks can run in CI; Keychain prompts, LocalAuthentication behavior,
signing, notarization, installation, and real-token behavior require supervised
tests on macOS. The [testing record](https://github.com/crazytan/kpexec/blob/main/docs/testing.md) separates those forms of
evidence and ties the v0.1.0 results to the released package.

## What it is—and is not

kpexec is:

- a local broker for one dedicated, standard KDBX4 vault;
- a policy layer around direct child-process execution;
- an unattended run path for commands a user approved in advance;
- a complement to an agent sandbox, OS permissions, and narrowly scoped tokens.

kpexec is not:

- a general sandbox, malware defense, or protection from account compromise;
- a remote secrets service or multi-user authorization system;
- a per-run approval dialog—the agent may repeat an allowed command unattended;
- proof that an allowed CLI, its flags, its working directory, or its network
  destinations are safe.

## Design and technical approach

Each vault entry contains one credential and one or more named command
templates. A template fixes an absolute executable path and leading arguments.
The caller may supply only trailing arguments:

```text
argv = [policy executable] + [policy prefix] + [caller's trailing arguments]
env  = minimal baseline + policy's non-secret variables + one injected secret
```

The main controls are:

- **No shell and no executable supplied by the agent.** kpexec uses direct
  process execution; trailing values remain separate argv elements.
- **Executable pinning.** The canonical executable's SHA-256 is recorded when
  the policy is approved and checked immediately before execution. Pinned files
  and their ancestors must be admin-owned and non-writable by the user. An
  executable upgrade fails closed until the user approves `entry repin`.
- **A defined child environment.** The child receives a minimal baseline,
  explicitly configured non-secret variables, and the secret in one named
  environment variable. It does not inherit the caller's full environment.
- **Human-approved mutation.** Creating, editing, removing, or repinning policy
  requires a local graphical LocalAuthentication check (Touch ID or account
  password fallback). Remote and non-graphical security sessions are rejected.
- **A protected vault key.** Policies and secrets are authenticated and
  encrypted in KDBX4. The generated vault password is stored in the macOS
  Keychain and bound to the released kpexec signing identity and identifier.
- **Bounded, deferred output.** stdout and stderr are captured up to policy
  limits and common literal/escaped forms of the secret are redacted before
  emission. This is defense in depth, not protection from deliberate encoding
  or network exfiltration by the child.
- **Fail-closed parsing and lookup.** Unknown entries, commands, policy fields,
  duplicate IDs, stale pins, ambiguous Keychain state, and malformed data are
  rejected.

The complete rationale and implementation boundaries are in the
[design document](https://github.com/crazytan/kpexec/blob/main/docs/design.md).

## Security properties and limits

Within the documented threat model and a correctly installed release:

- policy selects the executable and fixed prefix; a run request cannot replace
  the executable;
- a changed pinned executable is rejected before it is spawned;
- the vault password is not available through the normal agent-facing command;
- vault and policy mutation requires local user presence;
- raw trailing arguments and credentials are excluded from kpexec's audit log;
- kpexec does not intentionally print the credential, and applies output
  redaction before returning child output.

Important residual risks include:

- an unrestricted same-user process may debug or inspect an attachable child;
- trailing arguments can redirect many CLIs to attacker-controlled endpoints;
- the caller's working directory is inherited, so repository-controlled config
  may affect an allowed tool;
- pinning an interpreter or shim does not pin the scripts or modules it loads;
- output redaction cannot stop encoding, transformation, or network exfiltration;
- the encrypted vault can be rolled back to an older valid version, potentially
  restoring a revoked policy;
- anyone who obtains the vault password bypasses both confidentiality and the
  intended write gate;
- approving an unexpected Keychain or LocalAuthentication prompt can defeat the
  human-presence boundary.

See [Security and threat model](https://github.com/crazytan/kpexec/blob/main/docs/security.md) for the assumptions,
guarantees, attack paths, and accepted MVP risks.

## Install v0.1.0

The published package supports **Apple silicon** on **macOS 15 or newer**. Intel
and universal builds have not been validated.

Download the package and checksum file from the
[v0.1.0 release](https://github.com/crazytan/kpexec/releases/tag/v0.1.0), then:

```sh
shasum -a 256 -c SHA256SUMS
sudo installer -pkg kpexec-0.1.0-aarch64-apple-darwin.pkg -target /
kpexec doctor
```

The v0.1.0 package SHA-256 is
`bffbd1545a9d89bf2d625867e7c52a660541334be1b2ca838b6b640346a29736`.
It is Developer ID signed with hardened runtime, notarized by Apple, and has a
stapled notarization ticket. A bare command-line executable is not an app bundle,
so `doctor` may report the documented Gatekeeper “not an app” warning; the
installer package is the authoritative notarized artifact.

A source build is useful for development but will not pass the production
Keychain identity check. It is not equivalent to the signed release.

## Adopt it

Do credential authoring and recovery in a private Terminal session that the
agent cannot observe or capture. In particular, never run `init` or
`db show-password` through an agent: both can print the vault recovery password.

First, initialize the dedicated vault in that private session:

```sh
kpexec init
```

This requires local user authentication and prints a recovery key once. Store
that key outside the agent's reach—for example, in a personal password manager
or on paper. Losing both the login Keychain item and the recovery key makes the
vault unrecoverable.

Next, prepare the CLI you intend to authorize at an admin-owned, non-writable
path. For example, to make a root-owned copy of `gh`:

```sh
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec/kpexec
sudo install -o root -g wheel -m 0555 "$(command -v gh)" /usr/local/libexec/kpexec/gh
sudo chflags uchg /usr/local/libexec/kpexec/gh
```

This makes the byte pin enforceable; it does not make the running CLI
confidential from an unrestricted same-UID debugger. Keep the agent sandboxed
and prefer a self-contained hardened-runtime target as described in the user guide.

Create an entry with the interactive wizard and add one or more narrowly scoped
command templates:

```sh
kpexec entry add github
kpexec check --entry github
kpexec entry show github
```

For a GitHub entry, you might inject `GH_TOKEN`, select
`/usr/local/libexec/kpexec/gh`, and define separate templates such as `pr-list`
with prefix `pr list` and `pr-create` with prefix `pr create`. Prefer a token
whose server-side permissions and repository access are no broader than those
commands need.

Preview a request without extracting or injecting the selected credential and
without spawning a subprocess:

```sh
kpexec run --entry github --command pr-list --dry-run -- --state open
```

Then execute it:

```sh
kpexec run --entry github --command pr-list --json -- --state open
```

Arguments after `--` are appended verbatim to the approved prefix. Audit every
allowed trailing flag: endpoint, hostname, config-file, upload, and output flags
can change the security meaning of an otherwise safe command.

Use [Adoption and user guide](https://github.com/crazytan/kpexec/blob/main/docs/adoption.md) for policy-authoring guidance,
credential rotation, executable upgrades, recovery, and removal. Give a
configured agent the copy-paste [consumer-agent contract](https://github.com/crazytan/kpexec/blob/main/docs/consumer-agent.md).
The repository's [AGENTS.md](https://github.com/crazytan/kpexec/blob/main/AGENTS.md) and
[coding-agent guide](https://github.com/crazytan/kpexec/blob/main/docs/agent-guide.md) are for agents developing kpexec
itself, not for an agent that only uses a configured installation.

## Test evidence

Evidence supporting `v0.1.0` includes:

- protected-main CI passed on macOS 15 with Rust 1.96.0 and on macOS 26 with
  stable Rust;
- 177 automated tests ran across the library and integration suites: 176
  passed and one real-KDF benchmark was intentionally ignored;
- supervised, isolated Keychain and LocalAuthentication matrices passed on
  macOS 26.6.1, including other-signer denial, same-identity upgrade,
  planted-item denial, backend lifecycle, interactive approval, and SSH
  rejection. These Apple Development probes were carried forward because the
  relevant security-boundary code did not change before the tagged release;
- the final package was signed, notarized, stapled, installed, upgraded over the
  same identity, and correlated byte-for-byte with its extracted payload;
- the A1–A16 acceptance matrix passed. Most checks exercised the release
  candidate directly; the isolated signer/platform observations were carried
  forward under the unchanged-boundary condition documented in the evidence;
- a disposable, one-day, single-repository GitHub token completed a live `gh`
  run; plain/JSON output, audit logs, and captured artifacts were scanned without
  finding the credential value;
- release assets were downloaded into a fresh directory and independently
  rechecked before publication.

These results do not prove the absence of vulnerabilities. They document what
was exercised, on which platforms, and against which artifact. See
[Testing and release evidence](https://github.com/crazytan/kpexec/blob/main/docs/testing.md) and the credential-free reports
attached to the [GitHub release](https://github.com/crazytan/kpexec/releases/tag/v0.1.0).

## Documentation

- [Repository agent instructions](https://github.com/crazytan/kpexec/blob/main/AGENTS.md)
- [Coding-agent development guide](https://github.com/crazytan/kpexec/blob/main/docs/agent-guide.md)
- [Consumer-agent usage contract](https://github.com/crazytan/kpexec/blob/main/docs/consumer-agent.md)
- [Adoption and user guide](https://github.com/crazytan/kpexec/blob/main/docs/adoption.md)
- [Design and technical approach](https://github.com/crazytan/kpexec/blob/main/docs/design.md)
- [Security and threat model](https://github.com/crazytan/kpexec/blob/main/docs/security.md)
- [Security reporting policy](https://github.com/crazytan/kpexec/blob/main/SECURITY.md)
- [Testing and release evidence](https://github.com/crazytan/kpexec/blob/main/docs/testing.md)
- [Release runbook](https://github.com/crazytan/kpexec/blob/main/docs/release.md)
- [Contributing](https://github.com/crazytan/kpexec/blob/main/CONTRIBUTING.md)

## License

kpexec is licensed under [GPL-3.0-only](https://github.com/crazytan/kpexec/blob/main/LICENSE).
