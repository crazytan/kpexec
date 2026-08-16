# kpexec

A local credential broker that lets coding agents run pre-approved commands with injected secrets — without the secret ever entering the agent's context.

```
agent ──▶ kpexec run --entry github --command pr-create -- --title "Fix build"
              │
              ├─ resolve policy from a dedicated KeePass vault
              ├─ verify the pinned executable hash
              ├─ build argv from the policy template (agent never supplies the exe)
              ├─ inject the secret into the child env only
              └─ return redacted output — never the token
```

Policies and secrets live in a dedicated KDBX4 vault managed by kpexec and
remain openable in KeePassXC. kpexec is currently macOS-only.

## Status

kpexec is an experimental, pre-release implementation. The CLI, KDBX vault
lifecycle, executable pinning, policy checks, constrained subprocess runner,
output redaction, LocalAuthentication user-presence gate, vault-password
maintenance commands, and platform credential boundary are implemented.

The protected `main` build at `47bd556` passed both required CI jobs. Safe,
isolated Apple Development harnesses passed the Keychain T1–T5 and interactive
plus SSH LocalAuthentication matrices on macOS 26.6.1. A package from that
commit was Developer ID signed, notarized, stapled, Gatekeeper accepted,
installed, and correlated byte-for-byte with its payload; the initialized
production `doctor` report passed. Installed acceptance also exercised denied
mutation, stale-pin rejection and approved repinning, rollback audit behavior,
and a live disposable GitHub token without exposing the token in captured
output or artifacts.

Those results are a verified pre-final baseline, not a published release. The
isolated platform results were recorded at `a11564c` and apply to later commits
only while the relevant Keychain, LocalAuthentication, and signing boundaries
remain unchanged. The package at `47bd556` also predates the final macOS 15
deployment-target and acceptance-test changes. The final candidate must be
rebuilt, notarized, installed, and checked before publication. See the
[v0.1.0 release evidence](docs/release-evidence-v0.1.0.md) for exact hashes and
remaining gates.

Until the exact final notarized artifact passes those gates, a locally built
binary must not be treated as a complete security boundary against an untrusted
local agent.

## Requirements

- Apple silicon Mac running macOS 15 or newer (the initial package is arm64-only)
- Rust 1.96 or newer
- Xcode Command Line Tools

KeePassXC is optional. It is useful for inspecting the standard KDBX4 vault,
but normal kpexec operation does not require it.

## Build and install

Build a development binary from a checkout:

```sh
git clone https://github.com/crazytan/kpexec.git
cd kpexec
cargo build --release --locked
./target/release/kpexec --help
```

To put the locally built binary on Cargo's bin path:

```sh
cargo install --path . --locked
```

Both commands produce an unsigned development build. The production Keychain
backend rejects it because it does not satisfy kpexec's exact Developer ID
requirement. No release artifact has been published yet.

## Basic use

The workflow below is the intended CLI flow. Unsigned local builds intentionally
fail the production Keychain identity check; use the release signing workflow for
an end-to-end local validation. No release artifact is published yet.

Initialize the dedicated vault, then use the entry wizard to store a credential
and define one or more allowed command templates:

```sh
kpexec init
kpexec entry add
kpexec check
```

Preview a configured command without reading the entry's secret or starting a
subprocess:

```sh
kpexec run --entry github --command pr-create --dry-run -- --title "Fix build"
```

Remove `--dry-run` to execute it. Arguments after `--` are appended verbatim to
the policy's fixed argument prefix; kpexec does not invoke a shell. Run
`kpexec <command> --help` for the complete options for each command.

## Docs

- [Security design](docs/security-design.md) — target guarantees, trust model, invariants, residual risks
- [CLI design](docs/cli-design.md) — data model, KDBX mapping, subcommands, agent contract
- [Milestones](docs/milestones.md) — de-risking spikes, implementation milestones, acceptance tests
- [MVP ship checklist](docs/mvp-ship-checklist.md) — remaining platform work, release build, and final acceptance pass
- [Release runbook](docs/release.md) — staged build, signing, packaging, notarization, and verification
- [v0.1.0 release evidence](docs/release-evidence-v0.1.0.md) — verified pre-final results and final-candidate ledger

## License

kpexec is licensed under [GPL-3.0-only](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution terms, including DCO sign-off and the license grant.
