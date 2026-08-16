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
output redaction, the LocalAuthentication user-presence gate, and the vault
password maintenance commands and platform credential boundary are implemented.
The platform behavior has been supervised on macOS 26.6.1. The original probes
were signed too broadly; the current isolated Apple Development harnesses must
be rerun before their results count as ship evidence:

- every vault mutation and recovery-password display is gated by Touch ID or
  the macOS account-password fallback; the signed production path has been
  supervised successfully with account-password approval and fail-closed SSH
  rejection before any GUI sheet;
- production Keychain credential access now verifies the exact signed identity
  and singleton Team-ID partition before reading or updating the same item
  reference; historical planted-item and Rust lifecycle runs passed, with a
  safe isolated-profile rerun still required for ship evidence;
- release packaging, notarization, and clean-account acceptance are still
  pending.

Until a notarized release artifact passes the remaining ship gates, a locally
built binary must not be treated as a complete security boundary against an
untrusted local agent. See
[Milestones](docs/milestones.md) for the remaining supervised acceptance work.

## Requirements

- Apple silicon Mac (the initial package targets macOS 11, but that minimum
  still requires release-candidate runtime validation before it is advertised
  as supported)
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
requirement; there is not yet a notarized release artifact.

## Basic use

The workflow below is the intended CLI flow. Unsigned local builds intentionally
fail the production Keychain identity check; use the release signing workflow for
an end-to-end local validation. No notarized release artifact is published yet.

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

## License

kpexec is licensed under [GPL-3.0-only](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution terms, including DCO sign-off and the license grant.
