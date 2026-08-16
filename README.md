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
password maintenance commands are implemented. Platform hardening remains
incomplete:

- every vault mutation and recovery-password display is gated by Touch ID or
  the macOS account-password fallback, but the interactive GUI behavior still
  needs supervised validation;
- production Keychain credential access intentionally fails closed until the
  signed-identity ACL/partition-list provisioning workflow is supervised and
  verified;
- release signing, hardened runtime, notarization, and the corresponding
  release validation are still pending.

Until those protections land, a locally built binary must not be treated as a
complete security boundary against an untrusted local agent. See
[Milestones](docs/milestones.md) for the remaining supervised acceptance work.

## Requirements

- macOS
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

Both commands produce an unsigned development build with the platform
hardening limitations listed above; there is not yet a hardened release
artifact.

## Basic use

The workflow below is the intended CLI flow. In the current pre-release build,
production vault access stops at the fail-closed Keychain ACL check described
above; the commands become operational only after that provisioning boundary is
validated and enabled.

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

## License

kpexec is licensed under [GPL-3.0-only](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution terms, including DCO sign-off and the license grant.
