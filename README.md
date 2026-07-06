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

Policies and secrets live in a dedicated KDBX4 vault managed entirely by kpexec (still openable in KeePassXC). Every policy change requires Touch ID; the vault password is readable only by the signed kpexec binary via a Keychain ACL. macOS only.

**Status:** design complete, implementation in progress.

## Docs

- [Security design](docs/security-design.md) — guarantees, trust model, invariants, residual risks
- [CLI design](docs/cli-design.md) — data model, KDBX mapping, subcommands, agent contract
- [Milestones](docs/milestones.md) — de-risking spikes, implementation milestones, acceptance tests

## License

kpexec is licensed under [GPL-3.0-only](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution terms, including DCO sign-off and the license grant.
