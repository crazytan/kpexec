# Security policy

## Reporting a vulnerability

Please use GitHub's private
[security-advisory form](https://github.com/crazytan/kpexec/security/advisories/new)
for vulnerabilities that could expose credentials, bypass policy or user
presence, substitute a vault or executable, weaken release verification, or
cross the macOS Keychain identity boundary. Do not include real credentials,
recovery passwords, Keychain values, or signing material in a report.

Include the affected version and macOS release, the trust assumptions required
for the issue, a minimal reproduction using synthetic data, and the impact you
observed. Use a normal GitHub issue for non-sensitive bugs and documentation
problems.

## Supported versions

The current supported release is v0.1.0 for Apple silicon on macOS 15 or newer.
Security fixes will be released from the protected `main` branch as signed,
notarized packages. Source-built binaries do not share the production
Keychain identity and are not equivalent to the published package.

## Scope

Read [Security and threat model](docs/security.md) before filing a boundary
bypass. In particular, v0.1 does not claim credential confidentiality from an
unrestricted same-UID agent capable of debugger/task-port access to the
credential-bearing child. Reports that demonstrate impact within the stated
constrained-agent model—or a way to escape that model—are especially useful.
