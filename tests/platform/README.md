# Supervised macOS platform tests

These tests exercise security properties that mocks and unattended CI cannot
establish: Keychain ACL partitions, code identity across rebuilt bytes,
LocalAuthentication UI routing, and rejection from a non-graphical SSH
session. They use synthetic values and isolated Apple Development identifiers;
they never select the production Keychain service or Developer ID profile.

The scripts are release-maintainer tests. They require the Apple Development
identity and Team ID compiled into the harness, a console-attached Terminal,
and a person who can observe and deny unexpected prompts. Do not run the
prompt-bearing modes from an agent or unattended job.

## Safe preflight

These commands build and inspect prerequisites without reading or writing
Keychain secrets, invoking LocalAuthentication, or using a signing private key:

```sh
tests/platform/keychain/run-acl-matrix.sh --preflight
tests/platform/keychain/run-backend.sh --preflight
tests/platform/local-auth/run.sh --check-only
```

The LocalAuthentication preflight also checks the dedicated localhost SSH
setup needed for the negative non-graphical-session leg.

## Supervised run

After the safe preflight passes, follow the on-screen pauses in Terminal:

```sh
tests/platform/keychain/run-acl-matrix.sh
tests/platform/keychain/run-backend.sh
tests/platform/local-auth/run.sh --supervised
```

Approve only the named Apple Development signing-key request and the explicit
positive LocalAuthentication leg. Deny unexpected Keychain access. The scripts
use unique isolated accounts, verify their signer requirements, clean them on
exit, and write gitignored local result files. Review and sanitize those files
before attaching evidence to a release; never commit raw machine-local output.

The expected T1–T5 and LocalAuthentication results, evidence rules, and rerun
triggers are described in [Testing and release evidence](../../docs/testing.md).
