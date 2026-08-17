# Testing and release evidence

## Why this record exists

kpexec depends on properties that ordinary unit tests cannot establish:
Keychain ACL behavior, macOS code identity, LocalAuthentication UI routing,
hardened runtime, package signatures, notarization, Gatekeeper, install
ownership, and silent access after a same-identity upgrade. Those properties
also attach to exact bytes and identities—not to a source tree in the abstract.

The project therefore keeps three kinds of evidence separate:

1. repeatable source tests for policy and process behavior;
2. supervised platform tests for macOS security boundaries;
3. artifact verification for the exact tagged package users download.

This separation prevents a previously notarized development build, a successful
mock, or a test with a different signer from being presented as evidence for a
release. It also exposes what was observed only on one OS version.

## Automated source validation

Every push and pull request tests the minimum Rust toolchain on the macOS 15 CI
image and stable Rust on the macOS 26 image. The workflow runs:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
```

The stable job also repeats the tests in release mode, audits the locked
dependency graph, checks the shell release tools, attacks the release verifier
with malformed packages, proves platform-test trust-domain isolation, checks
the LocalAuthentication linkage, and rehearses an unsigned clean release
preparation.

The test suites cover policy schema rejection and duplicate IDs; config/vault
identity disagreement; KDBX lifecycle, locking, stale-lock recovery, atomic
save and backup behavior; the user-presence dispatch boundary; pin ownership,
tampering and repinning; exact argv and minimal environment construction; dry
run without selected-credential extraction, injection, or spawn; exit-status separation; timeout and partial
output; output caps and redaction forms; audit-log hygiene; and release verifier
regressions. A real child-process test interrupts a nonempty vault write and
checks that the original bytes remain decryptable.

The protected-main run for v0.1.0 passed both required jobs:
[GitHub Actions run 31973839307](https://github.com/crazytan/kpexec/actions/runs/31973839307).

## Threat-boundary validation

Threat-boundary testing used synthetic credentials only. On macOS 26.6.1, a
same-user process recovered a synthetic value from the initial environment of
ad-hoc-signed, Homebrew `gh`, and hardened-runtime targets through direct
`KERN_PROCARGS2` queries and through `ps -E`/`ps eww`. No debugger attachment or
authorization prompt was required. Apple platform binaries and a synthetic
target carrying `CS_RESTRICT` omitted their environment from those queries.
That is observed OS behavior, not a documented kpexec-supported contract:
kpexec does not currently require or diagnose `CS_RESTRICT`, and a descendant
that inherits the credential is evaluated independently.

Separate LLDB tests attached to the ad-hoc-signed `gh` target but were denied by
the hardened-runtime target. Hardened runtime is therefore useful defense in
depth for task-port and process-memory access, not protection for the initial
environment. Calling `unsetenv` did not erase the original stack bytes; an
in-place overwrite did in the synthetic target, but kpexec cannot assume that
arbitrary supported CLIs will perform one before an observer reads them.

Sandbox probes also showed that individual process-info or sysctl denial rules
were not reliable evidence on their own; a combined tested boundary denied the
observed environment-query paths. Adoption therefore requires end-to-end
negative probes of both process-environment and debugger/task-port access in the
actual agent sandbox or permission system.

## Supervised macOS tests

The platform suite uses isolated Apple Development identities and synthetic
values. Mutable workspace code is never signed into the production Developer
ID trust domain. Safe preflight and prompt-bearing commands are documented in
[`tests/platform/README.md`](../tests/platform/README.md).

The Keychain matrix checks:

- T1: the genuine signed reader gets silent access and the expected Team-ID
  partition is present;
- T2: a differently signed reader is denied after a visible dialog;
- T3: changed bytes with the same identity retain silent access;
- T4: an `apple-tool:` planted item is denied;
- T5: the Rust backend completes create, ACL inspection, read, update, reread,
  delete, and cleanup without a dialog.

The LocalAuthentication matrix checks a successful interactive account-password
sheet and a BatchMode SSH invocation that returns unavailable without presenting
a sheet on the console.

These tests passed on macOS 26.6.1 arm64. Their sanitized reports are release
assets: [Keychain platform report](https://github.com/crazytan/kpexec/releases/download/v0.1.0/keychain-platform-report.txt)
(SHA-256 `f03cb7e377f8dcc50ebd04cab9d7aad8424a051e93c504c5062c72b190122410`)
and [LocalAuthentication report](https://github.com/crazytan/kpexec/releases/download/v0.1.0/local-auth-report.txt)
(SHA-256 `517b6c717f67e2d63f8af1286df3fb13e3df5fd7e9373105c797c7bffe5bd422`).
They apply to v0.1.0 because the exercised boundary was unchanged between the
probe commit and release commit. They must be rerun after a relevant Keychain,
authentication, signing-identity, or platform change.

## Installed and live acceptance

The acceptance matrix checks dry run, deny-by-default resolution, child-only
injection, redaction, exit codes, timeout, write interruption, diagnostics,
stale-pin rejection before spawn, authorized repinning, denied mutation,
differently signed access, vault substitution, same-identity upgrade, and the
documented rollback behavior.

| Case | Procedure and required result | Evidence class |
| --- | --- | --- |
| A1 | Dry run resolves policy and prints exact argv. It may parse the vault, but does not extract or inject the selected credential and does not spawn a child. | Automated |
| A2 | Unknown entry/command, malformed or forward-version policy, duplicate ID, and unknown fields fail with the expected JSON status and no spawn. | Automated |
| A3 | A run executes exactly `[exe] + fixed prefix + trailing argv` with the defined minimal environment plus the one injected variable. | Automated + installed |
| A4 | The synthetic credential is absent from stdout, stderr, JSON, kpexec logs, and captured temporary artifacts after a full run. This does not test process-environment queries, debugger/task-port access, or process-memory access. | Automated + installed |
| A5 | Exact, JSON-escaped, and URL-encoded forms are redacted; a residual match suppresses both streams and fails closed. | Automated |
| A6 | Child exits and signals propagate under the documented contract; broker failures remain distinguishable through `kpexec_status`. | Automated |
| A7 | Timeout sends SIGTERM, escalates to SIGKILL after the grace period, and returns bounded redacted partial output with timeout status. | Automated |
| A8 | Live locks serialize writes, dead-PID locks are reclaimed, and terminating a writer during a nonempty temporary write leaves the live vault byte-intact and decryptable. | Automated |
| A9 | `doctor` and `check` surface `.env` credential names, unpinned/stale/unenforceable pins, and config/Keychain vault-path disagreement at the documented severity. | Automated + installed |
| A10 | Changed executable bytes produce `exe-hash-mismatch` before selected-credential extraction and child spawn. | Automated + installed |
| A11 | A legitimate upgrade remains blocked until locally authorized repinning records the new hash and restores execution; denied authorization makes no change. | Automated + installed |
| A12 | Every mutation denied by graphical-session preflight or LocalAuthentication—including SSH/headless invocation—leaves vault, config, backup, and Keychain state unchanged. | Automated denial tests + supervised platform test |
| A13 | A differently signed or unsigned reader cannot silently access the protected Keychain item. | Supervised platform test |
| A14 | An agent-planted item and config hint cannot substitute a different vault; production rejects the mismatch before protected use. | Automated + supervised platform test |
| A15 | Changed binary bytes with the same approved Team ID and identifier retain silent Keychain access, and an installed same-identity upgrade preserves the vault. | Supervised + installed |
| A16 | Replacing the vault with an older valid copy is accepted (documented rollback limitation), and the resulting run emits the advisory audit record. | Installed limitation check |

For v0.1.0, a disposable one-day GitHub token limited to this repository and
with zero optional permissions exercised a real pinned `gh` command. Plain and
JSON output, the audit log, and temporary artifacts were scanned for the token.
The token was not recorded and was revoked after the test. This validates the
normal redaction path; it does not change the non-guarantees for hostile child
behavior or same-UID process inspection described in [the threat
model](security.md).

The sanitized [acceptance report](https://github.com/crazytan/kpexec/releases/download/v0.1.0/acceptance-report.txt)
has SHA-256
`ecfd76842d17e27aa75bca97c75d213c4729dff5f7facff126cca05920051806`.

## Exact v0.1.0 artifact

- Source/tag: `f526f476ea4554737985f24b3a3ec737e85c4559`, signed tag `v0.1.0`
- Target: `aarch64-apple-darwin`, deployment target macOS 15.0
- Notary submission: `a0ed16d1-b0b4-4780-a7da-c52dfedfd46e`, accepted
- Package SHA-256:
  `bffbd1545a9d89bf2d625867e7c52a660541334be1b2ca838b6b640346a29736`
- Installed executable SHA-256:
  `4ad056de1fee4ef734c7b3ece8c705f56578f94a075c9ff89b3a4466f70c6d47`
- Installed owner/mode: `root:wheel`, `0755`

The package was Developer ID Application/Installer signed, timestamped with
hardened runtime, notarized, stapled, and accepted by the installer Gatekeeper
assessment. Its installed bytes matched the expanded package payload; the
receipt and CLI both reported version 0.1.0. A fresh download was verified
again before the draft release was published.

The supported minimum is macOS 15, and CI exercises a macOS 15 job. The
supervised graphical security matrix and final installed acceptance were run on
macOS 26.6.1 arm64. Do not reinterpret those observations as independent
platform evidence for every macOS 15.x–26.x point release.

## Repeating a release assessment

From a clean reviewed commit:

```sh
./scripts/release.sh preflight
./scripts/release.sh prepare dist/kpexec-<version>
KPEXEC_SIGN=1 ./scripts/release.sh sign-package dist/kpexec-<version>
KPEXEC_SUBMIT=1 KPEXEC_NOTARY_PROFILE=<profile> \
  ./scripts/release.sh notarize dist/kpexec-<version>
./scripts/release.sh verify dist/kpexec-<version>
```

Then install on a clean account, correlate the receipt and installed bytes with
the verified payload, run the supervised matrices and installed acceptance
tests, create a signed tag and draft release, download every asset into a fresh
directory, and independently repeat checksum/signature/staple/Gatekeeper/payload
verification before publication. Never copy hashes or notarization results from
an earlier build.

The maintainer procedure is detailed in [the release runbook](release.md).
