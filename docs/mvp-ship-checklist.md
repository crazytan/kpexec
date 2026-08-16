# MVP ship checklist

The implementation and release pipeline have passed a substantial pre-final
acceptance run. The exact evidence and hashes are recorded in [v0.1.0 release
evidence](release-evidence-v0.1.0.md). Do not publish the existing package: it
was built from `47bd556` with a macOS 11 deployment target and is evidence for
the pipeline, not the final macOS 15 release candidate.

## Completed baseline

- Protected `main` CI run `31970889228` passed the required Rust 1.96.0 and
  stable jobs at `47bd556`.
- The safe isolated Keychain T1–T5 and LocalAuthentication interactive/SSH
  matrices passed at `a11564c` on macOS 26.6.1. These results remain applicable
  only while the tested Keychain, LocalAuthentication, identity, and signing
  boundaries are unchanged.
- A clean package from `47bd556` was Developer ID signed, notarized, stapled,
  Gatekeeper accepted, installed, and matched byte-for-byte to its packaged
  executable. Production initialization and `doctor` passed.
- The installed candidate rejected a denied mutation without changing the
  observed vault, config, entry, or backup state; rejected stale pinned bytes
  before spawn; restored operation after an approved repin; and emitted the
  expected rollback audit record.
- A live one-day, repository-scoped GitHub token with zero optional permissions
  completed the pinned `gh` demo. Normal/JSON output and artifact/log scans
  found no token disclosure.

## Final release-candidate gates

1. Merge the macOS 15 deployment-target and final test/documentation changes.
   Require the exact `Rust 1.96.0` job on `macos-15` and `Rust stable` job on
   `macos-26` to pass on protected `main`.
2. From that clean commit, run the full [release runbook](release.md). Record the
   final commit, CI run, notarization result, package SHA-256, and extracted
   executable SHA-256 in the draft GitHub Release record.
3. Require the full automated release-candidate suite to execute on the hosted
   macOS 15 arm64 runner before advertising macOS 15 support. Record the
   human-present Keychain and LocalAuthentication checks on a supported macOS
   release (macOS 26.6.1 for v0.1.0); headless hosted CI cannot validate their
   GUI prompt observations. Rerun them whenever the corresponding security
   boundary, signing identity, or relevant platform behavior changes.
4. Install the exact final package on a clean macOS 15 account. Confirm the
   receipt/version, root ownership and modes, exact signature requirement,
   initialized `doctor` result, and byte equality with the extracted payload.
5. Run A1–A16 against the final candidate. Automated tests may supply synthetic
   evidence, but A12–A15 retain their supervised macOS observations. Repeat the
   disposable-token demo if the run path, redactor, policy parser, or packaged
   executable changed after the recorded demonstration.
6. Create a signed `v0.1.0` tag, publish the `.pkg`, `SHA256SUMS`, license, and
   matching source archive, then download and independently verify the
   published package before announcing it.

## Acceptance details

Pinned executables must use an admin-owned, non-writable canonical path.
Homebrew installations are commonly user-owned and are not suitable directly.
The final demonstration must prove that authoring/repin accepts the privileged
path, changed bytes cause `exe-hash-mismatch` without a spawn, and an approved
repin restores execution. `--no-pin` is development-only.

For A12, denial or unavailable graphical authentication must leave the vault,
config, backup, and Keychain state unchanged. T1–T5 cover silent genuine reads,
different-signer rejection, same-identity upgrades, planted-item rejection, and
the production Rust Keychain lifecycle. The LocalAuthentication SSH leg must
return unavailable before presenting a GUI sheet. A16 documents rather than
prevents vault rollback and therefore requires the expected audit line.

An installed bare CLI may produce doctor's not-applicable Gatekeeper warning
(`code is valid but does not seem to be an app`). That warning neither blocks
the gate nor proves notarization. The exact installer must pass staple
validation and `spctl --type install`, and the installed bytes must match the
verified package payload.

## Ship gate

Ship only when every final-candidate item above is recorded as passing in the
draft GitHub Release record, protected `main` is green, the signed tag identifies
the exact recorded commit, and independently downloaded draft artifacts verify
against the checksums. Publish that verified draft without rebuilding or
substituting any asset.
