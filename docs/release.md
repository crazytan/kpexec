# Release runbook

This runbook produces a Developer ID-signed, hardened-runtime, notarized macOS
installer package. The stages are intentionally separate: preparation accesses
no signing or notarization credentials, signing uses local Keychain identities,
and notarization will not submit anything unless explicitly enabled.

## Prerequisites

- A clean, reviewed commit whose Rust 1.96 and stable CI jobs passed.
- Xcode Command Line Tools, Rust 1.96 or newer, and the locked dependencies.
- For the credentialed stages, `Developer ID Application` and `Developer ID
  Installer` identities for Team ID `V82M9YX8BR` in the login Keychain.
- A `notarytool` Keychain profile. Create it interactively once; do not put
  Apple credentials in the repository or environment:

  ```sh
  xcrun notarytool store-credentials kpexec-notary \
    --apple-id "<apple-id>" \
    --team-id V82M9YX8BR \
    --password "<app-specific-password>"
  ```

## 1. Prepare without credentials

From the repository root:

```sh
./scripts/release.sh preflight
./scripts/release.sh prepare dist/kpexec-0.1.0
```

`prepare` refuses a dirty tree, runs formatting, Clippy, release tests, strict
rustdoc, Cargo package verification, and a locked release build. It stages the
unsigned binary under `stage/usr/local/bin/kpexec`, includes the license and
README under `stage/usr/local/share/doc/kpexec`, and records its version,
target, commit, and checksum. Review `RELEASE.env` and
`SHA256SUMS.unsigned`. `ALLOW_DIRTY=1` exists only for rehearsals; an artifact
with `DIRTY=1` must not ship.

One preparation run produces a package for the active Rust host target, recorded
in `RELEASE.env`; it does not create a universal binary. Before the first public
release, document the supported CPU target(s) and minimum macOS version, and
repeat this workflow on each supported target as needed.

## 2. Sign and package with a human present

```sh
KPEXEC_SIGN=1 ./scripts/release.sh sign-package dist/kpexec-0.1.0
```

This is the first credentialed stage. It signs the staged binary with a secure
timestamp, identifier `dev.crazytan.kpexec`, and hardened runtime; verifies the
identifier, Team ID, timestamp, and runtime flag; then creates and verifies a
signed installer package for `/usr/local/bin/kpexec`.

The defaults name Jia Tan's Team `V82M9YX8BR`. Override certificate display
names without changing the expected Team ID when Keychain naming differs:

```sh
KPEXEC_APPLICATION_IDENTITY="Developer ID Application: … (V82M9YX8BR)" \
KPEXEC_INSTALLER_IDENTITY="Developer ID Installer: … (V82M9YX8BR)" \
KPEXEC_SIGN=1 \
./scripts/release.sh sign-package dist/kpexec-0.1.0
```

Review the displayed signature information and
`SHA256SUMS.pre-notarization` before submission.

## 3. Submit, staple, and verify

Submission is guarded against accidental execution:

```sh
KPEXEC_SUBMIT=1 \
KPEXEC_NOTARY_PROFILE=kpexec-notary \
./scripts/release.sh notarize dist/kpexec-0.1.0
```

The command waits for Apple's verdict, staples the ticket, validates it, checks
the binary and installer signatures, confirms the package payload path, runs a
Gatekeeper installer assessment, and writes the final `SHA256SUMS`. On an
`Invalid` verdict, use the submission ID printed by `notarytool` to retrieve
the log; do not publish the artifact.

The verification stage can be repeated without a notary profile:

```sh
./scripts/release.sh verify dist/kpexec-0.1.0
```

## 4. Manual ship gates

Automation cannot replace product support decisions, security prompts, or
clean-machine checks:

1. Install the package on a clean macOS account with
   `sudo installer -pkg <package> -target /`, then run `kpexec doctor`.
2. Complete and record the Keychain ACL, LocalAuthentication, signer,
   substitution, and same-identity-upgrade tests in
   [`spikes/README.md`](../spikes/README.md).
3. Run A1–A16 and the disposable, minimally scoped `gh` token demonstration;
   confirm the token is absent from output, JSON, logs, and temporary artifacts.
4. Confirm protected `main` requires the green CI checks, create the signed
   release tag, publish the `.pkg`, `SHA256SUMS`, license, and matching source
   archive, and verify the downloaded package again before announcing it.
