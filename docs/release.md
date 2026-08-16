# Release runbook

This runbook produces a Developer ID-signed, hardened-runtime, notarized macOS
installer package. The stages are intentionally separate: preparation accesses
no signing or notarization credentials, signing uses local Keychain identities,
and notarization will not submit anything unless explicitly enabled.

## Prerequisites

- A clean, reviewed commit whose Rust 1.96 and stable CI jobs passed.
- An Apple silicon Mac running macOS 11 or newer. The initial MVP artifact is
  intentionally `aarch64-apple-darwin` with a macOS 11.0 deployment target;
  Intel and universal packages require later build-and-hardware validation.
- Xcode Command Line Tools, Rust 1.96 or newer, and the locked dependencies.
- For the credentialed stages, `Developer ID Application` and `Developer ID
  Installer` identities for Team ID `V82M9YX8BR` in the login Keychain.
- A `notarytool` Keychain profile. Create it interactively once; do not put
  Apple credentials in the repository or environment:

  ```sh
  xcrun notarytool store-credentials kpexec-notary \
    --apple-id "<apple-id>" \
    --team-id V82M9YX8BR
  ```

  Omit `--password` so `notarytool` requests the app-specific password through
  its secure interactive prompt instead of placing it in shell history or the
  process argument list.

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
with `DIRTY=1` cannot enter a credentialed stage.

The script records and verifies the architecture and deployment target. It does
not create a universal binary.

## 2. Sign and package with a human present

```sh
KPEXEC_SIGN=1 ./scripts/release.sh sign-package dist/kpexec-0.1.0
```

This is the first credentialed stage. Before changing the staging tree, it
rejects dirty rehearsal manifests, verifies that the unsigned binary still
matches `SHA256SUMS.unsigned`, rebuilds the reviewed clean Git commit in a fresh
target directory and requires byte-for-byte agreement, and confirms both
identities are usable. It then signs the staged binary with a secure timestamp,
identifier `dev.crazytan.kpexec`, and hardened runtime; verifies the identifier, Team ID,
architecture, deployment target, timestamp, and runtime flag; then creates and
verifies a signed installer package for `/usr/local/bin/kpexec`.

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
Gatekeeper installer assessment, and writes the final `SHA256SUMS` for the
distributed package. On an `Invalid` verdict, use the submission ID printed by
`notarytool` to retrieve
the log; do not publish the artifact.

The verification stage can be repeated without a notary profile. It expands the
package and verifies the exact identifier, version, install location, payload,
ownership, modes, exact Developer ID Installer leaf, and Developer ID
Application requirement on the packaged executable—not merely the copy left in
staging. Installer scripts, distribution/component packages, PackageInfo script
declarations, and any unexpected archive or payload path are rejected:

```sh
./scripts/release.sh verify dist/kpexec-0.1.0
```

A downloaded package is independently verifiable without its staging tree:

```sh
./scripts/release.sh verify ~/Downloads/kpexec-0.1.0-aarch64-apple-darwin.pkg
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

`kpexec doctor` verifies the installed executable's strict Developer ID
signature, exact identifier and Team ID, and hardened runtime. Gatekeeper may
report `code is valid but does not seem to be an app` for the installed bare
CLI; doctor reports that result as a warning because an individual non-bundle
executable is not the notarization artifact. The release gate is the successful
installer-package verification above, including its stapled ticket and
`spctl --type install` assessment. Do not treat the doctor warning as
independent proof that the package was notarized. Correlate the clean install
with the verified artifact: confirm the `dev.crazytan.kpexec.pkg` receipt and
version with `pkgutil --pkg-info`, compare that version with `kpexec --version`,
and byte-compare `/usr/local/bin/kpexec` with the executable extracted from the
exact verified package. This guards against assessing one package while testing
a different installed payload.
