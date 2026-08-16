# v0.1.0 release evidence

This document records verified pre-final evidence and defines the evidence that
the final GitHub Release must carry. It contains no credential values. Do not
copy hashes forward from an earlier build.

## Verified pre-final baseline — 2026-08-16

| Area | Candidate | Verified result |
|---|---|---|
| Protected CI | `47bd5565abd552acac3c3ad4fbb35bfe3fe2fce9` | [GitHub Actions run 31970889228](https://github.com/crazytan/kpexec/actions/runs/31970889228): required Rust 1.96.0 and stable jobs passed. |
| Keychain T1–T4 | `a11564c2c00d86e15645737db39ca26277ae3130` | PASS: genuine read silent; different signer denied after dialog; changed bytes with the same identity read silently; `apple-tool:` planted item denied. Evidence SHA-256: `a20d786df61c0cce630efd82461d340a877def881acabef4dab1086b979b6e1f`. |
| Rust Keychain backend T5 | `a11564c2c00d86e15645737db39ca26277ae3130` | PASS: create, ACL inspect, read, update, reread, delete; rc0, no dialog, cleanup confirmed absent. Evidence SHA-256: `a7a1238d6f04f1c7472d20ec39e768388936dbc944119a27d14267a00e05706c`. |
| LocalAuthentication | `a11564c2c00d86e15645737db39ca26277ae3130` | PASS: console account-password approval returned rc0; BatchMode SSH returned rc2 with no sheet. Evidence SHA-256: `8faebcc4495f8ba931b27878fc8e9788da92d4df615c6152928983d3703df416`; signed probe SHA-256: `723d0ee7ce18d37eed2f1311b1b2c2f3985458973e899a16fb1e20204ca00eeb`. |
| Signed package | `47bd5565abd552acac3c3ad4fbb35bfe3fe2fce9` | Developer ID signed with Team ID `V82M9YX8BR`; notarization submission `7fa72b82-96ee-439b-8c70-b09c55f30b72` accepted; staple validated; installer Gatekeeper assessment accepted. Pre-staple upload SHA-256: `e524f6e13ec9116817075d7c787f8c29d8dfefd181927319f51ca238f9401e51`; final stapled package SHA-256: `08d2bc9c3449f10f9c8e92a7942499b535050cfda07393073048f2f42b0a8151`. |
| Installed payload | package above | Receipt `dev.crazytan.kpexec.pkg` version `0.1.0`; installed bytes matched the extracted payload. Executable SHA-256: `c6bbf6cd050ee6f803776b85939807546128c63891414a77cb60014078937ee6`. Initialized production `doctor` reported no failures. |
| Installed A12 | package above | Denying the authentication sheet left the observed vault, config, entry, and backup state unchanged. Keychain metadata was not independently snapshotted for this observation. |
| Synthetic A1/A3/A4/A6/A7 | source test suite | PASS: dry-run/no secret read; exact argv and child-only secret injection; output/JSON/log redaction; exit-code separation; timeout and redacted partial output. |
| Installed A10/A11 | package above | Changed pinned bytes were rejected before child spawn; an approved repin recorded new bytes and restored execution. |
| A16 | acceptance run | PASS: the documented rollback remained possible and the expected entry/command audit record was emitted. |
| Live GitHub demo | package above | PASS with a one-day token scoped only to `crazytan/kpexec` and zero optional permissions. Pinned real `gh` execution succeeded; normal/JSON redaction and output/log/temporary-artifact scans found no credential value. |

The isolated T1–T5 and LocalAuthentication results ran on macOS 26.6.1. Their
applicability is limited to commits that do not change the exercised Keychain,
LocalAuthentication, code-identity, or signing boundaries. They do not by
themselves validate the newly selected macOS 15 minimum. The package above also
records `MIN_MACOS=11.0`; it must not be published as the macOS 15 artifact.

The isolated transcripts are held in gitignored, machine-local result paths.
Their hashes above are a durable operator record, but the source archive alone
cannot reproduce or inspect them. Attach sanitized copies of the final macOS 15
reports to the draft release, record their hashes in the Release notes, and
verify those downloaded attachments before publication.

## Final publishable record

This tracked file intentionally does not contain placeholders for the final
package hash or notarization result. Adding those values would change the source
commit after the artifact was built. Instead:

1. Merge the final source, test, deployment-target, and packaged-document
   changes. Require protected-main CI to pass. That immutable commit is the
   candidate and eventual signed-tag target.
2. Run `prepare`, `sign-package`, and `notarize` from that clean commit as
   documented in [the release runbook](release.md).
3. Require the full automated candidate suite on the hosted macOS 15 arm64
   runner. Complete the human-present platform checks on a supported graphical
   macOS release, clean-account install and payload correlation, final A1–A16
   matrix, and any required disposable-token rerun without changing candidate
   inputs. Record the exact OS used for each observation.
4. Create a signed `v0.1.0` tag on the candidate commit and a draft GitHub
   Release. Upload the exact package and its generated `SHA256SUMS`.
5. Put the source commit, protected-main CI run, target/minimum OS, supervised
   evidence hashes, notary submission ID and `Accepted` verdict, package and
   executable hashes, clean-account result, A1–A16 result, token-demo result,
   and signed-tag verification in the Release notes.
6. Download the draft assets into a fresh directory and independently repeat
   checksum, signature, staple, Gatekeeper, payload, and source/tag
   verification. Add that result to the Release notes, then publish the same
   draft without rebuilding or replacing assets.
