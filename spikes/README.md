# kpexec milestone-zero spikes

These harnesses validate the macOS security assumptions kpexec's design leans on
(see `../docs/milestones.md` "Milestone 0" and `../docs/security-design.md`). If one
fails, the design changes — so they run before any feature code.

**These spikes trigger Touch ID and Keychain GUI dialogs. Run them with the user
present, watching the screen.** Every script uses `set -euo pipefail`, echoes each
command, and pauses (`read -p`) before any step that shows a prompt. The scripts print
`PASS`/`FAIL`-oriented verdicts, but the load-bearing signal for several tests is a
**human observation** (did a dialog appear? was Touch ID requested?) — a process cannot
detect a Keychain confirmation dialog programmatically.

Do **not** commit any built binaries or the `dev.crazytan.kpexec.spike` Keychain items;
the keychain runner cleans its items up on exit (it only ever touches the service name
`dev.crazytan.kpexec.spike`).

## Spikes

| Dir | Milestone item | Proves |
|-----|----------------|--------|
| `keychain-acl/` | item 2 | A Team-ID + identifier partition list lets the signed binary read the vault password silently, prompts any other process, survives a version upgrade, and does **not** silently serve an agent-planted item (anti-substitution). |
| `local-auth/`   | item 3 | The Touch ID / account-password sheet can be raised from a signed, hardened-runtime CLI in a terminal, and **fails closed** over SSH / headless. |
| `signing/`      | item 4 | The Developer ID + hardened-runtime + notarization pipeline, and that a differently-signed binary degrades the ACL (observed in `keychain-acl` T2) rather than silently working. |

## Expected signing environment

- macOS on Apple Silicon with `swiftc` at `/usr/bin/swiftc`
- Signing identity: `Developer ID Application: Jia Tan (V82M9YX8BR)` (login keychain)
- Identifier: `dev.crazytan.kpexec`  · Team ID: `V82M9YX8BR`
- Isolated Keychain service: `dev.crazytan.kpexec.spike`

The harnesses record the actual macOS version, build, architecture, tool versions,
artifact hash, and signature at run time. Do not infer a result from the environment
description alone.

## Run order

Run in this order; `signing/` builds on what the keychain leg observes.

### 1. `keychain-acl/` (T1–T4)

```
cd keychain-acl
./run-tests.sh --preflight   # non-interactive; no Keychain data access or mutation
./run-tests.sh
```

`--preflight` type-checks and ad-hoc-signs an isolated temporary build, confirms the
Developer ID identity is installed, and performs attribute-only lookups for leftover
spike items. It does not read Keychain item data or create, update, or delete an item.

Run the supervised command once in a console-attached Terminal (not SSH). Stay at the
screen, approve only the named Developer ID signing operations, and click **Deny** for
T2 and T4 read dialogs. The script asks whether a dialog appeared after each read,
combines that observation with exit codes and isolated ACL dumps, and writes a report
to `keychain-acl/keychain-acl.local-results.txt` (gitignored). Cleanup runs
automatically.

- **T1** — signed binary create + read → expect silent success, **no dialog**.
- **T2** — differently-signed copy reads the same item → expect a **dialog** (Deny it).
- **T3** — rebuilt (different bytes) + re-signed same Team ID/identifier reads → expect
  **silent** success, no new dialog (this is acceptance test A15).
- **T4** — item planted by `security add-generic-password -T` read by the signed binary
  → **must not** be silently readable. If it reads with no dialog and rc=0, the
  anti-substitution assumption is **BROKEN** — the script flags this loudly.

**Partition-list note:** the script isolates each item from `security dump-keychain -a`
and machine-checks its `partition_id` entry. T1 must contain
`teamid:V82M9YX8BR`; T4 must contain `apple-tool:` and must not contain the team
partition. These checks are part of the verdict.

#### Production-backend decision after the report

- If all four tests pass, production may create a new item with `SecItemAdd`, inspect
  its partition ACL before treating it as trusted, update only an already-verified
  item, and inspect again before every data read. A duplicate item with an absent or
  wrong partition must be rejected without reading or updating it.
- If T1 lacks the team partition, silent API creation is insufficient. Keep the backend
  fail-closed until setup has an explicit login-Keychain-password provisioning step;
  LocalAuthentication approval alone does not provide that password to
  `set-generic-password-partition-list`.
- If T4 has the team partition or reads silently, the classic file-Keychain design does
  not provide anti-substitution. Do not weaken the verdict; move to a provisioned data
  protection Keychain access group/app-like bundle or redesign around a Secure Enclave
  signing key.

The minimum remaining supervised action is therefore exactly one command in
Terminal.app:

```
cd /Users/tan/src/kpexec/spikes/keychain-acl
./run-tests.sh
```

Approve the two named Developer ID signing requests if macOS asks, choose **Deny** for
T2 and T4 reads, answer the script's dialog-observation questions, and attach
`keychain-acl.local-results.txt`. If T4 creation itself asks, choose **Allow** (never
Always Allow) so the worst-case planted item can still be tested.

### 2. `local-auth/` (LA interactive, then LA-over-SSH)

First run the non-prompting prerequisite check. It type-checks the Swift reference,
builds a release probe through kpexec's real Rust/Objective-C authorization path, checks
framework/symbol linkage and the signing identity, and requires noninteractive localhost
SSH to be ready:

```
cd local-auth
./run-tests.sh --check-only
```

If it reports that SSH is not ready, enable Remote Login and follow the printed commands
to create/install a dedicated localhost test key. Pass its absolute path through
`KPEXEC_LA_SSH_IDENTITY` until `--check-only` passes. Then, with the human watching the
console for both legs, run one supervised session with the same environment variable:

```
KPEXEC_LA_SSH_IDENTITY="$HOME/.ssh/kpexec-localhost-test" \
  ./run-tests.sh --supervised
```

The harness signs the production-path probe with the shared release signing script,
machine-verifies its identifier, Team ID, hardened-runtime flag, timestamp, and hash,
then runs both legs itself:

- Interactive → require **AUTHORIZED** (rc=0) after Touch ID or account password and
  record which sheet appeared.
- SSH → require **UNAVAILABLE** (rc=2) and **no GUI sheet**. rc=0 is a hard failure.

It exits nonzero on either mismatch and writes logs plus a results summary under
`local-auth/build/` (gitignored). Exit codes are `0`=authorized, `1`=denied,
`2`=unavailable/fail-closed, `3`=internal.

### 3. `signing/` (sign/verify, then notarize)

```
cd signing
./sign.sh <binary> dev.crazytan.kpexec     # e.g. the kcprobe or a real kpexec build
KPEXEC_SUBMIT=1 ./notarize.sh <signed-artifact>  # requires one-time profile setup
```

`sign.sh` signs (Developer ID + hardened runtime + timestamp), runs strict
verification, and fails automatically unless the expected identifier, Team ID,
runtime flag, and timestamp are present. `notarize.sh` remains a spike harness
for arbitrary signed artifacts and requires a one-time Keychain profile. The
production `.pkg` workflow, accidental-submission guards, stapling, payload
inspection, Gatekeeper assessment, and checksums are in the
[release runbook](../docs/release.md).

## What the human must observe at each prompt

| Step | Watch for | Passing observation |
|------|-----------|---------------------|
| keychain T1 read | any Keychain dialog | **no dialog**, value printed |
| keychain T2 read | Keychain "wants to use …" dialog | dialog appears (then Deny) |
| keychain T3 read | any new dialog | **no dialog**, value printed |
| keychain T4 read | any dialog | dialog/denial — **not** a silent read |
| LA interactive | Touch ID sensor / password sheet | sheet shown, auth succeeds |
| LA over SSH | any sheet | **no sheet**, rc=2 (UNAVAILABLE) |
| sign/verify | codesign output | Team ID + identifier + `runtime` flag |
| notarize | notarytool verdict | `Accepted` |

## Results table (fill in during the supervised run)

Date run: __________   Operator: __________   macOS build: __________

| Test | Command | Dialog appeared? | Touch ID requested? | Exit code | Expected | PASS/FAIL | Notes |
|------|---------|------------------|---------------------|-----------|----------|-----------|-------|
| T1 (silent read) | `kcprobe read` (signed) | | n/a | | rc0, no dialog | | |
| T2 (other signer) | `kcprobe-copy read` | | n/a | | dialog (Deny→rc4) | | |
| T3 (upgrade, A15) | `kcprobe read` (rebuilt) | | n/a | | rc0, no dialog | | |
| T4 (planted item) | `kcprobe read` planted | | n/a | | dialog/deny, NOT silent | | |
| — partition list T1 | `dump-keychain -a` | n/a | n/a | n/a | `teamid:V82M9YX8BR` present? | | record actual |
| — partition list T4 | `dump-keychain -a` | n/a | n/a | n/a | no `teamid:` partition | | record actual |
| LA interactive | production-path probe (terminal) | | | | rc0 (AUTHORIZED), sheet shown | | |
| LA over SSH | production-path probe via BatchMode SSH | | n/a | | rc2 (UNAVAILABLE), no sheet | | |
| sign/verify | `sign.sh … dev.crazytan.kpexec` | n/a | n/a | | rc0, TeamID+runtime | | |
| notarize | `notarize.sh <artifact>` | n/a | n/a | | Accepted | | submission id: |

## Why T1–T4 are still supervised

Apple's open-source Security implementation supports the expected mechanism:
partition validation runs in addition to the ordinary trusted-application ACL;
Developer ID processes receive `teamid:<certificate OU>`, while `security(1)` receives
`apple-tool:`; and a mismatched partition can be extended only through authorization.
See Apple's [`acls.cpp`](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/acls.cpp)
and [`clientid.cpp`](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/clientid.cpp).
Source evidence does not establish current macOS UI behavior or the installed
certificate's runtime behavior, so these remain explicit observations:

1. **Partition list at creation time.** T1 dumps the creator-made item before its first
   read and requires `teamid:V82M9YX8BR`. T4 dumps the planted item before kpexec reads
   it and requires `apple-tool:` with no team partition. If T1 lacks its partition,
   production provisioning needs an authenticated setup step; if T4 already has the
   team partition, the anti-substitution design fails.
2. **T2 behavior for an ad-hoc-signed reader** — whether macOS shows a confirmation
   dialog (Allow/Deny) vs returns `errSecAuthFailed` outright. Either is a pass for the
   assumption (the point is: not silent); the exact mode is recorded, not assumed.
3. **T4 planted-item readability** — the ordinary `-T kcprobe` trusted-app entry must
   not override the separate `apple-tool:` partition check. A silent read is a design
   failure.
4. **LA over SSH exact LAError** — expected to be `notInteractive` or
   `biometryNotAvailable`, mapped to UNAVAILABLE (rc2). The specific code is printed and
   recorded; the requirement is only that it is **not** PASS.
5. **`codesign -d --requirements -` output shape** — the designated requirement text the
   Keychain ACL should anchor to; captured by `sign.sh` for the record.
6. **notarize stapling on a bare binary** — `stapler staple` is expected to fail on a
   bare Mach-O / plain `.zip`; the skeleton surfaces this rather than hiding it, flagging
   that release packaging must wrap kpexec in a stapleable container (`.dmg`/`.pkg`).
