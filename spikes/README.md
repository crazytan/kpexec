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

Do **not** commit any built binaries or spike Keychain items. The Keychain runners
clean their items on exit and can touch only `dev.crazytan.kpexec.spike` (T1–T4)
or `dev.crazytan.kpexec.backend-spike` with a `backend-spike:` account (T5).

## Spikes

| Dir | Milestone item | Proves |
|-----|----------------|--------|
| `keychain-acl/` | item 2 | A Team-ID + identifier partition list lets the signed binary read the vault password silently, prompts any other process, survives a version upgrade, and does **not** silently serve an agent-planted item (anti-substitution). |
| `local-auth/`   | item 3 | The Touch ID / account-password sheet can be raised from a signed, hardened-runtime CLI in a terminal, and **fails closed** over SSH / headless. |
| `signing/`      | item 4 | The Developer ID + hardened-runtime + notarization pipeline, and that a differently-signed binary degrades the ACL (observed in `keychain-acl` T2) rather than silently working. |

## Expected supervised signing environment

- macOS on Apple Silicon with `swiftc` at `/usr/bin/swiftc`
- Signing identity: `Apple Development: Jia Tan (ZW5U6862Q8)` (login keychain)
- Team ID: `V82M9YX8BR`
- Isolated identifiers/services: `dev.crazytan.kpexec.spike`,
  `dev.crazytan.kpexec.backend-spike`, and
  `dev.crazytan.kpexec.local-auth.spike`

Mutable workspace probes must never be signed with the Developer ID Application
identity or production identifier. Those credentials are reserved for a staged,
audited release artifact. Each supervised runner hardcodes Apple Development and
machine-checks that its signed probe fails the exact production requirement.

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
Apple Development identity is installed, and performs attribute-only lookups for leftover
spike items. It does not read Keychain item data or create, update, or delete an item.

Run the supervised command once in a console-attached Terminal (not SSH). Stay at the
screen, approve only the named Apple Development signing operations, and click **Deny** for
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

#### Recorded Keychain result

The OS-behavior matrix passed on 2026-08-15 PDT (2026-08-16T05:12:56Z) on macOS
26.6.1 (25G76). That historical run used the Developer ID identity on mutable
workspace code; this is not acceptable release evidence and the old signing path
has been removed. Re-run the matrix with the current Apple Development harness
before shipping.

| Test | Observation | Result |
|------|-------------|--------|
| T1 genuine create/read | creator partition `teamid:V82M9YX8BR`; silent read | **PASS** |
| T2 different identity | read denied after a Keychain dialog | **PASS** |
| T3 rebuilt, same identity | bytes changed; designated requirement unchanged; silent read | **PASS** |
| T4 `security(1)`-planted item | `apple-tool:` present, team partition absent; read denied | **PASS** |

The machine-local transcript remains in the gitignored
`keychain-acl/keychain-acl.local-results.txt`. The production backend therefore
uses automatic creator partitions: it verifies the exact running code identity,
inspects the item reference's non-secret partition ACL before every read/update,
and rejects a duplicate with an absent, malformed, or wrong-team partition.

#### Production-backend decision rule

- Because all four tests passed, production creates a new item with a public Security
  API, inspects its partition ACL before treating it as trusted, updates only an
  already-verified item, and inspects again before every data read. A duplicate item
  with an absent or wrong partition must be rejected without reading or updating it.
- If T1 lacks the team partition, silent API creation is insufficient. Keep the backend
  fail-closed until setup has an explicit login-Keychain-password provisioning step;
  LocalAuthentication approval alone does not provide that password to
  `set-generic-password-partition-list`.
- If T4 has the team partition or reads silently, the classic file-Keychain design does
  not provide anti-substitution. Do not weaken the verdict; move to a provisioned data
  protection Keychain access group/app-like bundle or redesign around a Secure Enclave
  signing key.

Repeat the supervised matrix for a release candidate when changing signing identity,
Keychain implementation, or the minimum supported macOS version.

### 1b. Isolated MacKeychain lifecycle (T5)

T1–T4 validate the operating-system property with a small Swift reference. T5 validates
the real Rust MacKeychain FFI, partition-property-list parser, and same-reference
sequencing through a compile-time development-only profile:

```
cd keychain-acl
./run-backend-test.sh --preflight  # build/identity checks only; no Keychain operation
./run-backend-test.sh              # supervised
```

The example is excluded from default builds and requires the
`supervised-probes` Cargo feature. Its type reuses the production implementation
but hardcodes the Apple Development certificate OIDs, isolated identifier/service
`dev.crazytan.kpexec.backend-spike`, and `backend-spike:` account prefix. It cannot
select the production profile at runtime. The runner verifies both the expected
development requirement and rejection of the production Developer ID requirement,
then performs `set -> acl_binding -> get -> update -> get -> delete` on a fresh UUID
account. No Keychain dialog is expected; if one appears, deny it and record failure.

#### Historical backend result

The 2026-08-15 T5 run returned rc0 with no dialog and confirmed cleanup, but it
signed mutable workspace code in the production Developer ID trust domain. Treat
that transcript only as historical implementation-debug evidence. A new passing
result from the isolated Apple Development profile is required before shipping.

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

The harness signs the production-path implementation with its fixed Apple Development
`.spike` identifier, verifies hardened runtime and rejection by the production
Developer ID requirement, then runs both legs itself:

- Interactive → require **AUTHORIZED** (rc=0) after Touch ID or account password and
  record which sheet appeared.
- SSH → require **UNAVAILABLE** (rc=2) and **no GUI sheet**. rc=0 is a hard failure.

It exits nonzero on either mismatch and writes logs plus a results summary under
`local-auth/build/` (gitignored). Exit codes are `0`=authorized, `1`=denied,
`2`=unavailable/fail-closed, `3`=internal.

### 3. `signing/` (legacy direct signer disabled)

```
cd signing
./sign.sh                                  # refuses with rc64; no signing occurs
```

The old helper could Developer-ID-sign any path and is now a fail-closed tombstone.
It cannot be used as a signing oracle for mutable probe code. The production `.pkg`
workflow, source/build verification, explicit credentialed signing, submission
guards, stapling, payload inspection, Gatekeeper assessment, and checksums are in the
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
| production sign/verify | release workflow output | reviewed artifact; Team ID + identifier + `runtime` flag |
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
| production sign/verify | `scripts/release.sh` credentialed stage | n/a | n/a | | reviewed artifact, TeamID+runtime | | |
| notarize | `notarize.sh <artifact>` | n/a | n/a | | Accepted | | submission id: |

### Recorded LocalAuthentication result

The first supervised attempt was correctly treated as a failure because macOS routed a
GUI authorization sheet from the SSH process to the active console. That observation led
to the production `SessionGetInfo` preflight described below; no passing result was
claimed for that attempt.

The corrected production-path probe was rerun on 2026-08-15 PDT (2026-08-16T05:12:45Z)
by `tan` on macOS 26.6.1 (25G76), arm64. Signed probe SHA-256:
`f7d20f74fd52aa388c9e93ac172e0ea7db5834e2080397471176ba5749829783`.
That historical run used Developer ID on mutable code; retain it only as behavioral
debug evidence and rerun the current Apple Development harness for ship acceptance.

| Leg | GUI sheet | Method | Exit | Diagnostic | Result |
|-----|-----------|--------|------|------------|--------|
| Console interactive | yes | account password | 0 | `AUTHORIZED` | **PASS** |
| BatchMode SSH | no | n/a | 2 | remote Security session disabled before `LAContext` | **PASS** |

The local machine-readable evidence and stdout/stderr logs are written to the gitignored
`spikes/local-auth/build/` directory. The table above is the durable repository record;
future OS/release-candidate validation should append a new dated result rather than
overwriting this one.

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
4. **LA over SSH security-session rejection** — macOS can route LocalAuthentication UI
   from an SSH process to the active console. The production gate therefore rejects
   `sessionIsRemote` or non-graphical Security sessions before creating `LAContext`.
   Expect `LocalAuthentication is disabled for remote security sessions`, rc2, and no
   sheet. Any LAError or GUI sheet in this leg means the preflight did not hold.
5. **Code requirement separation** — each supervised runner verifies its Apple
   Development requirement and requires the same bytes to fail the production
   Developer ID requirement. Production requirement evidence comes only from the
   reviewed release workflow.
6. **notarize stapling on a bare binary** — `stapler staple` is expected to fail on a
   bare Mach-O / plain `.zip`; the skeleton surfaces this rather than hiding it, flagging
   that release packaging must wrap kpexec in a stapleable container (`.dmg`/`.pkg`).
