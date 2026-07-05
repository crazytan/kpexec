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

## Environment (fixed for these spikes)

- macOS (Darwin 25.5), Apple Silicon, `swiftc` at `/usr/bin/swiftc`
- Signing identity: `Developer ID Application: Jia Tan (V82M9YX8BR)` (login keychain)
- Identifier: `dev.crazytan.kpexec`  · Team ID: `V82M9YX8BR`
- Isolated Keychain service: `dev.crazytan.kpexec.spike`

## Run order

Run in this order; `signing/` builds on what the keychain leg observes.

### 1. `keychain-acl/` (T1–T4)

```
cd keychain-acl
./run-tests.sh
```

The script builds + signs `kcprobe`, then walks T1→T4, pausing before each prompting
step. Answer/deny dialogs as instructed, and **record for each test whether a dialog
appeared**. Cleanup runs automatically on exit.

- **T1** — signed binary create + read → expect silent success, **no dialog**.
- **T2** — differently-signed copy reads the same item → expect a **dialog** (Deny it).
- **T3** — rebuilt (different bytes) + re-signed same Team ID/identifier reads → expect
  **silent** success, no new dialog (this is acceptance test A15).
- **T4** — item planted by `security add-generic-password -T` read by the signed binary
  → **must not** be silently readable. If it reads with no dialog and rc=0, the
  anti-substitution assumption is **BROKEN** — the script flags this loudly.

**Partition-list note:** the script also dumps the item's attributes
(`security dump-keychain -a`) after T1 and T4 so you can confirm whether a
`teamid:V82M9YX8BR` partition is present on the creator-made item and absent on the
planted item. See the header comment in `keychain-acl/run-tests.sh` for the working
expectation and what a divergence would mean. **This is an open runtime question — see
"Runtime uncertainties" below.**

### 2. `local-auth/` (LA interactive, then LA-over-SSH)

```
cd local-auth
./run-tests.sh          # interactive leg — approve the Touch ID / password sheet
```

Then the **SSH leg**, from a session **not** attached to the console GUI:

```
ssh localhost "$PWD/laprobe"; echo "ssh-leg rc=$?"
```

- Interactive → expect **PASS** (rc=0) after Touch ID / password; note if Touch ID was
  requested vs a password sheet.
- SSH → **must** be **UNAVAILABLE** (rc=2), **no sheet**. rc=0 (PASS) over SSH is a hard
  fail (the write gate would be bypassable headless).

`laprobe` exit codes: `0`=PASS, `1`=DENIED, `2`=UNAVAILABLE (fail-closed), `3`=error.

### 3. `signing/` (sign/verify, then notarize)

```
cd signing
./sign.sh <binary> dev.crazytan.kpexec     # e.g. the kcprobe or a real kpexec build
./notarize.sh <signed-artifact>            # requires one-time notarytool profile setup
```

`sign.sh` signs (Developer ID + hardened runtime + timestamp), runs
`codesign --verify --strict`, and displays the signature — confirm `TeamIdentifier=V82M9YX8BR`,
the identifier, and `flags=…(runtime)`. `notarize.sh` is a **skeleton**: it requires a
one-time `xcrun notarytool store-credentials kpexec-notary …` (documented in its header)
and does not fabricate credential handling.

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
| LA interactive | `laprobe` (terminal) | n/a | | | rc0 (PASS) | | |
| LA over SSH | `ssh localhost laprobe` | | n/a | | rc2 (UNAVAILABLE) | | |
| sign/verify | `sign.sh … dev.crazytan.kpexec` | n/a | n/a | | rc0, TeamID+runtime | | |
| notarize | `notarize.sh <artifact>` | n/a | n/a | | Accepted | | submission id: |

## Runtime uncertainties (deliberately left for the supervised run)

These are macOS-API behaviors the harnesses are designed to *reveal*, not assume. Treat
each as an explicit observation point:

1. **Partition list on API-created items.** Whether `SecItemAdd` from a team-signed,
   hardened-runtime binary yields an item whose partition list already contains
   `teamid:V82M9YX8BR` (so no `security set-generic-password-partition-list` is needed),
   or whether an explicit partition-list set is required for silent re-reads. The T1
   `dump-keychain -a` step is there to answer this. If a follow-up
   `set-generic-password-partition-list` proves necessary, that becomes a step kpexec's
   `init` must perform (and will itself trigger a login-password prompt at setup time).
2. **T2 behavior for an ad-hoc-signed reader** — whether macOS shows a confirmation
   dialog (Allow/Deny) vs returns `errSecAuthFailed` outright. Either is a pass for the
   assumption (the point is: not silent); the exact mode is recorded, not assumed.
3. **T4 planted-item readability** — the core anti-substitution check. Expectation: the
   `-T kcprobe` trusted-app entry does **not** grant a silent read because it lacks a
   `teamid:` partition, and adding one needs the login password. If T4 reads silently,
   the design's anti-substitution claim in `security-design.md` must be revisited.
4. **LA over SSH exact LAError** — expected to be `notInteractive` or
   `biometryNotAvailable`, mapped to UNAVAILABLE (rc2). The specific code is printed and
   recorded; the requirement is only that it is **not** PASS.
5. **`codesign -d --requirements -` output shape** — the designated requirement text the
   Keychain ACL should anchor to; captured by `sign.sh` for the record.
6. **notarize stapling on a bare binary** — `stapler staple` is expected to fail on a
   bare Mach-O / plain `.zip`; the skeleton surfaces this rather than hiding it, flagging
   that release packaging must wrap kpexec in a stapleable container (`.dmg`/`.pkg`).
