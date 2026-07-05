#!/usr/bin/env bash
# run-tests.sh — orchestrates the milestone-zero item-2 Keychain ACL matrix.
#
# THIS SCRIPT TRIGGERS KEYCHAIN GUI PROMPTS. Run it only with a human present who can
# watch the screen and answer/deny dialogs. It is fail-closed and echoes every command.
#
# What it proves (milestone doc item 2 + security-design "Vault access control"):
#   T1  team-signed binary (Developer ID + identifier dev.crazytan.kpexec, hardened
#       runtime) creates an item and reads it back  -> EXPECT silent success, no dialog.
#   T2  the SAME item read by a DIFFERENTLY-signed copy (ad-hoc, different identifier)
#       -> EXPECT a GUI confirmation dialog or denial (human observes).
#   T3  rebuild from source (different bytes) re-signed with the SAME identity+identifier
#       (simulates a kpexec version upgrade) reads the item -> EXPECT silent success.
#       (This is acceptance test A15's property.)
#   T4  an item planted by `security add-generic-password -T <signed kcprobe>` (simulating
#       an agent whitelisting kpexec) read by the signed kcprobe -> RECORD whether it is
#       silently readable. If it IS, that is a FAIL of the anti-substitution design
#       assumption and is flagged LOUDLY.
#
# NOTE (partition-list investigation — answer to be confirmed at runtime):
#   Question: after T1's SecItemAdd from a team-signed + hardened-runtime binary, is a
#   `security set-generic-password-partition-list` call needed for the item to carry a
#   `teamid:V82M9YX8BR` partition, or does the item inherit the right ACL automatically?
#   Working expectation: an item created via the Security API by a process gets an ACL
#   whose trusted-application list is that creating process, and its partition list is
#   seeded from the creator's code signature (partition `teamid:V82M9YX8BR`). No explicit
#   set-partition-list call should be required for the CREATOR to keep reading silently.
#   BUT the *partition list* (which gates which code-signed apps may access without a
#   prompt) is what blocks T4: an item minted by `security` (an Apple-signed tool, team
#   `apple:`) with `-T kcprobe` adds kcprobe as a *trusted application* yet does NOT put
#   kpexec's `teamid:` into the partition list — and adding a `teamid:` partition entry
#   requires the login password (an interactive unlock). So T4 SHOULD prompt/deny.
#   We verify both empirically below by dumping the partition list with:
#     security dump-keychain -a   (attributes only; never dumps secret data without auth)
#   and by the T4 read result. Record the actual behavior in the results table; if it
#   diverges from the above, the security design's anti-substitution claim needs revisiting.

set -euo pipefail

# --- config ---------------------------------------------------------------
IDENTITY="Developer ID Application: Jia Tan (V82M9YX8BR)"
IDENTIFIER="dev.crazytan.kpexec"
TEAM_ID="V82M9YX8BR"
SERVICE="dev.crazytan.kpexec.spike"   # NEVER touch any other service name
ACCT_MAIN="spike-main"
ACCT_PLANTED="spike-planted"
VALUE="spike-secret-do-not-reuse"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/kcprobe.swift"
BIN="$HERE/kcprobe"                    # T1/T3 signed binary
BIN_COPY="$HERE/kcprobe-copy"          # T2 differently-signed copy

echo "== kpexec keychain-acl spike =="
echo "service (isolated):    $SERVICE"
echo "identity:              $IDENTITY"
echo "identifier:            $IDENTIFIER"
echo "team id:               $TEAM_ID"
echo

# run() echoes then executes; used for every non-interactive command.
run() { echo "+ $*"; "$@"; }

pause() {
    echo
    echo "----------------------------------------------------------------------"
    echo ">>> $1"
    read -r -p ">>> Press Enter when you are watching the screen and ready to continue... " _
    echo "----------------------------------------------------------------------"
}

cleanup() {
    echo
    echo "== cleanup: deleting ONLY service=$SERVICE items =="
    # Use whichever signed binary exists; fall back to `security` for the planted item.
    for acct in "$ACCT_MAIN" "$ACCT_PLANTED"; do
        if [[ -x "$BIN" ]]; then
            echo "+ $BIN delete $SERVICE $acct"
            "$BIN" delete "$SERVICE" "$acct" || true
        fi
        # Belt-and-suspenders: security may hold items the binary's ACL can't delete.
        echo "+ security delete-generic-password -s $SERVICE -a $acct (best-effort)"
        security delete-generic-password -s "$SERVICE" -a "$acct" >/dev/null 2>&1 || true
    done
    rm -f "$BIN_COPY"
    echo "cleanup done (service $SERVICE only; other services untouched)."
}
trap cleanup EXIT

# =========================================================================
# T1 — build, sign (Developer ID + hardened runtime + identifier), create+read
# =========================================================================
echo
echo "########## T1: team-signed binary, silent create+read ##########"
run /usr/bin/swiftc -framework Security -o "$BIN" "$SRC"
run codesign --force --options runtime \
    --identifier "$IDENTIFIER" \
    --sign "$IDENTITY" \
    "$BIN"
run codesign --verify --strict --verbose=2 "$BIN"
run codesign -d -vv "$BIN" || true

pause "T1 create: about to CREATE the item. This should NOT prompt. Watch for any dialog."
run "$BIN" create "$SERVICE" "$ACCT_MAIN" "$VALUE"

echo
echo "-- dump partition list / ACL for the freshly created item (attributes only) --"
echo "+ security dump-keychain -a login.keychain-db  (grep for $SERVICE)"
security dump-keychain -a login.keychain-db 2>/dev/null | grep -A2 "$SERVICE" || \
    echo "(no matching attribute lines surfaced; inspect manually with Keychain Access)"
echo ">>> HUMAN: note whether a partition list 'teamid:$TEAM_ID' is shown for this item."

pause "T1 read: about to READ with the SAME signed binary. EXPECT: silent success, NO dialog."
run "$BIN" read "$SERVICE" "$ACCT_MAIN"
echo ">>> T1 VERDICT: PASS iff read succeeded AND no dialog appeared. Record in table."

# =========================================================================
# T2 — copy binary, re-sign ad-hoc with a DIFFERENT identifier, read -> expect prompt
# =========================================================================
echo
echo "########## T2: differently-signed copy, expect prompt/denial ##########"
run cp "$BIN" "$BIN_COPY"
# Ad-hoc (-s -) sign, DIFFERENT identifier => different designated requirement => not the
# blessed code. This is the "self-built / attacker binary" case.
run codesign --force --sign - --identifier "dev.crazytan.kpexec.impostor" "$BIN_COPY"
run codesign -d -vv "$BIN_COPY" || true

pause "T2 read: about to READ the SAME item with the DIFFERENTLY-SIGNED copy. \
EXPECT: a Keychain confirmation dialog (Allow/Always Allow/Deny). \
DENY it to prove the gate holds; the tool should then report user-canceled (exit 4)."
# Do not let a non-zero exit abort the script; we want to record the status.
set +e
"$BIN_COPY" read "$SERVICE" "$ACCT_MAIN"
t2_rc=$?
set -e
echo ">>> T2 read exit code: $t2_rc  (4=Deny/canceled, 3=auth-failed, 0=Allowed-through)"
echo ">>> T2 VERDICT: PASS iff a dialog appeared (regardless of Allow/Deny). "
echo ">>> If it read SILENTLY with rc=0 and NO dialog, that is a FAIL — record it."

# =========================================================================
# T3 — rebuild (different bytes), re-sign SAME identity+identifier, read -> silent (A15)
# =========================================================================
echo
echo "########## T3: version-upgrade simulation, expect silent read (A15) ##########"
# Touch the source so recompiled bytes differ (new mtime + a build stamp comment).
run touch "$SRC"
# Rebuild + re-sign with the SAME identity and identifier as T1.
run /usr/bin/swiftc -framework Security -o "$BIN" "$SRC"
run codesign --force --options runtime \
    --identifier "$IDENTIFIER" \
    --sign "$IDENTITY" \
    "$BIN"
run codesign --verify --strict --verbose=2 "$BIN"

pause "T3 read: the binary was rebuilt (new bytes) but re-signed with the SAME Team ID + \
identifier — simulating a kpexec upgrade. EXPECT: silent success, NO new dialog (A15)."
set +e
"$BIN" read "$SERVICE" "$ACCT_MAIN"
t3_rc=$?
set -e
echo ">>> T3 read exit code: $t3_rc"
echo ">>> T3 VERDICT: PASS iff read succeeded silently (rc=0, no dialog). A new dialog = FAIL."

# =========================================================================
# T4 — agent-planted item (security add-generic-password -T), read with signed binary
# =========================================================================
echo
echo "########## T4: vault-substitution property — agent-planted item ##########"
echo "This simulates an agent that plants a Keychain item and whitelists kpexec with -T."
echo "The anti-substitution design REQUIRES that this item is NOT silently readable by the"
echo "signed kpexec (planting a teamid:-trusted item needs the login password, which the"
echo "agent does not have). If it IS silently readable, the design assumption FAILS."
pause "T4 plant: about to run 'security add-generic-password -T $BIN ...'. \
macOS MAY prompt to authorize the keychain modification — note if it does."
run security add-generic-password \
    -s "$SERVICE" \
    -a "$ACCT_PLANTED" \
    -w "planted-by-simulated-agent" \
    -T "$BIN" \
    login.keychain-db

echo
echo "-- dump partition list / ACL for the PLANTED item --"
echo "+ security dump-keychain -a login.keychain-db  (grep for $ACCT_PLANTED)"
security dump-keychain -a login.keychain-db 2>/dev/null | grep -A2 "$ACCT_PLANTED" || \
    echo "(no matching attribute lines surfaced; inspect manually with Keychain Access)"
echo ">>> HUMAN: note whether the planted item's partition list contains 'teamid:$TEAM_ID'."
echo ">>> Expectation: it should NOT — -T adds a trusted-app entry, not a teamid partition."

pause "T4 read: about to READ the PLANTED item with the signed kcprobe. \
EXPECT (design holds): a dialog OR denial — the planted item should NOT be silently readable. \
Watch carefully: if it reads with NO dialog and rc=0, the design assumption is BROKEN."
set +e
"$BIN" read "$SERVICE" "$ACCT_PLANTED"
t4_rc=$?
set -e
echo ">>> T4 read exit code: $t4_rc"
if [[ "$t4_rc" -eq 0 ]]; then
    echo "######################################################################"
    echo "### T4 POSSIBLE FAIL: planted item returned data (rc=0).           ###"
    echo "### If NO dialog appeared, the anti-substitution assumption is      ###"
    echo "### BROKEN — a signed kpexec would silently read an agent-planted   ###"
    echo "### item. Flag this LOUDLY in the results and revisit the design.   ###"
    echo "### (If a dialog DID appear, that is expected/PASS — record which.) ###"
    echo "######################################################################"
else
    echo ">>> T4 VERDICT: PASS — planted item not silently readable (rc=$t4_rc)."
fi

echo
echo "== all test steps executed. Fill in the results table in ../README.md. =="
echo "== cleanup runs now via trap. =="
