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
#   prompt) is what blocks T4: an item minted by `security` (the specially partitioned
#   Apple security tool, `apple-tool:`) with `-T kcprobe` adds kcprobe as a trusted app
#   yet does NOT put
#   kpexec's `teamid:` into the partition list — and adding a `teamid:` partition entry
#   requires the login password (an interactive unlock). So T4 SHOULD prompt/deny.
#   We verify both empirically below by dumping the partition list with:
#     security dump-keychain -a   (attributes only; never dumps secret data without auth)
#   and by the T4 read result. The script combines these with human dialog observations
#   in its local result file.

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
RESULTS_FILE="${KPEXEC_ACL_RESULTS_FILE:-$HERE/keychain-acl.local-results.txt}"
WORK=""
BIN=""
BIN_COPY=""

preflight() {
    local failures=0 identity_output item_rc preflight_dir
    echo "== non-interactive keychain ACL preflight =="
    echo "No Keychain item is created, changed, read, or deleted by this mode."

    for tool in /usr/bin/swiftc /usr/bin/codesign /usr/bin/security /usr/bin/shasum awk; do
        if [[ -x "$tool" ]] || command -v "$tool" >/dev/null 2>&1; then
            echo "OK: $tool"
        else
            echo "FAIL: required tool unavailable: $tool" >&2
            failures=$((failures + 1))
        fi
    done

    if command -v shellcheck >/dev/null 2>&1; then
        shellcheck -x "$0"
        echo "OK: shellcheck"
    else
        echo "WARN: shellcheck unavailable (not required for the supervised run)"
    fi
    /usr/bin/swiftc -typecheck "$SRC"
    echo "OK: Swift source type-checks"

    # Ad-hoc signing exercises the build/sign mechanics without asking the
    # login Keychain for the Developer ID private key.
    preflight_dir="$(mktemp -d "${TMPDIR:-/tmp}/kpexec-keychain-acl-preflight.XXXXXX")"
    /usr/bin/swiftc -framework Security -o "$preflight_dir/kcprobe-v1" "$SRC"
    /usr/bin/swiftc -D KC_PROBE_V2 -framework Security \
        -o "$preflight_dir/kcprobe-v2" "$SRC"
    if cmp -s "$preflight_dir/kcprobe-v1" "$preflight_dir/kcprobe-v2"; then
        echo "FAIL: T1/T3 probe generations unexpectedly have identical bytes" >&2
        failures=$((failures + 1))
    else
        echo "OK: T3 probe generation has different bytes"
    fi
    /usr/bin/codesign --force --sign - \
        --identifier "$IDENTIFIER.preflight" "$preflight_dir/kcprobe-v1" >/dev/null
    /usr/bin/codesign --verify --strict "$preflight_dir/kcprobe-v1"
    echo "OK: isolated build and ad-hoc sign"
    rm -rf -- "$preflight_dir"

    identity_output="$(/usr/bin/security find-identity -v -p codesigning 2>&1)"
    if grep -Fq "\"$IDENTITY\"" <<<"$identity_output"; then
        echo "OK: Developer ID identity is installed and currently valid"
    else
        echo "FAIL: signing identity not found: $IDENTITY" >&2
        failures=$((failures + 1))
    fi

    # Attribute-only lookup: omitting -w never asks Keychain for item data.
    for account in "$ACCT_MAIN" "$ACCT_PLANTED"; do
        set +e
        /usr/bin/security find-generic-password \
            -s "$SERVICE" -a "$account" login.keychain-db >/dev/null 2>&1
        item_rc=$?
        set -e
        if [[ "$item_rc" -eq 44 ]]; then
            echo "OK: no leftover $SERVICE / $account item"
        elif [[ "$item_rc" -eq 0 ]]; then
            echo "FAIL: leftover $SERVICE / $account item exists; clean it in the supervised session" >&2
            failures=$((failures + 1))
        else
            echo "FAIL: attribute-only lookup for $account returned rc=$item_rc" >&2
            failures=$((failures + 1))
        fi
    done

    echo "console user: $(stat -f '%Su' /dev/console)"
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        echo "FAIL: run the supervised matrix at the console, not over SSH" >&2
        failures=$((failures + 1))
    elif [[ -t 0 ]]; then
        echo "OK: interactive terminal detected"
    else
        echo "WARN: no TTY in this preflight process; use Terminal.app for the supervised run"
    fi

    if [[ "$failures" -ne 0 ]]; then
        echo "preflight: $failures failure(s)" >&2
        return 1
    fi
    echo "preflight: PASS — ready for one supervised ./run-tests.sh session"
}

if [[ "${1:-}" == "--preflight" ]]; then
    preflight
    exit $?
elif [[ "$#" -ne 0 ]]; then
    echo "usage: $0 [--preflight]" >&2
    exit 10
fi

if [[ -n "${SSH_CONNECTION:-}" || ! -t 0 ]]; then
    echo "FAIL: the supervised matrix requires a console-attached interactive terminal." >&2
    echo "Run '$0 --preflight' here, then run '$0' in Terminal.app." >&2
    exit 10
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kpexec-keychain-acl.XXXXXX")"
BIN="$WORK/kcprobe"                    # T1/T3 signed binary
BIN_COPY="$WORK/kcprobe-copy"          # T2 differently-signed copy

echo "== kpexec keychain-acl spike =="
echo "service (isolated):    $SERVICE"
echo "identity:              $IDENTITY"
echo "identifier:            $IDENTIFIER"
echo "team id:               $TEAM_ID"
echo

# run() echoes then executes; used for every non-interactive command.
run() { echo "+ $*"; "$@"; }

record() {
    printf '%s\n' "$*" | tee -a "$RESULTS_FILE"
}

pause() {
    echo
    echo "----------------------------------------------------------------------"
    echo ">>> $1"
    read -r -p ">>> Press Enter when you are watching the screen and ready to continue... " _
    echo "----------------------------------------------------------------------"
}

ask_dialog() {
    local label=$1 answer
    while true; do
        read -r -p ">>> Did a Keychain dialog appear during $label? [y/n] " answer
        case "$answer" in
            y|Y|yes|YES) printf 'yes'; return ;;
            n|N|no|NO) printf 'no'; return ;;
            *) echo ">>> Please answer y or n." >&2 ;;
        esac
    done
}

dump_item_acl() {
    local account=$1 output=$2
    /usr/bin/security dump-keychain -a login.keychain-db 2>/dev/null |
        awk -v acct="$account" '
            BEGIN { RS="keychain: "; ORS="" }
            index($0, "\"acct\"<blob>=\"" acct "\"") { print "keychain: " $0 }
        ' | tee "$output"
    if [[ ! -s "$output" ]]; then
        echo "FAIL: could not isolate ACL output for account $account" >&2
        return 1
    fi
}

has_partition() {
    local acl_file=$1 partition=$2
    grep -Eq 'authorizations .*partition_id' "$acl_file" &&
        grep -Fq "description: $partition" "$acl_file"
}

cleanup() {
    echo
    echo "== cleanup: deleting ONLY service=$SERVICE items =="
    # Delete each item through its creator partition to avoid manufacturing an
    # extra authorization prompt during normal cleanup.
    if [[ -x "$BIN" ]]; then
        echo "+ $BIN delete $SERVICE $ACCT_MAIN"
        "$BIN" delete "$SERVICE" "$ACCT_MAIN" || true
    fi
    echo "+ security delete-generic-password -s $SERVICE -a $ACCT_PLANTED"
    /usr/bin/security delete-generic-password \
        -s "$SERVICE" -a "$ACCT_PLANTED" login.keychain-db >/dev/null 2>&1 || true

    # Best-effort fallback if T1 failed before a signed probe existed. This may
    # ask the supervised operator for authorization; never choose Always Allow.
    set +e
    /usr/bin/security find-generic-password \
        -s "$SERVICE" -a "$ACCT_MAIN" login.keychain-db >/dev/null 2>&1
    main_still_exists=$?
    set -e
    if [[ "$main_still_exists" -eq 0 ]]; then
        echo ">>> Cleanup fallback must delete $ACCT_MAIN; approve only this isolated spike item."
        /usr/bin/security delete-generic-password \
            -s "$SERVICE" -a "$ACCT_MAIN" login.keychain-db >/dev/null 2>&1 || true
    fi
    if [[ -n "$WORK" && -d "$WORK" ]]; then
        rm -rf -- "$WORK"
    fi
    echo "cleanup done (service $SERVICE only; other services untouched)."
}

umask 077
if ! (set -o noclobber; : > "$RESULTS_FILE") 2>/dev/null; then
    echo "FAIL: results file already exists: $RESULTS_FILE" >&2
    echo "Move it aside after attaching it, then rerun." >&2
    exit 10
fi
trap cleanup EXIT
record "date=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
record "operator=${USER:-unknown}"
record "macOS=$(sw_vers -productVersion) build=$(sw_vers -buildVersion)"
record "service=$SERVICE"
record "NOTE: synthetic spike values only; no real credential data is recorded."

# =========================================================================
# T1 — build, sign (Developer ID + hardened runtime + identifier), create+read
# =========================================================================
echo
echo "########## T1: team-signed binary, silent create+read ##########"
run /usr/bin/swiftc -framework Security -o "$BIN" "$SRC"
pause "Developer ID signing may ask for private-key access. Approve only the codesign request for '$IDENTITY'."
run /usr/bin/codesign --force --options runtime --timestamp=none \
    --identifier "$IDENTIFIER" \
    --sign "$IDENTITY" \
    "$BIN"
run /usr/bin/codesign --verify --strict --verbose=2 "$BIN"
run /usr/bin/codesign -d -vv "$BIN" || true
t1_hash="$(/usr/bin/shasum -a 256 "$BIN" | awk '{print $1}')"
/usr/bin/codesign -d --requirements - "$BIN" > "$WORK/t1.requirement" 2>&1
record "T1 signed_sha256=$t1_hash"
record "T1 designated_requirement=$(tr '\n' ' ' < "$WORK/t1.requirement")"

pause "T1 create: about to CREATE the item. This should NOT prompt. Watch for any dialog."
run "$BIN" create "$SERVICE" "$ACCT_MAIN" "$VALUE"
t1_create_dialog="$(ask_dialog 'T1 create')"
record "T1 create_dialog=$t1_create_dialog"

echo
echo "-- dump partition list / ACL for the freshly created item (attributes only) --"
echo "+ security dump-keychain -a login.keychain-db  (isolate account $ACCT_MAIN)"
dump_item_acl "$ACCT_MAIN" "$WORK/t1.acl"
if has_partition "$WORK/t1.acl" "teamid:$TEAM_ID"; then
    t1_partition=present
else
    t1_partition=absent
fi
record "T1 partition_teamid_$TEAM_ID=$t1_partition"

pause "T1 read: about to READ with the SAME signed binary. EXPECT: silent success, NO dialog."
set +e
"$BIN" read "$SERVICE" "$ACCT_MAIN"
t1_rc=$?
set -e
t1_dialog="$(ask_dialog 'T1 read')"
if [[ "$t1_rc" -eq 0 && "$t1_dialog" == no && "$t1_partition" == present ]]; then
    t1_verdict=PASS
else
    t1_verdict=FAIL
fi
record "T1 read_rc=$t1_rc dialog=$t1_dialog partition=$t1_partition verdict=$t1_verdict"

# =========================================================================
# T2 — copy binary, re-sign ad-hoc with a DIFFERENT identifier, read -> expect prompt
# =========================================================================
echo
echo "########## T2: differently-signed copy, expect prompt/denial ##########"
run cp "$BIN" "$BIN_COPY"
# Ad-hoc (-s -) sign, DIFFERENT identifier => different designated requirement => not the
# blessed code. This is the "self-built / attacker binary" case.
run /usr/bin/codesign --force --sign - --identifier "dev.crazytan.kpexec.impostor" "$BIN_COPY"
run /usr/bin/codesign -d -vv "$BIN_COPY" || true

pause "T2 read: about to READ the SAME item with the DIFFERENTLY-SIGNED copy. \
EXPECT: a Keychain confirmation dialog (Allow/Always Allow/Deny). \
DENY it to prove the gate holds; the tool should then report user-canceled (exit 4)."
# Do not let a non-zero exit abort the script; we want to record the status.
set +e
"$BIN_COPY" read "$SERVICE" "$ACCT_MAIN"
t2_rc=$?
set -e
t2_dialog="$(ask_dialog 'T2 read')"
if [[ "$t2_dialog" == yes || "$t2_rc" -ne 0 ]]; then
    t2_verdict=PASS
else
    t2_verdict=FAIL
fi
record "T2 read_rc=$t2_rc dialog=$t2_dialog verdict=$t2_verdict"
echo ">>> T2 verdict: $t2_verdict (pass means the read was not silent)."

# =========================================================================
# T3 — rebuild (different bytes), re-sign SAME identity+identifier, read -> silent (A15)
# =========================================================================
echo
echo "########## T3: version-upgrade simulation, expect silent read (A15) ##########"
# KC_PROBE_V2 changes observable program data, guaranteeing different bytes.
run /usr/bin/swiftc -D KC_PROBE_V2 -framework Security -o "$BIN" "$SRC"
pause "T3 re-signs different bytes with the same identity and identifier. Approve only a codesign private-key request."
run /usr/bin/codesign --force --options runtime --timestamp=none \
    --identifier "$IDENTIFIER" \
    --sign "$IDENTITY" \
    "$BIN"
run /usr/bin/codesign --verify --strict --verbose=2 "$BIN"
t3_hash="$(/usr/bin/shasum -a 256 "$BIN" | awk '{print $1}')"
/usr/bin/codesign -d --requirements - "$BIN" > "$WORK/t3.requirement" 2>&1
if [[ "$t1_hash" != "$t3_hash" ]]; then
    bytes_changed=yes
else
    bytes_changed=no
fi
if cmp -s "$WORK/t1.requirement" "$WORK/t3.requirement"; then
    requirement_same=yes
else
    requirement_same=no
fi
record "T3 signed_sha256=$t3_hash bytes_changed=$bytes_changed designated_requirement_same=$requirement_same"

pause "T3 read: the binary was rebuilt (new bytes) but re-signed with the SAME Team ID + \
identifier — simulating a kpexec upgrade. EXPECT: silent success, NO new dialog (A15)."
set +e
"$BIN" read "$SERVICE" "$ACCT_MAIN"
t3_rc=$?
set -e
t3_dialog="$(ask_dialog 'T3 read')"
if [[ "$t3_rc" -eq 0 && "$t3_dialog" == no && "$bytes_changed" == yes && "$requirement_same" == yes ]]; then
    t3_verdict=PASS
else
    t3_verdict=FAIL
fi
record "T3 read_rc=$t3_rc dialog=$t3_dialog bytes_changed=$bytes_changed requirement_same=$requirement_same verdict=$t3_verdict"
echo ">>> T3 verdict: $t3_verdict"

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
If a dialog appears, choose Allow (never Always Allow) so the worst-case planted item exists."
run /usr/bin/security add-generic-password \
    -s "$SERVICE" \
    -a "$ACCT_PLANTED" \
    -w "planted-by-simulated-agent" \
    -T "$BIN" \
    login.keychain-db
t4_plant_dialog="$(ask_dialog 'T4 plant')"
record "T4 plant_dialog=$t4_plant_dialog"

echo
echo "-- dump partition list / ACL for the PLANTED item --"
echo "+ security dump-keychain -a login.keychain-db  (isolate account $ACCT_PLANTED)"
dump_item_acl "$ACCT_PLANTED" "$WORK/t4.acl"
if has_partition "$WORK/t4.acl" "teamid:$TEAM_ID"; then
    t4_team_partition=present
else
    t4_team_partition=absent
fi
if has_partition "$WORK/t4.acl" "apple-tool:"; then
    t4_apple_partition=present
else
    t4_apple_partition=absent
fi
record "T4 partition_teamid_$TEAM_ID=$t4_team_partition partition_apple_tool=$t4_apple_partition"

pause "T4 read: about to READ the PLANTED item with the signed kcprobe. \
EXPECT (design holds): a dialog OR denial — the planted item should NOT be silently readable. \
Watch carefully: if it reads with NO dialog and rc=0, the design assumption is BROKEN."
set +e
"$BIN" read "$SERVICE" "$ACCT_PLANTED"
t4_rc=$?
set -e
t4_dialog="$(ask_dialog 'T4 read')"
if [[ ( "$t4_dialog" == yes || "$t4_rc" -ne 0 ) \
    && "$t4_team_partition" == absent && "$t4_apple_partition" == present ]]; then
    t4_verdict=PASS
else
    t4_verdict=FAIL
fi
record "T4 read_rc=$t4_rc dialog=$t4_dialog team_partition=$t4_team_partition apple_tool_partition=$t4_apple_partition verdict=$t4_verdict"
if [[ "$t4_verdict" == FAIL ]]; then
    echo "######################################################################"
    echo "### T4 FAIL: silent-read protection or expected ACL provenance did ###"
    echo "### not hold. Inspect read_rc/dialog and both partition fields in   ###"
    echo "### the result file before changing the production backend.         ###"
    echo "######################################################################"
else
    echo ">>> T4 VERDICT: PASS — planted item not silently readable (rc=$t4_rc dialog=$t4_dialog)."
fi

echo
if [[ "$t1_verdict" == PASS && "$t2_verdict" == PASS && "$t3_verdict" == PASS && "$t4_verdict" == PASS ]]; then
    overall=PASS
else
    overall=FAIL
fi
record "OVERALL=$overall"
echo "== all test steps executed: $overall =="
echo "== machine + human observations saved to: $RESULTS_FILE =="
echo "== Attach that file to the implementation task; it contains no real secret. =="
echo "== cleanup runs now via trap. =="
