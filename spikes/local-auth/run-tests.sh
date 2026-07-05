#!/usr/bin/env bash
# run-tests.sh — milestone-zero item-3: LocalAuthentication from a signed CLI binary.
#
# THIS SCRIPT TRIGGERS A TOUCH ID / PASSWORD SHEET. Run with a human present.
# It compiles + signs laprobe, runs it once interactively, then prints instructions for
# the SSH leg (which MUST fail closed — UNAVAILABLE, never PASS).
#
# laprobe exit codes: 0=PASS(authenticated) 1=DENIED 2=UNAVAILABLE(fail-closed) 3=error

set -euo pipefail

IDENTITY="Developer ID Application: Jia Tan (V82M9YX8BR)"
IDENTIFIER="dev.crazytan.kpexec"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/laprobe.swift"
BIN="$HERE/laprobe"

run() { echo "+ $*"; "$@"; }

pause() {
    echo
    echo "----------------------------------------------------------------------"
    echo ">>> $1"
    read -r -p ">>> Press Enter when ready and watching the screen... " _
    echo "----------------------------------------------------------------------"
}

echo "== kpexec local-auth spike =="
echo "identity:   $IDENTITY"
echo "identifier: $IDENTIFIER"
echo

echo "########## build + sign ##########"
run /usr/bin/swiftc -framework LocalAuthentication -o "$BIN" "$SRC"
run codesign --force --options runtime \
    --identifier "$IDENTIFIER" \
    --sign "$IDENTITY" \
    "$BIN"
run codesign --verify --strict --verbose=2 "$BIN"
run codesign -d -vv "$BIN" || true

# =========================================================================
# LA interactive leg — expect PASS (or DENIED if you choose to cancel)
# =========================================================================
echo
echo "########## LA interactive: expect the auth sheet ##########"
pause "About to run laprobe in THIS terminal. EXPECT a Touch ID / password sheet titled \
with the reason 'kpexec spike: approve test mutation'. Approve it to get PASS (rc=0); \
or cancel to confirm DENIED (rc=1). Note whether Touch ID was requested."
set +e
"$BIN"
la_rc=$?
set -e
echo ">>> LA interactive exit code: $la_rc  (0=PASS 1=DENIED 2=UNAVAILABLE 3=error)"
case "$la_rc" in
    0) echo ">>> LA interactive VERDICT: PASS — sheet presented and authenticated." ;;
    1) echo ">>> LA interactive VERDICT: DENIED — sheet presented, you cancelled/failed." ;;
    2) echo ">>> LA interactive VERDICT: UNEXPECTED UNAVAILABLE in a GUI terminal — investigate."
       echo ">>>   (Are you actually in an Aqua session? Is a passcode/biometry enrolled?)" ;;
    *) echo ">>> LA interactive VERDICT: error rc=$la_rc — investigate." ;;
esac

# =========================================================================
# LA-over-SSH leg — MUST fail closed (UNAVAILABLE, rc=2). Never PASS.
# =========================================================================
echo
echo "########## LA over SSH: MUST fail closed ##########"
cat <<EOF

The SSH leg proves LocalAuthentication cannot be satisfied from a non-GUI session — the
property kpexec's write gate depends on. Run it in a SEPARATE step, from an SSH login that
is NOT attached to the console GUI session.

  How to run it (from another machine, or a fresh shell):

    ssh localhost "$BIN"; echo "ssh-leg rc=\$?"

  Notes:
    * 'ssh localhost' still lands on this Mac but in a session NOT owned by the console
      user's GUI — that is the point. Do NOT unlock/deny anything; there should be no sheet.
    * EXPECT: no auth sheet at all, and rc=2 (UNAVAILABLE) with an LAError printed to
      stderr (commonly notInteractive / biometryNotAvailable).
    * FAIL-CLOSED CHECK: rc=0 (PASS) over SSH is a HARD FAIL — it would mean the write gate
      can be bypassed headless. rc=2 is the required pass. rc=1 (DENIED) is acceptable only
      if a sheet somehow appeared and was denied, but rc=2 is the expected/clean result.
    * If ssh to localhost is disabled, enable Remote Login in System Settings > General >
      Sharing for the duration of the test, or run over SSH from a second machine.

Record the SSH-leg rc and whether any sheet appeared in the results table (../README.md).
EOF

echo
echo "== interactive leg done. Run the SSH leg per instructions above, then fill the table. =="
