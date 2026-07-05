#!/usr/bin/env bash
# sign.sh — milestone-zero item-4: sign a binary the way release kpexec must be signed,
# then verify and display the signature.
#
# Usage: ./sign.sh <binary> <identifier>
#   e.g. ./sign.sh ./kpexec dev.crazytan.kpexec
#
# Signs with the Developer ID identity + hardened runtime + the given identifier, then
# runs strict verification and dumps the signature so a human can confirm Team ID,
# identifier, and hardened-runtime flags. Does NOT notarize (see notarize.sh).

set -euo pipefail

IDENTITY="Developer ID Application: Jia Tan (V82M9YX8BR)"

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <binary> <identifier>" >&2
    echo "  e.g. $0 ./kpexec dev.crazytan.kpexec" >&2
    exit 10
fi

BINARY="$1"
IDENTIFIER="$2"

if [[ ! -f "$BINARY" ]]; then
    echo "FAIL: '$BINARY' is not a regular file" >&2
    exit 11
fi

run() { echo "+ $*"; "$@"; }

echo "== signing $BINARY =="
echo "identity:   $IDENTITY"
echo "identifier: $IDENTIFIER"
echo

# --options runtime  => hardened runtime (blocks ptrace / dylib injection into the
#                       process that will hold the vault password in memory).
# --timestamp        => secure timestamp, required for notarization.
run codesign --force --timestamp --options runtime \
    --identifier "$IDENTIFIER" \
    --sign "$IDENTITY" \
    "$BINARY"

echo
echo "== strict verification =="
# --strict + --deep catches nested/inconsistent signatures; non-zero exit aborts (set -e).
run codesign --verify --strict --deep --verbose=2 "$BINARY"

echo
echo "== signature details (Team ID, identifier, hardened-runtime flags) =="
run codesign --display --verbose=4 "$BINARY"

echo
echo "== designated requirement (what the Keychain ACL should anchor to) =="
run codesign --display --requirements - "$BINARY" || true

echo
echo "OK: signed and verified. For a release artifact, next run ./notarize.sh."
echo ">>> HUMAN: confirm the display output shows"
echo ">>>   - 'TeamIdentifier=V82M9YX8BR'"
echo ">>>   - the identifier you passed ('$IDENTIFIER')"
echo ">>>   - 'flags=0x10000(runtime)' (hardened runtime present)"
