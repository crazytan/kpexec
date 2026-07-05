#!/usr/bin/env bash
# notarize.sh — SKELETON for the milestone-zero item-4 notarization leg.
#
# ============================ ONE-TIME SETUP (the user must do this) ============================
# Notarization needs Apple-issued credentials stored under a named keychain profile. This is a
# ONE-TIME, INTERACTIVE step you (the human) run once; this script then references the profile by
# name and never handles raw credentials.
#
#   xcrun notarytool store-credentials kpexec-notary \
#       --apple-id "<your-apple-id-email>" \
#       --team-id  "V82M9YX8BR" \
#       --password "<app-specific-password>"
#
#   * <app-specific-password> is an APP-SPECIFIC password generated at
#     https://account.apple.com  (Sign-In and Security > App-Specific Passwords) — NOT your
#     real Apple ID password. notarytool stores it in the keychain under the profile name
#     'kpexec-notary'; from then on only the profile name is referenced.
#   * Alternatively, App Store Connect API keys (--key / --key-id / --issuer) can back the
#     profile; either way the result is a named profile this script consumes.
#
# This SKELETON deliberately does NOT fabricate any credential handling beyond referencing the
# profile name. Do not add Apple IDs, passwords, or API keys into this file or the repo.
# ================================================================================================
#
# Usage: ./notarize.sh <signed-artifact>
#   <signed-artifact> should already be signed by sign.sh (Developer ID + hardened runtime +
#   secure timestamp). Notarization REQUIRES hardened runtime and a secure timestamp.
#
# notarytool submits a .zip (or .dmg/.pkg). A bare Mach-O binary must be zipped first. Stapling
# a ticket to a bare binary is not supported — for a CLI, the notarization ticket is validated
# online by Gatekeeper; distribute inside a stapled .dmg/.pkg/.zip container as needed. This
# skeleton shows the submit + (attempted) staple flow; wire it into the real release packaging
# when kpexec ships.

set -euo pipefail

PROFILE="kpexec-notary"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <signed-artifact>" >&2
    exit 10
fi

ARTIFACT="$1"
if [[ ! -e "$ARTIFACT" ]]; then
    echo "FAIL: '$ARTIFACT' does not exist" >&2
    exit 11
fi

run() { echo "+ $*"; "$@"; }

echo "== notarize $ARTIFACT via keychain profile '$PROFILE' =="
echo

# Guard: make sure the one-time profile exists before we try to submit.
if ! xcrun notarytool history --keychain-profile "$PROFILE" >/dev/null 2>&1; then
    cat <<EOF >&2
FAIL: notarytool keychain profile '$PROFILE' not found (or not readable).
Run the one-time setup documented in the header of this script:

  xcrun notarytool store-credentials $PROFILE \\
      --apple-id "<your-apple-id-email>" \\
      --team-id  "V82M9YX8BR" \\
      --password "<app-specific-password>"

EOF
    exit 12
fi

# --- submit ---
# --wait blocks until Apple returns Accepted/Invalid; prints a submission id either way.
echo "== submit (blocking until Apple returns a verdict) =="
run xcrun notarytool submit "$ARTIFACT" \
    --keychain-profile "$PROFILE" \
    --wait

# --- staple ---
# Stapling attaches the ticket to the artifact for offline Gatekeeper checks. This works for
# .dmg/.pkg/.app and app bundles; it does NOT work on a bare Mach-O or a raw .zip. If ARTIFACT
# is a container that supports stapling, this succeeds; otherwise it reports why (skeleton lets
# it surface rather than pretending success).
echo
echo "== staple ticket =="
if xcrun stapler staple "$ARTIFACT"; then
    run xcrun stapler validate "$ARTIFACT"
    echo "OK: notarized and stapled."
else
    echo ">>> stapler could not staple '$ARTIFACT' (expected for bare binaries / plain .zip)."
    echo ">>> The submission may still be Accepted — package into a .dmg/.pkg for a stapled,"
    echo ">>> offline-verifiable release artifact, then re-run staple on the container."
fi

echo
echo ">>> HUMAN: record the notarytool submission id and Accepted/Invalid verdict in the"
echo ">>> results table (../README.md). On 'Invalid', run:"
echo ">>>   xcrun notarytool log <submission-id> --keychain-profile $PROFILE"
