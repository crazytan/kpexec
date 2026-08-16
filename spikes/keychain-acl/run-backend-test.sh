#!/usr/bin/env bash
# Supervised, secret-free runtime validation of the MacKeychain implementation.
#
# The example is compiled with a feature-gated profile whose Apple Development
# requirement, identifier, isolated service, and account prefix are hardcoded.
# Production constants and Developer ID credentials are never selected. It then
# exercises set -> acl_binding -> get -> update -> get -> delete on one generated
# account. Synthetic values are compared only in memory and are never printed.

set -euo pipefail

readonly IDENTITY="Apple Development: Jia Tan (ZW5U6862Q8)"
readonly IDENTIFIER="dev.crazytan.kpexec.backend-spike"
readonly SERVICE="dev.crazytan.kpexec.backend-spike"
readonly TEAM_ID="V82M9YX8BR"
readonly DEVELOPMENT_REQUIREMENT="identifier \"$IDENTIFIER\" and anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.2] exists and certificate leaf[field.1.2.840.113635.100.6.1.12] exists and certificate leaf[subject.OU] = \"$TEAM_ID\""
readonly PRODUCTION_REQUIREMENT="identifier \"dev.crazytan.kpexec\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$TEAM_ID\""

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RESULTS_FILE="${KPEXEC_BACKEND_RESULTS_FILE:-$HERE/keychain-backend.local-results.txt}"
WORK=""
BINARY=""
ACCOUNT=""

preflight() {
    local failures=0 identity_output
    echo "== non-interactive development-profile Keychain backend preflight =="
    echo "No Keychain item is created, changed, read, or deleted by this mode."

    for tool in cargo /usr/bin/codesign /usr/bin/security /usr/bin/uuidgen; do
        if [[ -x "$tool" ]] || command -v "$tool" >/dev/null 2>&1; then
            echo "OK: $tool"
        else
            echo "FAIL: required tool unavailable: $tool" >&2
            failures=$((failures + 1))
        fi
    done
    if cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked \
        --example keychain_backend_probe >/dev/null 2>&1; then
        echo "FAIL: backend probe built without its supervised-probes feature" >&2
        failures=$((failures + 1))
    else
        echo "OK: default/release build excludes the backend probe"
    fi
    cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked \
        --features supervised-probes --example keychain_backend_probe
    echo "OK: development-profile backend probe builds only with its explicit feature"

    identity_output="$(/usr/bin/security find-identity -v -p codesigning 2>&1)"
    if grep -Fq "\"$IDENTITY\"" <<<"$identity_output"; then
        echo "OK: Apple Development identity is installed and currently valid"
    else
        echo "FAIL: signing identity not found: $IDENTITY" >&2
        failures=$((failures + 1))
    fi

    if command -v shellcheck >/dev/null 2>&1; then
        shellcheck -x "$0"
        echo "OK: shellcheck"
    fi
    if [[ "$failures" -ne 0 ]]; then
        echo "preflight: $failures failure(s)" >&2
        return 1
    fi
    echo "preflight: PASS — ready for one supervised ./run-backend-test.sh session"
}

if [[ "${1:-}" == "--preflight" ]]; then
    preflight
    exit $?
elif [[ "$#" -ne 0 ]]; then
    echo "usage: $0 [--preflight]" >&2
    exit 10
fi

if [[ -n "${SSH_CONNECTION:-}" || ! -t 0 ]]; then
    echo "FAIL: run this supervised test in a console-attached Terminal." >&2
    exit 10
fi

pause() {
    echo
    echo "----------------------------------------------------------------------"
    echo ">>> $1"
    read -r -p ">>> Press Enter when you are watching the screen and ready... " _
    echo "----------------------------------------------------------------------"
}

ask_dialog() {
    local answer
    while true; do
        read -r -p ">>> Did any Keychain dialog appear during the lifecycle? [y/n] " answer
        case "$answer" in
            y|Y|yes|YES) printf 'yes'; return ;;
            n|N|no|NO) printf 'no'; return ;;
            *) echo ">>> Please answer y or n." >&2 ;;
        esac
    done
}

cleanup() {
    local item_rc
    if [[ -n "$BINARY" && -x "$BINARY" && -n "$ACCOUNT" ]]; then
        echo "+ development backend exact-account cleanup: $SERVICE / $ACCOUNT"
        "$BINARY" cleanup "$ACCOUNT" >/dev/null 2>&1 || true

        # Attribute-only existence check. The fallback is still scoped to the
        # generated account and runs while the operator is present.
        set +e
        /usr/bin/security find-generic-password \
            -s "$SERVICE" -a "$ACCOUNT" login.keychain-db >/dev/null 2>&1
        item_rc=$?
        set -e
        if [[ "$item_rc" -eq 0 ]]; then
            echo ">>> Signed cleanup failed; delete only $SERVICE / $ACCOUNT (never choose Always Allow)."
            /usr/bin/security delete-generic-password \
                -s "$SERVICE" -a "$ACCOUNT" login.keychain-db >/dev/null 2>&1 || true
        fi
    fi
    if [[ -n "$WORK" && -d "$WORK" ]]; then
        rm -rf -- "$WORK"
    fi
}

umask 077
if ! (set -o noclobber; : > "$RESULTS_FILE") 2>/dev/null; then
    echo "FAIL: results file already exists: $RESULTS_FILE" >&2
    exit 10
fi
trap cleanup EXIT

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kpexec-keychain-backend.XXXXXX")"
BINARY="$WORK/keychain_backend_probe"
ACCOUNT="backend-spike:$(/usr/bin/uuidgen | tr '[:upper:]' '[:lower:]')"

cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked \
    --features supervised-probes --example keychain_backend_probe
cp "$ROOT/target/release/examples/keychain_backend_probe" "$BINARY"

pause "Apple Development signing may request private-key access. Approve only '$IDENTITY'."
/usr/bin/codesign --force --timestamp=none --options runtime \
    --identifier "$IDENTIFIER" --sign "$IDENTITY" "$BINARY"
/usr/bin/codesign --verify --strict --verbose=2 \
    -R="$DEVELOPMENT_REQUIREMENT" "$BINARY"
signature="$(/usr/bin/codesign --display --verbose=4 "$BINARY" 2>&1)"
grep -Fq "Identifier=$IDENTIFIER" <<<"$signature"
grep -Fq "TeamIdentifier=$TEAM_ID" <<<"$signature"
grep -Eq '^CodeDirectory .* flags=.*\(runtime\)' <<<"$signature"

# A supervised probe must never enter the production Developer ID trust
# domain. This is an expected negative verification of the exact signed bytes.
if /usr/bin/codesign --verify --strict \
    -R="$PRODUCTION_REQUIREMENT" "$BINARY" >/dev/null 2>&1; then
    echo "FAIL: development probe unexpectedly satisfies the production requirement" >&2
    exit 1
fi
echo "PASS: development probe cannot satisfy the production Developer ID requirement"

{
    echo "date=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "macOS=$(sw_vers -productVersion) build=$(sw_vers -buildVersion)"
    echo "service=$SERVICE"
    echo "account=$ACCOUNT"
    echo "profile=apple-development-supervised-probe"
    echo "signed_sha256=$(/usr/bin/shasum -a 256 "$BINARY" | awk '{print $1}')"
    echo "NOTE: synthetic values only; credential material is never printed."
} >> "$RESULTS_FILE"

pause "The signed development backend will create, verify, read, update, read, and delete ONLY $SERVICE / $ACCOUNT. Expect no Keychain dialog."
set +e
"$BINARY" lifecycle "$ACCOUNT"
lifecycle_rc=$?
set -e
dialog="$(ask_dialog)"

if [[ "$lifecycle_rc" -eq 0 && "$dialog" == no ]]; then
    verdict=PASS
else
    verdict=FAIL
fi
printf 'T5 backend_lifecycle_rc=%s dialog=%s verdict=%s\n' \
    "$lifecycle_rc" "$dialog" "$verdict" | tee -a "$RESULTS_FILE"
echo "OVERALL=$verdict" | tee -a "$RESULTS_FILE"
echo "Results: $RESULTS_FILE"

if [[ "$verdict" != PASS ]]; then
    exit 1
fi
