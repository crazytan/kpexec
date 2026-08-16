#!/usr/bin/env bash
# Validate LocalAuthentication through the hardened kpexec implementation.
#
# Safe mode (never executes LocalAuthentication or uses the signing private key):
#   ./run-tests.sh --check-only
#
# Prompt-bearing supervised mode (Apple-Development-signs an isolated probe, then
# runs GUI + SSH legs in one session):
#   ./run-tests.sh --supervised
#
# Production probe exit codes: 0=authorized, 1=denied, 2=unavailable, 3=internal.

set -euo pipefail

readonly IDENTITY="Apple Development: Jia Tan (ZW5U6862Q8)"
readonly IDENTIFIER="dev.crazytan.kpexec.local-auth.spike"
readonly TEAM_ID="V82M9YX8BR"
readonly DEVELOPMENT_REQUIREMENT="identifier \"$IDENTIFIER\" and anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.2] exists and certificate leaf[field.1.2.840.113635.100.6.1.12] exists and certificate leaf[subject.OU] = \"$TEAM_ID\""
readonly PRODUCTION_REQUIREMENT="identifier \"dev.crazytan.kpexec\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$TEAM_ID\""

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$HERE/laprobe.swift"
BUILD_DIR="${KPEXEC_LA_BUILD_DIR:-$HERE/build}"
BIN="${KPEXEC_LA_PROBE:-$REPO_ROOT/target/release/examples/user_presence_probe}"
RELEASE_BIN="$REPO_ROOT/target/release/kpexec"
RESULTS="$BUILD_DIR/results.txt"
INTERACTIVE_LOG="$BUILD_DIR/interactive.log"
SSH_LOG="$BUILD_DIR/ssh.log"
SSH_IDENTITY="${KPEXEC_LA_SSH_IDENTITY:-}"
SSH_OPTIONS=(
    -T
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o StrictHostKeyChecking=yes
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=2
)
if [[ -n "$SSH_IDENTITY" ]]; then
    SSH_OPTIONS+=(-o IdentitiesOnly=yes -i "$SSH_IDENTITY")
fi

usage() {
    cat <<EOF
usage: $0 --check-only | --supervised

  --check-only   Type-check and compile the probe, inspect prerequisites, and
                 test noninteractive localhost SSH readiness. Never uses the
                 signing private key or executes the probe, so it cannot
                 present LocalAuthentication UI.

  --supervised   Repeat the safe checks, sign the isolated probe with Apple
                 Development + hardened
                 runtime, run the interactive approval leg, then run the same
                 binary through non-TTY localhost SSH. A human must watch the
                 screen and answer the observation questions.
EOF
}

run() {
    echo "+ $*"
    "$@"
}

require_tool() {
    if [[ ! -x "$1" ]]; then
        echo "FAIL: required tool is missing or not executable: $1" >&2
        return 1
    fi
}

lower() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

is_yes() {
    case "$(lower "$1")" in
        y | yes) return 0 ;;
        *) return 1 ;;
    esac
}

check_ssh() {
    echo
    echo "== noninteractive localhost SSH prerequisite =="
    if ssh "${SSH_OPTIONS[@]}" localhost true </dev/null; then
        echo "PASS: BatchMode localhost SSH is ready."
        return 0
    fi
    cat <<'EOF' >&2
NOT READY: noninteractive localhost SSH failed. No LocalAuthentication code ran.

Before the supervised session:
  1. Enable Remote Login in System Settings > General > Sharing.
  2. If you have no suitable localhost key, create a dedicated one and install it:
       ssh-keygen -t ed25519 -f "$HOME/.ssh/kpexec-localhost-test" -N ''
       ssh-copy-id -i "$HOME/.ssh/kpexec-localhost-test.pub" localhost
  3. Re-run this harness with its absolute path:
       KPEXEC_LA_SSH_IDENTITY="$HOME/.ssh/kpexec-localhost-test" \
         ./run-tests.sh --check-only

The supervised harness deliberately uses BatchMode and no pseudo-terminal so an SSH
password or host-key question cannot be confused with LocalAuthentication behavior.
EOF
    return 1
}

safe_checks() {
    echo "== kpexec LocalAuthentication prerequisites =="
    echo "identity:   $IDENTITY"
    echo "identifier: $IDENTIFIER"
    echo "team id:    $TEAM_ID"
    echo "probe:       $BIN"
    echo "evidence:    $BUILD_DIR"
    echo "ssh key:     ${SSH_IDENTITY:-default SSH selection}"
    echo

    require_tool /usr/bin/swiftc
    require_tool /usr/bin/codesign
    require_tool /usr/bin/security
    require_tool /usr/bin/ssh
    require_tool /usr/bin/otool
    require_tool /usr/bin/nm
    if [[ -n "$SSH_IDENTITY" && ! -f "$SSH_IDENTITY" ]]; then
        echo "FAIL: KPEXEC_LA_SSH_IDENTITY is not a regular file: $SSH_IDENTITY" >&2
        return 1
    fi
    mkdir -p "$BUILD_DIR"

    echo "== OS and toolchain =="
    run /usr/bin/sw_vers
    run /usr/bin/uname -mprsv
    run /usr/bin/swiftc --version

    echo
    echo "== console GUI session =="
    console_user="$(/usr/bin/stat -f '%Su' /dev/console)"
    current_user="$(/usr/bin/id -un)"
    if [[ "$console_user" != "$current_user" ]]; then
        echo "FAIL: current user '$current_user' does not own /dev/console ('$console_user')." >&2
        return 1
    fi
    if ! /bin/launchctl print "gui/$(/usr/bin/id -u)" >/dev/null 2>&1; then
        echo "FAIL: no Aqua launchd session exists for uid $(/usr/bin/id -u)." >&2
        return 1
    fi
    echo "PASS: current user owns the console and has an Aqua launchd session."

    echo
    echo "== Swift reference type-check (no LocalAuthentication execution) =="
    run /usr/bin/swiftc -typecheck \
        -framework LocalAuthentication -framework Security "$SRC"

    echo
    echo "== production Rust/Objective-C probe build + linkage =="
    run cargo build \
        --manifest-path "$REPO_ROOT/Cargo.toml" \
        --release --locked --bin kpexec --example user_presence_probe
    if [[ ! -x "$BIN" ]]; then
        echo "FAIL: production probe was not built at $BIN" >&2
        return 1
    fi
    linkage="$(/usr/bin/otool -L "$BIN")"
    printf '%s\n' "$linkage"
    grep -Fq '/LocalAuthentication.framework/' <<<"$linkage" || {
        echo "FAIL: production probe does not link LocalAuthentication.framework" >&2
        return 1
    }
    symbols="$(/usr/bin/nm -gU "$BIN")"
    grep -Fq '_kpexec_authorize_user_presence' <<<"$symbols" || {
        echo "FAIL: production probe does not contain the kpexec authorization shim" >&2
        return 1
    }
    echo "probe_sha256=$(/usr/bin/shasum -a 256 "$BIN" | awk '{print $1}')"
    echo "PASS: production authorization path is linked into the release probe."

    if [[ ! -x "$RELEASE_BIN" ]]; then
        echo "FAIL: release kpexec binary was not built at $RELEASE_BIN" >&2
        return 1
    fi
    release_linkage="$(/usr/bin/otool -L "$RELEASE_BIN")"
    grep -Fq '/LocalAuthentication.framework/' <<<"$release_linkage" || {
        echo "FAIL: release kpexec does not link LocalAuthentication.framework" >&2
        return 1
    }
    release_symbols="$(/usr/bin/nm -gU "$RELEASE_BIN")"
    grep -Fq '_kpexec_authorize_user_presence' <<<"$release_symbols" || {
        echo "FAIL: release kpexec does not contain the authorization shim" >&2
        return 1
    }
    echo "release_sha256=$(/usr/bin/shasum -a 256 "$RELEASE_BIN" | awk '{print $1}')"
    echo "PASS: the same production authorization path is linked into release kpexec."

    echo
    echo "== signing identity presence (read-only) =="
    identity_output="$(/usr/bin/security find-identity -v -p codesigning)"
    printf '%s\n' "$identity_output"
    if ! grep -Fq "$IDENTITY" <<<"$identity_output"; then
        echo "FAIL: required Apple Development identity is not available." >&2
        return 1
    fi
    echo "PASS: required Apple Development identity is listed."

    check_ssh
}

sign_and_verify() {
    echo
    echo "== isolated Apple Development sign + strict verification =="
    echo ">>> This step uses the signing private key and may require Keychain approval."
    run /usr/bin/codesign --force --timestamp=none --options runtime \
        --identifier "$IDENTIFIER" --sign "$IDENTITY" "$BIN"
    run /usr/bin/codesign --verify --strict --verbose=2 \
        -R="$DEVELOPMENT_REQUIREMENT" "$BIN"
    signature="$(/usr/bin/codesign --display --verbose=4 "$BIN" 2>&1)"
    grep -Fq "Identifier=$IDENTIFIER" <<<"$signature"
    grep -Fq "TeamIdentifier=$TEAM_ID" <<<"$signature"
    grep -Eq '^CodeDirectory .* flags=.*\(runtime\)' <<<"$signature"
    if /usr/bin/codesign --verify --strict \
        -R="$PRODUCTION_REQUIREMENT" "$BIN" >/dev/null 2>&1; then
        echo "FAIL: LocalAuthentication probe satisfies the production requirement" >&2
        return 1
    fi
    echo "PASS: LocalAuthentication probe cannot satisfy the production Developer ID requirement."
}

record_results() {
    local interactive_rc="$1"
    local interactive_sheet="$2"
    local interactive_method="$3"
    local ssh_rc="$4"
    local ssh_sheet="$5"
    local overall="$6"
    {
        echo "kpexec LocalAuthentication supervised result"
        echo "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "operator=${USER:-unknown}"
        echo "macos=$(/usr/bin/sw_vers -productVersion) ($(/usr/bin/sw_vers -buildVersion))"
        echo "architecture=$(/usr/bin/uname -m)"
        echo "kernel=$(/usr/bin/uname -r)"
        echo "identity=$IDENTITY"
        echo "identifier=$IDENTIFIER"
        echo "team_id=$TEAM_ID"
        echo "ssh_identity=${SSH_IDENTITY:-default SSH selection}"
        echo "git_commit=$(git -C "$REPO_ROOT" rev-parse HEAD)"
        echo "probe_sha256=$(/usr/bin/shasum -a 256 "$BIN" | awk '{print $1}')"
        echo "interactive_exit=$interactive_rc"
        echo "interactive_sheet=$interactive_sheet"
        echo "interactive_method=$interactive_method"
        echo "ssh_exit=$ssh_rc"
        echo "ssh_sheet=$ssh_sheet"
        echo "overall=$overall"
        echo "interactive_log=$INTERACTIVE_LOG"
        echo "ssh_log=$SSH_LOG"
    } >"$RESULTS"
    echo ">>> Evidence summary written to $RESULTS"
}

supervised_run() {
    if [[ ! -t 0 ]]; then
        echo "FAIL: --supervised requires an interactive terminal and human observer." >&2
        exit 20
    fi

    safe_checks
    sign_and_verify

    echo
    echo "======================================================================"
    echo "INTERACTIVE LEG"
    echo "A Touch ID / account-password sheet should appear with reason:"
    echo "  kpexec: approve production user-presence validation"
    echo "Approve it. Keep watching the console screen throughout the SSH leg."
    read -r -p ">>> Press Enter when ready to present the authentication sheet... " _
    echo "======================================================================"

    set +e
    "$BIN" 2>&1 | tee "$INTERACTIVE_LOG"
    interactive_rc=${PIPESTATUS[0]}
    set -e
    read -r -p ">>> Did a LocalAuthentication sheet appear? [y/N] " interactive_sheet
    read -r -p ">>> Method observed (touch-id/account-password/other): " interactive_method

    echo
    echo "======================================================================"
    echo "SSH LEG"
    echo "The exact same signed binary will run through BatchMode localhost SSH"
    echo "without a pseudo-terminal. Do not approve or deny anything. Watch for"
    echo "any GUI sheet; the required result is no sheet and exit code 2."
    read -r -p ">>> Press Enter when ready and watching the console screen... " _
    echo "======================================================================"

    printf -v remote_command '%q' "$BIN"
    set +e
    # `printf %q` above deliberately produces one shell-safe absolute command
    # for ssh's remote shell; no untrusted fragment is concatenated here.
    # shellcheck disable=SC2029
    ssh "${SSH_OPTIONS[@]}" localhost "$remote_command" </dev/null 2>&1 | tee "$SSH_LOG"
    ssh_rc=${PIPESTATUS[0]}
    set -e
    read -r -p ">>> Did any LocalAuthentication GUI sheet appear during SSH? [y/N] " ssh_sheet

    interactive_pass=false
    if [[ "$interactive_rc" -eq 0 ]] && is_yes "$interactive_sheet"; then
        interactive_pass=true
    fi
    ssh_pass=false
    if [[ "$ssh_rc" -eq 2 ]] && ! is_yes "$ssh_sheet"; then
        ssh_pass=true
    fi

    overall=FAIL
    if [[ "$interactive_pass" == true && "$ssh_pass" == true ]]; then
        overall=PASS
    fi
    record_results \
        "$interactive_rc" "$interactive_sheet" "$interactive_method" \
        "$ssh_rc" "$ssh_sheet" "$overall"

    echo
    echo "== supervised verdict =="
    echo "interactive: rc=$interactive_rc sheet=$interactive_sheet pass=$interactive_pass"
    echo "ssh:         rc=$ssh_rc sheet=$ssh_sheet pass=$ssh_pass"
    echo "overall:     $overall"
    if [[ "$overall" != PASS ]]; then
        echo "FAIL: do not treat the LocalAuthentication platform assumption as validated." >&2
        return 1
    fi
}

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 10
fi

case "$1" in
    --check-only)
        safe_checks
        echo
        echo "PASS: non-prompting checks complete. No signing key was used and no probe ran."
        echo "Next, with a human watching the console, run:"
        echo "  $0 --supervised"
        ;;
    --supervised)
        supervised_run
        ;;
    -h | --help)
        usage
        ;;
    *)
        usage >&2
        exit 10
        ;;
esac
