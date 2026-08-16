#!/usr/bin/env bash
# Build, sign, package, notarize, and verify a macOS kpexec release.
#
# `prepare` and `preflight` never use signing or notarization credentials.
# The credentialed stages are separate and require an explicit user invocation;
# notarization additionally requires KPEXEC_SUBMIT=1.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IDENTIFIER="dev.crazytan.kpexec"
PACKAGE_IDENTIFIER="dev.crazytan.kpexec.pkg"
DEFAULT_TEAM_ID="V82M9YX8BR"

die() {
    echo "release: $*" >&2
    exit 1
}

run() {
    echo "+ $*"
    "$@"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_macos() {
    [[ "$(uname -s)" == "Darwin" ]] || die "release artifacts must be built on macOS"
}

absolute_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$PWD" "$1" ;;
    esac
}

release_value() {
    local key="$1"
    local env_file="$2"
    awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$env_file"
}

release_paths() {
    RELEASE_DIR="$(absolute_path "$1")"
    RELEASE_ENV="$RELEASE_DIR/RELEASE.env"
    [[ -f "$RELEASE_ENV" ]] || die "missing release manifest: $RELEASE_ENV"

    VERSION="$(release_value VERSION "$RELEASE_ENV")"
    TARGET="$(release_value TARGET "$RELEASE_ENV")"
    [[ "$VERSION" =~ ^[0-9A-Za-z._+-]+$ ]] || die "invalid VERSION in $RELEASE_ENV"
    [[ "$TARGET" =~ ^[0-9A-Za-z._-]+$ ]] || die "invalid TARGET in $RELEASE_ENV"

    STAGED_BINARY="$RELEASE_DIR/stage/usr/local/bin/kpexec"
    PACKAGE="$RELEASE_DIR/kpexec-${VERSION}-${TARGET}.pkg"
    [[ -f "$STAGED_BINARY" ]] || die "missing staged binary: $STAGED_BINARY"
}

verify_binary_signature() {
    local binary="$1"
    local expected_team_id="$2"
    local details

    run codesign --verify --strict --verbose=2 "$binary"
    details="$(codesign --display --verbose=4 "$binary" 2>&1)"
    printf '%s\n' "$details"

    [[ "$details" == *"Identifier=$IDENTIFIER"* ]] ||
        die "binary signature identifier is not $IDENTIFIER"
    [[ "$details" == *"TeamIdentifier=$expected_team_id"* ]] ||
        die "binary signature Team ID is not $expected_team_id"
    [[ "$details" == *"runtime"* ]] ||
        die "binary signature does not enable hardened runtime"
    [[ "$details" == *"Timestamp="* ]] ||
        die "binary signature has no secure timestamp"
}

verify_package_signature() {
    local package="$1"
    local expected_team_id="$2"
    local details
    local payload

    details="$(pkgutil --check-signature "$package" 2>&1)"
    printf '%s\n' "$details"
    [[ "$details" == *"Developer ID Installer"* ]] ||
        die "package does not have a Developer ID Installer signature"
    [[ "$details" == *"$expected_team_id"* ]] ||
        die "package signature Team ID is not $expected_team_id"

    payload="$(pkgutil --payload-files "$package")"
    printf '%s\n' "$payload" | grep -E '^\.?/?usr/local/bin/kpexec$' >/dev/null ||
        die "package payload does not contain usr/local/bin/kpexec"
    printf '%s\n' "$payload" | grep -E '^\.?/?usr/local/share/doc/kpexec/LICENSE$' >/dev/null ||
        die "package payload does not contain the license"
}

preflight() {
    local command_name
    require_macos
    for command_name in cargo rustc git shasum codesign pkgbuild pkgutil spctl xcrun; do
        require_cmd "$command_name"
    done

    echo "Release tools are available. No keychain identity or notary profile was accessed."
}

prepare() {
    [[ $# -eq 1 ]] || die "usage: $0 prepare <new-release-directory>"
    preflight

    local output_dir version target commit package_args rustc_verbose
    output_dir="$(absolute_path "$1")"
    [[ ! -e "$output_dir" ]] || die "release directory already exists: $output_dir"

    if [[ "${ALLOW_DIRTY:-0}" != "1" ]] &&
        [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]]; then
        die "working tree is dirty; commit changes first (or set ALLOW_DIRTY=1 for a non-release rehearsal)"
    fi

    version="$(awk -F '"' '/^version = "/ { print $2; exit }' "$ROOT/Cargo.toml")"
    rustc_verbose="$(rustc -vV)"
    target="$(awk '/^host: / { print $2; exit }' <<<"$rustc_verbose")"
    commit="$(git -C "$ROOT" rev-parse HEAD)"
    [[ -n "$version" && -n "$target" && -n "$commit" ]] || die "could not determine release metadata"

    echo "== local release gates =="
    run cargo fmt --manifest-path "$ROOT/Cargo.toml" --all -- --check
    run cargo clippy --manifest-path "$ROOT/Cargo.toml" --locked --all-targets --all-features -- -D warnings
    run cargo test --manifest-path "$ROOT/Cargo.toml" --release --locked --all-targets --all-features
    run env RUSTDOCFLAGS=-Dwarnings cargo doc --manifest-path "$ROOT/Cargo.toml" --locked --all-features --no-deps

    package_args=(package --manifest-path "$ROOT/Cargo.toml" --locked)
    if [[ "${ALLOW_DIRTY:-0}" == "1" ]]; then
        package_args+=(--allow-dirty)
    fi
    run cargo "${package_args[@]}"

    echo "== release build =="
    run cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked --target "$target"
    local built_binary="$ROOT/target/$target/release/kpexec"
    [[ -x "$built_binary" ]] || die "release binary was not produced: $built_binary"

    run mkdir -p "$output_dir/stage/usr/local/bin" "$output_dir/stage/usr/local/share/doc/kpexec"
    run chmod 0755 "$output_dir/stage" "$output_dir/stage/usr" \
        "$output_dir/stage/usr/local" "$output_dir/stage/usr/local/bin" \
        "$output_dir/stage/usr/local/share" "$output_dir/stage/usr/local/share/doc" \
        "$output_dir/stage/usr/local/share/doc/kpexec"
    run install -m 0755 "$built_binary" "$output_dir/stage/usr/local/bin/kpexec"
    run install -m 0644 "$ROOT/LICENSE" "$output_dir/stage/usr/local/share/doc/kpexec/LICENSE"
    run install -m 0644 "$ROOT/README.md" "$output_dir/stage/usr/local/share/doc/kpexec/README.md"
    run install -m 0644 "$ROOT/LICENSE" "$output_dir/LICENSE"
    run install -m 0644 "$ROOT/README.md" "$output_dir/README.md"

    {
        printf 'VERSION=%s\n' "$version"
        printf 'TARGET=%s\n' "$target"
        printf 'COMMIT=%s\n' "$commit"
        printf 'DIRTY=%s\n' "${ALLOW_DIRTY:-0}"
    } >"$output_dir/RELEASE.env"

    (
        cd "$output_dir"
        shasum -a 256 stage/usr/local/bin/kpexec >SHA256SUMS.unsigned
    )

    echo
    echo "Prepared unsigned release staging at $output_dir"
    echo "No signing or notarization credential was accessed. Review RELEASE.env and"
    echo "SHA256SUMS.unsigned before explicitly running the sign-package stage."
}

sign_package() {
    [[ $# -eq 1 ]] || die "usage: $0 sign-package <release-directory>"
    [[ "${KPEXEC_SIGN:-0}" == "1" ]] ||
        die "signing uses Developer ID credentials; rerun with KPEXEC_SIGN=1 after review"
    require_macos
    local command_name
    for command_name in codesign pkgbuild pkgutil shasum; do
        require_cmd "$command_name"
    done
    release_paths "$1"

    local expected_team_id application_identity installer_identity
    expected_team_id="${KPEXEC_EXPECTED_TEAM_ID:-$DEFAULT_TEAM_ID}"
    application_identity="${KPEXEC_APPLICATION_IDENTITY:-Developer ID Application: Jia Tan ($expected_team_id)}"
    installer_identity="${KPEXEC_INSTALLER_IDENTITY:-Developer ID Installer: Jia Tan ($expected_team_id)}"
    [[ ! -e "$PACKAGE" ]] || die "package already exists: $PACKAGE"

    echo "This stage uses the Developer ID identities in the login keychain."
    echo "Application identity: $application_identity"
    echo "Installer identity:   $installer_identity"
    echo

    run codesign --force --timestamp --options runtime \
        --identifier "$IDENTIFIER" \
        --sign "$application_identity" \
        "$STAGED_BINARY"
    verify_binary_signature "$STAGED_BINARY" "$expected_team_id"

    run pkgbuild \
        --root "$RELEASE_DIR/stage" \
        --install-location / \
        --identifier "$PACKAGE_IDENTIFIER" \
        --version "$VERSION" \
        --ownership recommended \
        --sign "$installer_identity" \
        "$PACKAGE"
    verify_package_signature "$PACKAGE" "$expected_team_id"

    (
        cd "$RELEASE_DIR"
        shasum -a 256 "stage/usr/local/bin/kpexec" "$(basename "$PACKAGE")" \
            >SHA256SUMS.pre-notarization
    )

    echo
    echo "Signed and packaged: $PACKAGE"
    echo "Next, review the signature output and explicitly run the notarize stage."
}

verify_release() {
    [[ $# -eq 1 ]] || die "usage: $0 verify <release-directory>"
    require_macos
    local command_name
    for command_name in codesign pkgutil spctl xcrun; do
        require_cmd "$command_name"
    done
    release_paths "$1"
    [[ -f "$PACKAGE" ]] || die "missing package: $PACKAGE"

    local expected_team_id="${KPEXEC_EXPECTED_TEAM_ID:-$DEFAULT_TEAM_ID}"
    verify_binary_signature "$STAGED_BINARY" "$expected_team_id"
    verify_package_signature "$PACKAGE" "$expected_team_id"
    run xcrun stapler validate "$PACKAGE"
    run spctl --assess --type install --verbose=4 "$PACKAGE"
    echo "Release signatures, notarization ticket, payload, and Gatekeeper assessment passed."
}

notarize() {
    [[ $# -eq 1 ]] || die "usage: $0 notarize <release-directory>"
    [[ "${KPEXEC_SUBMIT:-0}" == "1" ]] ||
        die "notarization submits to Apple; rerun with KPEXEC_SUBMIT=1 after review"
    require_macos
    local command_name
    for command_name in xcrun shasum; do
        require_cmd "$command_name"
    done
    release_paths "$1"
    [[ -f "$PACKAGE" ]] || die "missing package: $PACKAGE"

    local profile="${KPEXEC_NOTARY_PROFILE:-kpexec-notary}"
    xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1 ||
        die "notarytool profile is missing or unreadable: $profile"

    run xcrun notarytool submit "$PACKAGE" --keychain-profile "$profile" --wait
    run xcrun stapler staple "$PACKAGE"
    verify_release "$RELEASE_DIR"

    (
        cd "$RELEASE_DIR"
        shasum -a 256 "stage/usr/local/bin/kpexec" "$(basename "$PACKAGE")" >SHA256SUMS
    )
    echo "Final notarized package checksum: $RELEASE_DIR/SHA256SUMS"
}

usage() {
    cat <<EOF
usage: $0 <command> [argument]

Commands:
  preflight                         Check release tools; access no credentials
  prepare <new-release-directory>   Run local gates and stage an unsigned binary
  sign-package <release-directory>  Sign/package (needs KPEXEC_SIGN=1)
  notarize <release-directory>      Submit, staple, and verify (needs KPEXEC_SUBMIT=1)
  verify <release-directory>        Verify signatures, ticket, payload, and Gatekeeper

See docs/release.md for identity/profile environment variables and the manual gates.
EOF
}

command_name="${1:-}"
if [[ $# -gt 0 ]]; then
    shift
fi
case "$command_name" in
    preflight) [[ $# -eq 0 ]] || die "preflight takes no arguments"; preflight ;;
    prepare) prepare "$@" ;;
    sign-package) sign_package "$@" ;;
    notarize) notarize "$@" ;;
    verify) verify_release "$@" ;;
    help | --help | -h | "") usage ;;
    *) usage >&2; die "unknown command: $command_name" ;;
esac
