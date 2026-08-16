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
SUPPORTED_TARGET="aarch64-apple-darwin"
MIN_MACOS_VERSION="11.0"
RELEASE_REQUIREMENT='identifier "dev.crazytan.kpexec" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "V82M9YX8BR"'

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
    COMMIT="$(release_value COMMIT "$RELEASE_ENV")"
    DIRTY="$(release_value DIRTY "$RELEASE_ENV")"
    MIN_MACOS="$(release_value MIN_MACOS "$RELEASE_ENV")"
    [[ "$VERSION" =~ ^[0-9A-Za-z._+-]+$ ]] || die "invalid VERSION in $RELEASE_ENV"
    [[ "$TARGET" =~ ^[0-9A-Za-z._-]+$ ]] || die "invalid TARGET in $RELEASE_ENV"
    [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "invalid COMMIT in $RELEASE_ENV"
    [[ "$DIRTY" == "0" || "$DIRTY" == "1" ]] || die "invalid DIRTY in $RELEASE_ENV"
    [[ "$MIN_MACOS" =~ ^[0-9]+\.[0-9]+$ ]] || die "invalid MIN_MACOS in $RELEASE_ENV"

    STAGED_BINARY="$RELEASE_DIR/stage/usr/local/bin/kpexec"
    PACKAGE="$RELEASE_DIR/kpexec-${VERSION}-${TARGET}.pkg"
    [[ -f "$STAGED_BINARY" ]] || die "missing staged binary: $STAGED_BINARY"
}

require_shippable_manifest() {
    [[ "$DIRTY" == "0" ]] ||
        die "refusing a credentialed stage for a dirty rehearsal artifact"
    [[ "$TARGET" == "$SUPPORTED_TARGET" ]] ||
        die "unsupported release target: $TARGET (expected $SUPPORTED_TARGET)"
    [[ "$MIN_MACOS" == "$MIN_MACOS_VERSION" ]] ||
        die "unsupported minimum macOS version: $MIN_MACOS (expected $MIN_MACOS_VERSION)"
}

verify_unsigned_binary_checksum() {
    local checksum_file="$RELEASE_DIR/SHA256SUMS.unsigned"
    local expected actual

    [[ -f "$checksum_file" ]] || die "missing unsigned checksum: $checksum_file"
    expected="$(awk '$2 == "stage/usr/local/bin/kpexec" { print $1; count++ } END { if (count != 1) exit 1 }' "$checksum_file")" ||
        die "unsigned checksum must contain exactly stage/usr/local/bin/kpexec"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "invalid unsigned binary checksum"
    actual="$(shasum -a 256 "$STAGED_BINARY" | awk '{ print $1 }')"
    [[ "$actual" == "$expected" ]] ||
        die "staged binary changed after prepare; discard this release directory"
}

verify_source_binding() {
    local current_commit current_version rebuild_dir rebuilt_binary

    [[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]] ||
        die "working tree changed after prepare; sign only from the reviewed clean commit"
    current_commit="$(git -C "$ROOT" rev-parse HEAD)"
    [[ "$current_commit" == "$COMMIT" ]] ||
        die "release manifest commit is $COMMIT, but the checkout is $current_commit"
    current_version="$(awk -F '"' '/^version = "/ { print $2; exit }' "$ROOT/Cargo.toml")"
    [[ "$current_version" == "$VERSION" ]] ||
        die "release manifest version is $VERSION, but Cargo.toml is $current_version"

    # Rebuild into a fresh target directory so a reviewed source commit, rather
    # than mutable staging metadata alone, determines the bytes being signed.
    rebuild_dir="$(mktemp -d -t kpexec-release-rebuild)"
    (
        trap 'rm -rf -- "$rebuild_dir"' EXIT
        run env CARGO_TARGET_DIR="$rebuild_dir" \
            MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS" \
            cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked --target "$TARGET"
        rebuilt_binary="$rebuild_dir/$TARGET/release/kpexec"
        [[ -x "$rebuilt_binary" ]] || die "source-bound rebuild did not produce kpexec"
        cmp -s "$rebuilt_binary" "$STAGED_BINARY" ||
            die "staged binary does not match a clean rebuild of commit $COMMIT"
    )
}

require_identity() {
    local identity="$1"
    security find-identity -v -p basic 2>/dev/null |
        grep -F -- "\"$identity\"" >/dev/null ||
        die "required signing identity is missing or unusable: $identity"
}

verify_binary_platform() {
    local binary="$1"
    local target="$2"
    local minimum_version="$3"
    local expected_arch actual_arch actual_minimum

    case "$target" in
        aarch64-apple-darwin) expected_arch="arm64" ;;
        *) die "cannot verify unsupported release target: $target" ;;
    esac

    actual_arch="$(lipo -archs "$binary")"
    [[ "$actual_arch" == "$expected_arch" ]] ||
        die "binary architecture is $actual_arch, expected $expected_arch"
    actual_minimum="$(otool -l "$binary" | awk '$1 == "minos" { print $2; exit }')"
    [[ "$actual_minimum" == "$minimum_version" ]] ||
        die "binary minimum macOS is $actual_minimum, expected $minimum_version"
}

verify_binary_signature() {
    local binary="$1"
    local details

    run codesign --verify --strict --verbose=2 -R="$RELEASE_REQUIREMENT" "$binary"
    verify_binary_platform "$binary" "$TARGET" "$MIN_MACOS"
    details="$(codesign --display --verbose=4 "$binary" 2>&1)"
    printf '%s\n' "$details"

    [[ "$details" == *"Identifier=$IDENTIFIER"* ]] ||
        die "binary signature identifier is not $IDENTIFIER"
    [[ "$details" == *"TeamIdentifier=$DEFAULT_TEAM_ID"* ]] ||
        die "binary signature Team ID is not $DEFAULT_TEAM_ID"
    grep -Eq '^CodeDirectory .* flags=.*\(runtime\)' <<<"$details" ||
        die "binary signature does not enable hardened runtime"
    grep -Eq '^Timestamp=' <<<"$details" ||
        die "binary signature has no secure timestamp"
}

verify_installer_signature_details() {
    local details="$1"
    local leaf_lines leaf certificate_name
    local leaf_prefix="Developer ID Installer: "
    local leaf_suffix=" ($DEFAULT_TEAM_ID)"

    # `pkgutil` validates the cryptographic chain. Parse exactly one numbered
    # leaf certificate rather than broadly searching all output, where a path
    # or unrelated certificate could contain the expected Team ID.
    leaf_lines="$(awk '
        /^[[:space:]]*Certificate Chain:[[:space:]]*$/ { in_chain = 1; next }
        in_chain && /^[[:space:]]*1\.[[:space:]]+/ {
            line = $0
            sub(/^[[:space:]]*1\.[[:space:]]+/, "", line)
            print line
        }
    ' <<<"$details")"
    [[ -n "$leaf_lines" && "$leaf_lines" != *$'\n'* ]] ||
        die "package signature output does not contain exactly one leaf certificate"
    leaf="$leaf_lines"
    [[ "$leaf" == "$leaf_prefix"*"$leaf_suffix" ]] ||
        die "package leaf is not a Developer ID Installer certificate for $DEFAULT_TEAM_ID"
    certificate_name="${leaf#"$leaf_prefix"}"
    certificate_name="${certificate_name%"$leaf_suffix"}"
    [[ -n "${certificate_name//[[:space:]]/}" ]] ||
        die "package Developer ID Installer certificate has an empty display name"
}

verify_package_contents() (
    local package="$1"
    local expected_version="$2"
    local verify_embedded_signature="${3:-1}"
    local inspect_dir expanded payload_root package_info actual_version actual_entries
    local expected_entries top_entries expected_top_entries bom_details
    inspect_dir="$(mktemp -d -t kpexec-release-inspect)"
    trap 'rm -rf -- "$inspect_dir"' EXIT
    expanded="$inspect_dir/expanded"
    payload_root="$inspect_dir/root"

    run pkgutil --expand "$package" "$expanded"
    top_entries="$(cd "$expanded" && find . -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort)"
    expected_top_entries=$'./Bom\n./PackageInfo\n./Payload'
    [[ "$top_entries" == "$expected_top_entries" ]] ||
        die "package contains installer scripts, components, or unexpected top-level members"

    package_info="$expanded/PackageInfo"
    [[ "$(xmllint --xpath 'string(/pkg-info/@identifier)' "$package_info")" == "$PACKAGE_IDENTIFIER" ]] ||
        die "package identifier is not $PACKAGE_IDENTIFIER"
    actual_version="$(xmllint --xpath 'string(/pkg-info/@version)' "$package_info")"
    [[ "$actual_version" =~ ^[0-9A-Za-z._+-]+$ ]] || die "package has an invalid version"
    if [[ -n "$expected_version" && "$actual_version" != "$expected_version" ]]; then
        die "package version is $actual_version, expected $expected_version"
    fi
    [[ "$(xmllint --xpath 'string(/pkg-info/@install-location)' "$package_info")" == "/" ]] ||
        die "package install location is not /"
    [[ "$(xmllint --xpath 'string(/pkg-info/@auth)' "$package_info")" == "root" ]] ||
        die "package does not require root installation"
    [[ "$(xmllint --xpath 'count(/pkg-info/scripts)' "$package_info")" == "0" ]] ||
        die "package declares installer scripts"

    run mkdir "$payload_root"
    run ditto -x "$expanded/Payload" "$payload_root"
    actual_entries="$(cd "$payload_root" && find . -mindepth 1 -print | LC_ALL=C sort)"
    expected_entries=$'./usr\n./usr/local\n./usr/local/bin\n./usr/local/bin/kpexec\n./usr/local/share\n./usr/local/share/doc\n./usr/local/share/doc/kpexec\n./usr/local/share/doc/kpexec/LICENSE\n./usr/local/share/doc/kpexec/README.md'
    [[ "$actual_entries" == "$expected_entries" ]] ||
        die "package payload contains unexpected or missing paths"

    bom_details="$(lsbom -p fMUG "$expanded/Bom")"
    grep -Eq '^\./usr/local/bin/kpexec[[:space:]]+-rwxr-xr-x[[:space:]]+root[[:space:]]+wheel$' <<<"$bom_details" ||
        die "package binary ownership or mode is not root:wheel 0755"
    grep -Eq '^\./usr/local/share/doc/kpexec/LICENSE[[:space:]]+-rw-r--r--[[:space:]]+root[[:space:]]+wheel$' <<<"$bom_details" ||
        die "package license ownership or mode is not root:wheel 0644"
    grep -Eq '^\./usr/local/share/doc/kpexec/README.md[[:space:]]+-rw-r--r--[[:space:]]+root[[:space:]]+wheel$' <<<"$bom_details" ||
        die "package README ownership or mode is not root:wheel 0644"

    if [[ "$verify_embedded_signature" == "1" ]]; then
        verify_binary_signature "$payload_root/usr/local/bin/kpexec"
    fi
)

verify_package_signature() {
    local package="$1"
    local expected_version="$2"
    local details

    # Copy to a fixed generated path before requesting human-readable output.
    # A malicious filename (including embedded newlines) therefore cannot
    # masquerade as a certificate-chain line in the parser.
    details="$({
        local signature_dir fixed_package
        signature_dir="$(mktemp -d -t kpexec-release-signature)"
        trap 'rm -rf -- "$signature_dir"' EXIT
        fixed_package="$signature_dir/release.pkg"
        ditto "$package" "$fixed_package"
        pkgutil --check-signature "$fixed_package" 2>&1
    })"
    printf '%s\n' "$details"
    verify_installer_signature_details "$details"
    verify_package_contents "$package" "$expected_version"
}

preflight() {
    local command_name
    require_macos
    for command_name in cargo rustc git shasum codesign ditto lipo lsbom otool pkgbuild pkgutil spctl xmllint xcrun; do
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
    [[ "$target" == "$SUPPORTED_TARGET" ]] ||
        die "MVP releases support $SUPPORTED_TARGET only; current Rust host is $target"

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
    run env MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS_VERSION" \
        cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked --target "$target"
    local built_binary="$ROOT/target/$target/release/kpexec"
    [[ -x "$built_binary" ]] || die "release binary was not produced: $built_binary"
    verify_binary_platform "$built_binary" "$target" "$MIN_MACOS_VERSION"

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
        printf 'MIN_MACOS=%s\n' "$MIN_MACOS_VERSION"
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
    for command_name in cargo cmp codesign ditto git lipo lsbom mktemp otool pkgbuild pkgutil security shasum xmllint; do
        require_cmd "$command_name"
    done
    release_paths "$1"
    require_shippable_manifest
    verify_unsigned_binary_checksum
    verify_source_binding

    local application_identity installer_identity
    application_identity="${KPEXEC_APPLICATION_IDENTITY:-Developer ID Application: Jia Tan ($DEFAULT_TEAM_ID)}"
    installer_identity="${KPEXEC_INSTALLER_IDENTITY:-Developer ID Installer: Jia Tan ($DEFAULT_TEAM_ID)}"
    [[ "$application_identity" == "Developer ID Application:"*"($DEFAULT_TEAM_ID)" ]] ||
        die "application identity must be a Developer ID Application identity for $DEFAULT_TEAM_ID"
    [[ "$installer_identity" == "Developer ID Installer:"*"($DEFAULT_TEAM_ID)" ]] ||
        die "installer identity must be a Developer ID Installer identity for $DEFAULT_TEAM_ID"
    [[ ! -e "$PACKAGE" ]] || die "package already exists: $PACKAGE"

    echo "This stage uses the Developer ID identities in the login keychain."
    echo "Application identity: $application_identity"
    echo "Installer identity:   $installer_identity"
    echo

    # Check both identities before mutating the staged binary. In particular,
    # avoid leaving a half-completed staging tree when the Installer identity
    # has not yet been provisioned.
    require_identity "$application_identity"
    require_identity "$installer_identity"

    run codesign --force --timestamp --options runtime \
        --identifier "$IDENTIFIER" \
        --sign "$application_identity" \
        "$STAGED_BINARY"
    verify_binary_signature "$STAGED_BINARY"

    run pkgbuild \
        --root "$RELEASE_DIR/stage" \
        --install-location / \
        --identifier "$PACKAGE_IDENTIFIER" \
        --version "$VERSION" \
        --ownership recommended \
        --sign "$installer_identity" \
        "$PACKAGE"
    verify_package_signature "$PACKAGE" "$VERSION"

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
    [[ $# -eq 1 ]] || die "usage: $0 verify <release-directory-or-package>"
    require_macos
    local command_name
    for command_name in codesign ditto lipo lsbom otool pkgutil spctl xmllint xcrun; do
        require_cmd "$command_name"
    done
    if [[ -f "$1" ]]; then
        PACKAGE="$(absolute_path "$1")"
        VERSION=""
        TARGET="$SUPPORTED_TARGET"
        MIN_MACOS="$MIN_MACOS_VERSION"
    else
        release_paths "$1"
        require_shippable_manifest
        [[ -f "$PACKAGE" ]] || die "missing package: $PACKAGE"
    fi

    verify_package_signature "$PACKAGE" "$VERSION"
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
    require_shippable_manifest
    [[ -f "$PACKAGE" ]] || die "missing package: $PACKAGE"

    local profile="${KPEXEC_NOTARY_PROFILE:-kpexec-notary}"
    xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1 ||
        die "notarytool profile is missing or unreadable: $profile"

    run xcrun notarytool submit "$PACKAGE" --keychain-profile "$profile" --wait
    run xcrun stapler staple "$PACKAGE"
    verify_release "$RELEASE_DIR"

    (
        cd "$RELEASE_DIR"
        shasum -a 256 "$(basename "$PACKAGE")" >SHA256SUMS
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
  verify <release-dir-or-pkg>       Verify signatures, ticket, payload, and Gatekeeper

See docs/release.md for identity/profile environment variables and the manual gates.
EOF
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

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
