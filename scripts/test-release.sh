#!/usr/bin/env bash
# Credential-free regression tests for release package parsing and layout checks.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release.sh
source "$ROOT/scripts/release.sh"

fail() {
    echo "release-test: $*" >&2
    exit 1
}

expect_rejected() {
    local description="$1"
    shift
    if ("$@" >/dev/null 2>&1); then
        fail "$description was accepted"
    fi
}

test_dir="$(mktemp -d -t kpexec-release-tests)"
trap 'rm -rf -- "$test_dir"' EXIT

valid_signature_details=$'Package "release.pkg":\n   Status: signed by a certificate trusted by macOS\n   Certificate Chain:\n    1. Developer ID Installer: Example (V82M9YX8BR)\n    2. Developer ID Certification Authority\n    3. Apple Root CA'
verify_installer_signature_details "$valid_signature_details"

wrong_leaf_with_team_elsewhere=$'Package "V82M9YX8BR.pkg":\n   Status: signed by a certificate trusted by macOS\n   Certificate Chain:\n    1. Developer ID Installer: Example (WRONGTEAM1)\n    2. Developer ID Certification Authority\n    3. Apple Root CA'
expect_rejected "wrong-team Installer leaf" \
    verify_installer_signature_details "$wrong_leaf_with_team_elsewhere"

duplicate_leaf=$'Package "release.pkg":\n   Status: signed by a certificate trusted by macOS\n   Certificate Chain:\n    1. Developer ID Installer: Example (V82M9YX8BR)\n    1. Developer ID Installer: Example (V82M9YX8BR)\n    2. Developer ID Certification Authority'
expect_rejected "duplicate Installer leaf" \
    verify_installer_signature_details "$duplicate_leaf"

stage="$test_dir/stage"
mkdir -p "$stage/usr/local/bin" "$stage/usr/local/share/doc/kpexec"
install -m 0755 /usr/bin/true "$stage/usr/local/bin/kpexec"
printf 'test license\n' >"$stage/usr/local/share/doc/kpexec/LICENSE"
printf 'test readme\n' >"$stage/usr/local/share/doc/kpexec/README.md"
chmod 0644 "$stage/usr/local/share/doc/kpexec/LICENSE" \
    "$stage/usr/local/share/doc/kpexec/README.md"

benign_package="$test_dir/benign.pkg"
pkgbuild --root "$stage" \
    --install-location / \
    --identifier "$PACKAGE_IDENTIFIER" \
    --version 0.1.0 \
    --ownership recommended \
    "$benign_package" >/dev/null
verify_package_contents "$benign_package" 0.1.0 0

installer_scripts="$test_dir/installer-scripts"
mkdir "$installer_scripts"
printf '#!/bin/sh\nexit 0\n' >"$installer_scripts/preinstall"
chmod 0755 "$installer_scripts/preinstall"
scripted_package="$test_dir/scripted.pkg"
pkgbuild --root "$stage" \
    --scripts "$installer_scripts" \
    --install-location / \
    --identifier "$PACKAGE_IDENTIFIER" \
    --version 0.1.0 \
    --ownership recommended \
    "$scripted_package" >/dev/null
expect_rejected "package with installer Scripts archive" \
    verify_package_contents "$scripted_package" 0.1.0 0

# Also prove the PackageInfo declaration is independently rejected even if the
# Scripts archive is stripped from a malformed/repacked flat package.
scripted_expanded="$test_dir/scripted-expanded"
pkgutil --expand "$scripted_package" "$scripted_expanded"
mv "$scripted_expanded/Scripts" "$test_dir/removed-Scripts"
declared_only_package="$test_dir/scripts-declared-only.pkg"
pkgutil --flatten "$scripted_expanded" "$declared_only_package"
expect_rejected "PackageInfo scripts declaration" \
    verify_package_contents "$declared_only_package" 0.1.0 0

distribution_package="$test_dir/distribution.pkg"
productbuild --package "$benign_package" "$distribution_package" >/dev/null
expect_rejected "distribution package with top-level component" \
    verify_package_contents "$distribution_package" 0.1.0 0

echo "Release verifier parser and package-layout regression tests passed."
