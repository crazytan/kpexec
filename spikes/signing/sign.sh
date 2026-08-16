#!/usr/bin/env bash
# Direct Developer ID signing of arbitrary binaries is intentionally disabled.
# The former helper made a user's approval a signing oracle for mutable workspace
# code in kpexec's production trust domain. Supervised probes now use fixed Apple
# Development profiles. Production signing must go through scripts/release.sh
# after its clean-source preparation and verification gates.

set -euo pipefail

echo "REFUSED: direct Developer ID signing of arbitrary binaries is disabled." >&2
echo "Use the fixed Apple Development harnesses for supervised probes." >&2
echo "Use ../../scripts/release.sh for a reviewed production release artifact." >&2
exit 64
