#!/bin/bash
# Syncs bundled SigmaHQ rules from upstream. This script is manually invoked by
# developers and is never called by the app or build process.
set -euo pipefail

# Check that we're in the repo root
if [[ ! -d "Resources/Rules/imported" ]]; then
    echo "Error: Resources/Rules/imported not found. Run this script from the repo root." >&2
    exit 1
fi

# Create and trap cleanup of temp directory
TMPDIR=$(mktemp -d)
trap "rm -rf '$TMPDIR'" EXIT

echo "==> Cloning SigmaHQ/sigma (shallow, depth 1)..."
git clone --depth 1 https://github.com/SigmaHQ/sigma "$TMPDIR/sigma"

updated=0
unchanged=0
missing_upstream=0

echo "==> Syncing imported (macos/process_creation)..."
for file in Resources/Rules/imported/*.yml; do
    filename=$(basename "$file")
    upstream_file="$TMPDIR/sigma/rules/macos/process_creation/$filename"

    if [[ -f "$upstream_file" ]]; then
        if ! cmp -s "$file" "$upstream_file"; then
            cp "$upstream_file" "$file"
            ((updated++))
        else
            ((unchanged++))
        fi
    else
        echo "Warning: $filename no longer exists upstream (not removed locally)" >&2
        ((missing_upstream++))
    fi
done

echo "==> Syncing imported-portable (linux/process_creation)..."
for file in Resources/Rules/imported-portable/*.yml; do
    filename=$(basename "$file")
    upstream_file="$TMPDIR/sigma/rules/linux/process_creation/$filename"

    if [[ -f "$upstream_file" ]]; then
        if ! cmp -s "$file" "$upstream_file"; then
            cp "$upstream_file" "$file"
            ((updated++))
        else
            ((unchanged++))
        fi
    else
        echo "Warning: $filename no longer exists upstream (not removed locally)" >&2
        ((missing_upstream++))
    fi
done

echo ""
echo "==> Summary"
git diff --stat Resources/Rules
echo ""
echo "Updated: $updated, Unchanged: $unchanged, Missing upstream: $missing_upstream"
echo ""
echo "Note: BundledRulesTests asserts rule count and IDs."
echo "Run 'swift test' to verify bundled rules."
