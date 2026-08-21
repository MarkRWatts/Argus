#!/bin/bash
# Builds Argus in release mode and assembles build/Argus.app, a real
# double-clickable macOS app bundle (icon, Info.plist, ad-hoc code signature).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> swift build -c release"
swift build -c release

APP="build/Argus.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp .build/release/Argus "$APP/Contents/MacOS/Argus"
cp Resources/Info.plist "$APP/Contents/Info.plist"

echo "==> bundling detection rules"
mkdir -p "$APP/Contents/Resources/Rules"
cp -R Resources/Rules/imported "$APP/Contents/Resources/Rules/imported"
cp -R Resources/Rules/imported-portable "$APP/Contents/Resources/Rules/imported-portable"
cp -R Resources/Rules/custom "$APP/Contents/Resources/Rules/custom"

echo "==> generating app icon"
ICONSET=$(mktemp -d)/AppIcon.iconset
mkdir -p "$ICONSET"
swift Resources/icon_gen.swift "$ICONSET/../icon_1024.png"
SRC="$ICONSET/../icon_1024.png"
sips -z 16 16     "$SRC" --out "$ICONSET/icon_16x16.png"      >/dev/null
sips -z 32 32     "$SRC" --out "$ICONSET/icon_16x16@2x.png"   >/dev/null
sips -z 32 32     "$SRC" --out "$ICONSET/icon_32x32.png"      >/dev/null
sips -z 64 64     "$SRC" --out "$ICONSET/icon_32x32@2x.png"   >/dev/null
sips -z 128 128   "$SRC" --out "$ICONSET/icon_128x128.png"    >/dev/null
sips -z 256 256   "$SRC" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256   "$SRC" --out "$ICONSET/icon_256x256.png"    >/dev/null
sips -z 512 512   "$SRC" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
sips -z 512 512   "$SRC" --out "$ICONSET/icon_512x512.png"    >/dev/null
cp "$SRC" "$ICONSET/icon_512x512@2x.png"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

# Sign with a stable identity when one is available. An ad-hoc signature
# (-s -) changes on every rebuild, which resets the app's identity as far as
# the Keychain is concerned — macOS then re-prompts for access to the
# IntegrityGuard key after each rebuild. A real signing identity (an Apple
# Development certificate, or any codesigning cert) keeps the designated
# requirement stable across rebuilds, so the Keychain ACL keeps matching and
# the prompt never comes back. Resolution order:
#   1. $ARGUS_SIGN_IDENTITY, if set (name or SHA-1 of a keychain identity)
#   2. the first valid codesigning identity in the keychain
#   3. ad-hoc (-s -) — the CI runner has no identities and lands here
IDENTITY="${ARGUS_SIGN_IDENTITY:-}"
if [ -z "$IDENTITY" ]; then
  IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null \
    | awk -F'"' '/^ *[0-9]+\)/ { print $2; exit }')
fi
if [ -n "$IDENTITY" ]; then
  echo "==> code signing as: $IDENTITY"
  codesign --force --deep -s "$IDENTITY" "$APP"
else
  echo "==> ad-hoc code signing (no signing identity found)"
  codesign --force --deep -s - "$APP"
fi

echo "==> done: $APP"
echo "    open $APP"
