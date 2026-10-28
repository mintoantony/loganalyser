#!/usr/bin/env bash
# Build the Mac app and its two installers. Run on a Mac from the repository root:
#   bash packaging/build_mac.sh
# Makes:
#   dist/LogAnalyser.app
#   dist/LogAnalyser-<version>-macOS-Installer.pkg   a step-by-step installer wizard (checks, then installs)
#   dist/LogAnalyser-<version>-macOS-<arch>.dmg      the usual drag-to-Applications disk image
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=1.1.1
ARCH=$(uname -m)
APP=dist/LogAnalyser.app
[ -d .venv ] || python3 -m venv .venv
PY=.venv/bin/python
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -e ".[desktop,build]"

"$PY" packaging/make_icons.py
"$PY" -m PyInstaller packaging/loganalyser.spec --noconfirm --clean --distpath dist --workpath build

# Ad-hoc signature so the app runs. To share it without the first-run warning, sign with a
# Developer ID (codesign for the app, productsign for the .pkg) and notarise both.
codesign --force --deep --sign - "$APP"

# Retina-ready art: join the 1x and 2x pictures into one .tiff.
hidpi() { tiffutil -cathidpicheck "packaging/$1.png" "packaging/$1@2x.png" -out "$2"; }

# ------------------------------------------------------------------ installer wizard (.pkg)
WORK=build/pkg
rm -rf "$WORK"
mkdir -p "$WORK/root" "$WORK/resources"
ditto "$APP" "$WORK/root/LogAnalyser.app"
# Always install to /Applications, even if another copy of the app exists elsewhere on the Mac.
pkgbuild --analyze --root "$WORK/root" "$WORK/component.plist"
plutil -replace 0.BundleIsRelocatable -bool NO "$WORK/component.plist"
pkgbuild --root "$WORK/root" --component-plist "$WORK/component.plist" --install-location /Applications \
    --identifier com.loganalyser.desktop --version "$VERSION" "$WORK/LogAnalyser-component.pkg"
cp packaging/macos/welcome.html packaging/macos/conclusion.html "$WORK/resources/"
hidpi mac-pkg-background "$WORK/resources/background.tiff"
sed "s/@VERSION@/$VERSION/g" packaging/macos/Distribution.xml > "$WORK/Distribution.xml"
PKG="dist/LogAnalyser-${VERSION}-macOS-Installer.pkg"
rm -f "$PKG"
productbuild --distribution "$WORK/Distribution.xml" --resources "$WORK/resources" --package-path "$WORK" "$PKG"
echo "Installer: $PKG"

# ------------------------------------------------- disk image with a drag-to-Applications window
DMG="dist/LogAnalyser-${VERSION}-macOS-${ARCH}.dmg"
STAGE=$(mktemp -d)
RW="$(mktemp -u).dmg"
rm -f "$DMG"
ditto "$APP" "$STAGE/LogAnalyser.app"
ln -s /Applications "$STAGE/Applications"
mkdir "$STAGE/.background"
hidpi mac-dmg-background "$STAGE/.background/background.tiff"
hdiutil create -volname LogAnalyser -srcfolder "$STAGE" -ov -fs HFS+ -format UDRW "$RW" >/dev/null
MOUNT=$(hdiutil attach -readwrite -noverify -noautoopen "$RW" | awk -F'\t' '/\/Volumes\//{print $NF}')
VOLUME=$(basename "$MOUNT")
# Lay out the window: background picture, big icons, app on the left and Applications on the right
# (positions match the arrow in the picture). Needs Finder; if it is not available, for example on
# a build server without a desktop session, the disk image still works with Finder's default layout.
if ! osascript <<EOF
tell application "Finder"
    tell disk "$VOLUME"
        open
        set current view of container window to icon view
        set toolbar visible of container window to false
        set statusbar visible of container window to false
        set the bounds of container window to {200, 120, 860, 548}
        set viewOptions to the icon view options of container window
        set arrangement of viewOptions to not arranged
        set icon size of viewOptions to 112
        set text size of viewOptions to 13
        set background picture of viewOptions to file ".background:background.tiff"
        set position of item "LogAnalyser.app" of container window to {170, 190}
        set position of item "Applications" of container window to {490, 190}
        close
        open
        update without registering applications
        delay 2
        close
    end tell
end tell
EOF
then
    echo "Could not lay out the disk image window (Finder automation unavailable); it will use the default layout." >&2
fi
chmod -Rf go-w "$MOUNT" || true
sync
hdiutil detach "$MOUNT" -quiet || hdiutil detach "$MOUNT" -force
hdiutil convert "$RW" -format UDZO -imagekey zlib-level=9 -o "$DMG" >/dev/null
rm -f "$RW"
rm -rf "$STAGE"
echo "Disk image: $DMG"
