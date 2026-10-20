#!/bin/bash
# Build only; never installs, launches, or modifies Surge/user configuration.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="${SURGE_CC_DIST_DIR:-$PROJECT_ROOT/dist}"
APP_NAME="${SURGE_CC_APP_NAME-Surge CC.app}"
APP_NAME_PATTERN='^[A-Za-z0-9][A-Za-z0-9._ -]*\.app$'
ICON_FILE="$PROJECT_ROOT/app/assets/SurgeCCIcon.icns"

if [[ ! "$APP_NAME" =~ $APP_NAME_PATTERN ]] || [ "${#APP_NAME}" -gt 120 ]; then
    echo "SURGE_CC_APP_NAME must be a basename ending .app (letters, digits, spaces, dots, _ or -; maximum 120 characters)." >&2
    exit 1
fi
APP_DIR="$DIST_DIR/$APP_NAME"
if [ -e "$APP_DIR" ] || [ -L "$APP_DIR" ]; then
    echo "Refusing to replace existing output: $APP_DIR" >&2
    echo "Choose a new SURGE_CC_APP_NAME or SURGE_CC_DIST_DIR." >&2
    exit 1
fi
if ! command -v swiftc >/dev/null 2>&1; then
    echo "Missing Swift compiler. Install Apple's Command Line Tools first." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "Missing Python 3, required for safe no-overwrite publication." >&2
    exit 1
fi
if [ ! -f "$PROJECT_ROOT/scripts/surge-cc" ] || [ ! -d "$PROJECT_ROOT/src/surge_cc" ]; then
    echo "Backend is missing: scripts/surge-cc and src/surge_cc are required." >&2
    exit 1
fi
if [ ! -s "$ICON_FILE" ]; then
    echo "App icon is missing or empty: app/assets/SurgeCCIcon.icns is required." >&2
    exit 1
fi

mkdir -p "$DIST_DIR"
# Stage on the destination filesystem so publication is one atomic rename.
# Every invocation owns only this private temporary directory.
STAGE_ROOT="$(mktemp -d "$DIST_DIR/.surge-cc-build.XXXXXX")"
trap 'rm -rf "$STAGE_ROOT"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
STAGE_DIR="$STAGE_ROOT/$APP_NAME"
CACHE_DIR="$STAGE_ROOT/module-cache"
mkdir -p "$CACHE_DIR"
mkdir -p "$STAGE_DIR/Contents/MacOS" "$STAGE_DIR/Contents/Resources/scripts" \
    "$STAGE_DIR/Contents/Resources/src"

# Relative input also keeps Swift runtime source-location strings free of the
# builder's home directory; prefix maps alone cover debug/index data only.
cd "$PROJECT_ROOT"
swiftc -O -parse-as-library \
    -file-prefix-map "$PROJECT_ROOT=/SurgeCC" \
    -debug-prefix-map "$PROJECT_ROOT=/SurgeCC" \
    -file-compilation-dir /SurgeCC \
    -module-cache-path "$CACHE_DIR" \
    -target "$(uname -m)-apple-macos13.0" \
    app/main.swift \
    -o "$STAGE_DIR/Contents/MacOS/SurgeCC" \
    -framework SwiftUI -framework AppKit

cp "$PROJECT_ROOT/scripts/surge-cc" "$STAGE_DIR/Contents/Resources/scripts/surge-cc"
cp -R "$PROJECT_ROOT/src/surge_cc" "$STAGE_DIR/Contents/Resources/src/"
cp "$ICON_FILE" "$STAGE_DIR/Contents/Resources/SurgeCCIcon.icns"
chmod 755 "$STAGE_DIR/Contents/MacOS/SurgeCC" \
    "$STAGE_DIR/Contents/Resources/scripts/surge-cc"
find "$STAGE_DIR/Contents/Resources/src" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$STAGE_DIR/Contents/Resources/src" -name '*.pyc' -type f -delete
if [ -f "$PROJECT_ROOT/LICENSE" ]; then
    cp "$PROJECT_ROOT/LICENSE" "$STAGE_DIR/Contents/Resources/LICENSE"
fi

cat > "$STAGE_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>SurgeCC</string>
  <key>CFBundleIdentifier</key><string>local.surgecc.app</string>
  <key>CFBundleName</key><string>Surge CC</string>
  <key>CFBundleDisplayName</key><string>Surge CC</string>
  <key>CFBundleIconFile</key><string>SurgeCCIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.2.3</string>
  <key>CFBundleVersion</key><string>5</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST

plutil -lint "$STAGE_DIR/Contents/Info.plist"
codesign --force --sign - "$STAGE_DIR"
codesign --verify --strict "$STAGE_DIR"
python3 - "$STAGE_DIR" "$APP_DIR" <<'PY'
import ctypes
import os
import sys

# Unlike mv, renamex_np never nests the app inside a concurrently created
# directory. RENAME_EXCL atomically refuses any existing destination,
# including a dangling symlink. Unsupported filesystems fail closed.
libc = ctypes.CDLL(None, use_errno=True)
rename = getattr(libc, "renamex_np", None)
if rename is None:
    sys.exit("Safe app publication requires macOS renamex_np; output was not published.")
rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
rename.restype = ctypes.c_int
if rename(os.fsencode(sys.argv[1]), os.fsencode(sys.argv[2]), 0x00000004):
    error = ctypes.get_errno()
    sys.exit(f"Output was not published: {os.strerror(error)}: {sys.argv[2]}")
PY
echo "Built: $APP_DIR"
echo "Build only. The app was not installed or opened."
