#!/bin/bash
# Package the original artwork into standard macOS icon representations.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTWORK="$PROJECT_ROOT/app/assets/SurgeCCIcon.png"
ICONSET="$PROJECT_ROOT/build/SurgeCCIcon.iconset"
OUTPUT="$PROJECT_ROOT/app/assets/SurgeCCIcon.icns"

if [ ! -s "$ARTWORK" ]; then
    echo "Missing icon artwork: $ARTWORK" >&2
    exit 1
fi

mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
    /usr/bin/sips -z "$size" "$size" "$ARTWORK" \
        --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    retina=$((size * 2))
    /usr/bin/sips -z "$retina" "$retina" "$ARTWORK" \
        --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done

/usr/bin/iconutil --convert icns --output "$OUTPUT" "$ICONSET"
echo "Built: $OUTPUT"
