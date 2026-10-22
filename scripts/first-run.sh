#!/bin/bash
# Works in the release app's Contents/Resources and in a source checkout.
# The backend contains every mutation; this file selects a supported runtime.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
RESOURCE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
if [ ! -f "$RESOURCE_ROOT/src/surge_cc/onboarding.py" ]; then
    printf '%s\n' 'Surge CC setup backend is missing. Reinstall the complete app.' >&2
    exit 78
fi
PYTHON_CANDIDATES=(
    /opt/homebrew/bin/python3
    /usr/local/bin/python3
    /usr/bin/python3
    /Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/Current/bin/python3
    /Library/Developer/CommandLineTools/usr/bin/python3
)
for candidate in "${PYTHON_CANDIDATES[@]}"; do
    if [ -x "$candidate" ] && "$candidate" -I -B -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' </dev/null >/dev/null 2>&1; then
        exec "$candidate" -I -B -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from surge_cc.onboarding import main; raise SystemExit(main())' "$RESOURCE_ROOT/src" "$@"
    fi
done
printf '%s\n' 'Python 3.9+ is required. Install Python first, then run this script again.' >&2
exit 78
