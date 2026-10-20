#!/bin/bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/gui-tests"
mkdir -p "$BUILD_DIR" "$PROJECT_ROOT/build/module-cache"
python3 -B - "$PROJECT_ROOT" "$BUILD_DIR" <<'PY'
from pathlib import Path
import sys

root, build = map(Path, sys.argv[1:])
source = (root / "app/main.swift").read_text()
models = source.split("private enum Backend {", 1)[0]
tests = (root / "tests/gui-contract.swift").read_text()
(build / "GUIContractTests.swift").write_text(models + "\n" + tests)
PY
swiftc -parse-as-library -module-cache-path "$PROJECT_ROOT/build/module-cache" \
    "$BUILD_DIR/GUIContractTests.swift" -o "$BUILD_DIR/GUIContractTests" \
    -framework SwiftUI -framework AppKit
"$BUILD_DIR/GUIContractTests"
