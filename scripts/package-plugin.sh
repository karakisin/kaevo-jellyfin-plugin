#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${KAEVO_BUILD_DIR:-$PROJECT_ROOT/artifacts/build}"
PACKAGE_ROOT="${KAEVO_PACKAGE_ROOT:-$PROJECT_ROOT/artifacts/package}"
PLUGIN_DIR="$PACKAGE_ROOT/Kaevo"
ZIP_PATH="$PACKAGE_ROOT/Kaevo.Plugin.KaevoForJellyfin.zip"
PROJECT_FILE="$PROJECT_ROOT/src/Kaevo.Plugin.KaevoForJellyfin/Kaevo.Plugin.KaevoForJellyfin.csproj"
PLUGIN_VERSION="$(awk -F '[<>]' '/<Version>/{print $3; exit}' "$PROJECT_FILE")"

if [[ ! "$PLUGIN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Could not read a valid plugin version from $PROJECT_FILE." >&2
    exit 1
fi
if [[ -n "${KAEVO_RELEASE_TIMESTAMP:-}" ]]; then
    TIMESTAMP="$KAEVO_RELEASE_TIMESTAMP"
else
    RELEASE_EPOCH="$(git -C "$PROJECT_ROOT" show -s --format=%ct HEAD)"
    TIMESTAMP="$(python3 - "$RELEASE_EPOCH" <<'PY'
import datetime
import sys

print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
fi

test -f "$BUILD_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" || {
    echo "Build output is missing. Run scripts/build-plugin-docker.sh first." >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || {
    echo "Python 3 is required to create the deterministic Plugin archive." >&2
    exit 1
}

# Preserve previous artifacts. Use a fresh KAEVO_PACKAGE_ROOT for each candidate.
python3 "$SCRIPT_DIR/package-plugin-dependencies.py" "$BUILD_DIR" "$PLUGIN_DIR" "$ZIP_PATH" \
    --version "$PLUGIN_VERSION" --timestamp "$TIMESTAMP"

echo "Packaged directory: $PLUGIN_DIR"
echo "Packaged archive:   $ZIP_PATH"
