#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/artifacts/build"
PACKAGE_ROOT="$PROJECT_ROOT/artifacts/package"
PLUGIN_DIR="$PACKAGE_ROOT/Kaevo"
ZIP_PATH="$PACKAGE_ROOT/Kaevo.Plugin.KaevoForJellyfin.zip"
if [[ -n "${KAEVO_RELEASE_TIMESTAMP:-}" ]]; then
    TIMESTAMP="$KAEVO_RELEASE_TIMESTAMP"
else
    RELEASE_EPOCH="$(git -C "$PROJECT_ROOT" show -s --format=%ct HEAD)"
    TIMESTAMP="$(date -u -r "$RELEASE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
fi

test -f "$BUILD_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" || {
    echo "Build output is missing. Run scripts/build-plugin-docker.sh first." >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || {
    echo "Python 3 is required to create the deterministic Plugin archive." >&2
    exit 1
}

rm -rf "$PLUGIN_DIR" "$ZIP_PATH"
mkdir -p "$PLUGIN_DIR"

cp "$BUILD_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" "$PLUGIN_DIR/"
cp "$BUILD_DIR/QRCoder.dll" "$PLUGIN_DIR/"

cat > "$PLUGIN_DIR/meta.json" <<EOF
{
  "category": "General",
  "changelog": "Adds a Kaevo-branded plugin layout and a live countdown for local pairing codes.",
  "description": "Connects Jellyfin securely to the Kaevo app with simple app-guided setup.",
  "guid": "80c77b84-7f2d-4b52-84c7-7dfe68cd95ae",
  "name": "Kaevo",
  "overview": "Secure Kaevo Cloud access for Jellyfin",
  "owner": "Kaevo",
  "targetAbi": "10.11.0.0",
  "timestamp": "$TIMESTAMP",
  "version": "0.2.51.0"
}
EOF

NORMALIZED_TIMESTAMP="$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$TIMESTAMP" '+%Y%m%d%H%M.%S')"
touch -t "$NORMALIZED_TIMESTAMP" "$PLUGIN_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" "$PLUGIN_DIR/QRCoder.dll" "$PLUGIN_DIR/meta.json"

python3 "$SCRIPT_DIR/create-deterministic-plugin-zip.py" "$PLUGIN_DIR" "$ZIP_PATH"

echo "Packaged directory: $PLUGIN_DIR"
echo "Packaged archive:   $ZIP_PATH"
