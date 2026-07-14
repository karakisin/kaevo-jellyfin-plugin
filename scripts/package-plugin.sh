#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/artifacts/build"
PACKAGE_ROOT="$PROJECT_ROOT/artifacts/package"
PLUGIN_DIR="$PACKAGE_ROOT/Kaevo"
ZIP_PATH="$PACKAGE_ROOT/Kaevo.Plugin.KaevoForJellyfin.zip"
TIMESTAMP="${KAEVO_RELEASE_TIMESTAMP:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

test -f "$BUILD_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" || {
    echo "Build output is missing. Run scripts/build-plugin-docker.sh first." >&2
    exit 1
}

rm -rf "$PLUGIN_DIR" "$ZIP_PATH"
mkdir -p "$PLUGIN_DIR"

cp "$BUILD_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" "$PLUGIN_DIR/"
if [[ -f "$BUILD_DIR/Kaevo.Plugin.KaevoForJellyfin.pdb" ]]; then
    cp "$BUILD_DIR/Kaevo.Plugin.KaevoForJellyfin.pdb" "$PLUGIN_DIR/"
fi

cat > "$PLUGIN_DIR/meta.json" <<EOF
{
  "category": "General",
  "changelog": "Adds the plugin-only Kaevo Cloud connector, remote metadata and artwork, guarded Jellyfin writes, playback preparation, and an outbound secure playback relay.",
  "description": "Connects Jellyfin to Kaevo Cloud through an outbound-only, least-privilege connector with local playback processing.",
  "guid": "80c77b84-7f2d-4b52-84c7-7dfe68cd95ae",
  "name": "Kaevo",
  "overview": "Secure Kaevo Cloud access for Jellyfin",
  "owner": "Kaevo",
  "targetAbi": "10.11.0.0",
  "timestamp": "$TIMESTAMP",
  "version": "0.2.0.0"
}
EOF

(
    cd "$PLUGIN_DIR"
    zip -q -r "$ZIP_PATH" .
)

echo "Packaged directory: $PLUGIN_DIR"
echo "Packaged archive:   $ZIP_PATH"
