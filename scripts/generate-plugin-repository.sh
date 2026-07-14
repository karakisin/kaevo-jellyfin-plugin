#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ZIP_PATH="$PROJECT_ROOT/artifacts/package/Kaevo.Plugin.KaevoForJellyfin.zip"
META_PATH="$PROJECT_ROOT/artifacts/package/Kaevo/meta.json"
REPOSITORY_DIR="$PROJECT_ROOT/artifacts/repository"
MANIFEST_PATH="$REPOSITORY_DIR/manifest.json"
PUBLISHED_MANIFEST_PATH="$PROJECT_ROOT/manifest.json"
SOURCE_URL="${1:-${KAEVO_PLUGIN_SOURCE_URL:-}}"
IMAGE_URL="${2:-${KAEVO_PLUGIN_IMAGE_URL:-https://raw.githubusercontent.com/karakisin/kaevo-jellyfin-plugin/main/assets/Kaevo.Plugin.Icon.png}}"

if [[ -z "$SOURCE_URL" ]]; then
    echo "Usage: $0 https://example.com/Kaevo.Plugin.KaevoForJellyfin.zip" >&2
    exit 1
fi

if [[ "$SOURCE_URL" != https://* ]]; then
    echo "The plugin source URL must use HTTPS." >&2
    exit 1
fi

if [[ "$IMAGE_URL" != https://* ]]; then
    echo "The plugin image URL must use HTTPS." >&2
    exit 1
fi

command -v jq >/dev/null 2>&1 || {
    echo "jq is required to generate and validate the repository manifest." >&2
    exit 1
}

test -f "$ZIP_PATH" || {
    echo "Plugin package is missing. Run scripts/package-plugin.sh first." >&2
    exit 1
}

test -f "$META_PATH" || {
    echo "Plugin metadata is missing. Run scripts/package-plugin.sh first." >&2
    exit 1
}

if command -v md5 >/dev/null 2>&1; then
    CHECKSUM="$(md5 -q "$ZIP_PATH")"
elif command -v md5sum >/dev/null 2>&1; then
    CHECKSUM="$(md5sum "$ZIP_PATH" | awk '{print $1}')"
else
    echo "An MD5 checksum utility is required by the Jellyfin repository format." >&2
    exit 1
fi

mkdir -p "$REPOSITORY_DIR"
cp "$ZIP_PATH" "$REPOSITORY_DIR/"

jq -n \
    --slurpfile meta "$META_PATH" \
    --slurpfile published "$PUBLISHED_MANIFEST_PATH" \
    --arg sourceUrl "$SOURCE_URL" \
    --arg imageUrl "$IMAGE_URL" \
    --arg checksum "$CHECKSUM" \
    '[{
      category: $meta[0].category,
      guid: $meta[0].guid,
      imageUrl: $imageUrl,
      name: $meta[0].name,
      description: $meta[0].description,
      owner: $meta[0].owner,
      overview: $meta[0].overview,
      versions: ([{
        version: $meta[0].version,
        changelog: $meta[0].changelog,
        targetAbi: $meta[0].targetAbi,
        sourceUrl: $sourceUrl,
        checksum: $checksum,
        timestamp: $meta[0].timestamp
      }] + (($published[0][0].versions // []) | map(select(.version != $meta[0].version))))
    }]' > "$MANIFEST_PATH"

jq -e '
  length == 1 and
  .[0].guid == "80c77b84-7f2d-4b52-84c7-7dfe68cd95ae" and
  (.[0].imageUrl | startswith("https://")) and
  .[0].versions[0].targetAbi == "10.11.0.0" and
  (.[0].versions[0].checksum | test("^[0-9a-f]{32}$")) and
  (.[0].versions[0].sourceUrl | startswith("https://"))
' "$MANIFEST_PATH" >/dev/null

echo "Repository manifest: $MANIFEST_PATH"
echo "Catalog checksum:    $CHECKSUM"
