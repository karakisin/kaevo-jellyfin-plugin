#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PACKAGE_ROOT="$PROJECT_ROOT/artifacts/package"
PLUGIN_DIR="$PACKAGE_ROOT/Kaevo"
TRUENAS_SSH="${1:-root@192.168.68.203}"

test -f "$PLUGIN_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" || {
    echo "Package is missing. Run scripts/package-plugin.sh first." >&2
    exit 1
}

echo "Installing Kaevo into the running Jellyfin container on $TRUENAS_SSH..."
tar -C "$PACKAGE_ROOT" -cf - Kaevo | ssh "$TRUENAS_SSH" 'set -eu
tmp_dir=$(mktemp -d)
trap '\''rm -rf "$tmp_dir"'\'' EXIT
tar -xf - -C "$tmp_dir"
container=$(docker ps --format "{{.ID}} {{.Names}} {{.Image}}" | awk '\''tolower($0) ~ /jellyfin/ { print $1; exit }'\'')
if [ -z "$container" ]; then
    echo "No running Jellyfin Docker container was found." >&2
    exit 1
fi
docker exec "$container" rm -rf /config/plugins/Kaevo
docker cp "$tmp_dir/Kaevo" "$container:/config/plugins/Kaevo"
docker restart "$container" >/dev/null
echo "Installed Kaevo and restarted Jellyfin container $container."'
