#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PACKAGE_ROOT="$PROJECT_ROOT/artifacts/package"
PACKAGE_ROOT="${KAEVO_PACKAGE_ROOT:-$PACKAGE_ROOT}"
PLUGIN_DIR="$PACKAGE_ROOT/Kaevo"
TRUENAS_SSH="${1:-root@192.168.68.203}"
TRUENAS_IDENTITY_FILE="${KAEVO_TRUENAS_IDENTITY_FILE:-}"
SSH_ARGS=()
if [[ -n "$TRUENAS_IDENTITY_FILE" ]]; then
    test -f "$TRUENAS_IDENTITY_FILE" || {
        echo "Configured TrueNAS SSH identity file is missing." >&2
        exit 1
    }
    SSH_ARGS=(-o IdentitiesOnly=yes -i "$TRUENAS_IDENTITY_FILE")
fi

test -f "$PLUGIN_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" || {
    echo "Package is missing. Run scripts/package-plugin.sh first." >&2
    exit 1
}

PLUGIN_VERSION="$(python3 - "$PLUGIN_DIR/meta.json" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["version"])
PY
)"
PLUGIN_TARGET_DIRECTORY="Kaevo_${PLUGIN_VERSION}"
PLUGIN_DLL_SHA256="$(shasum -a 256 "$PLUGIN_DIR/Kaevo.Plugin.KaevoForJellyfin.dll" | awk '{print $1}')"

echo "Installing Kaevo ${PLUGIN_VERSION} into the running Jellyfin container on $TRUENAS_SSH..."
REMOTE_SCRIPT="$(cat <<'REMOTE'
set -eu

container=$(docker ps --format '{{.ID}} {{.Names}} {{.Image}}' | awk 'tolower($0) ~ /jellyfin/ { print $1; exit }')
if [ -z "$container" ]; then
    echo "No running Jellyfin Docker container was found." >&2
    exit 1
fi

image=$(docker inspect -f '{{.Config.Image}}' "$container")
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
target="${KAEVO_PLUGIN_TARGET_DIRECTORY:?}"
expected_hash="${KAEVO_PLUGIN_DLL_SHA256:?}"

docker stop "$container" >/dev/null

docker run --rm -i --volumes-from "$container" --entrypoint /bin/sh "$image" -c '
    set -eu
    target="$1"
    expected_hash="$2"
    timestamp="$3"
    staging="/config/kaevo-plugin-staging/${target}-${timestamp}"
    backup="/config/kaevo-plugin-backups/${target}-${timestamp}"

    mkdir -p "$staging" /config/kaevo-plugin-backups
    tar -xf - -C "$staging" --strip-components=1
    for name in Kaevo.Plugin.KaevoForJellyfin.dll QRCoder.dll BouncyCastle.Cryptography.dll meta.json; do
        test -f "$staging/$name"
    done

    new_hash=$(sha256sum "$staging/Kaevo.Plugin.KaevoForJellyfin.dll" | awk "{print \\$1}")
    test "$new_hash" = "$expected_hash"

    if test -d "/config/plugins/$target"; then
        current_hash=$(sha256sum "/config/plugins/$target/Kaevo.Plugin.KaevoForJellyfin.dll" | awk "{print \\$1}")
        echo "Current plugin version directory: $target"
        echo "Current plugin DLL SHA-256: $current_hash"
        mv "/config/plugins/$target" "$backup"
        echo "Backed up the previous plugin as $backup"
    fi

    mv "$staging" "/config/plugins/$target"
    echo "New plugin DLL SHA-256: $new_hash"
' sh "$target" "$expected_hash" "$timestamp"

docker start "$container" >/dev/null
sleep 20
docker inspect -f 'Jellyfin status={{.State.Status}} restarting={{.State.Restarting}} exit={{.State.ExitCode}}' "$container"
echo "Installed Kaevo and restarted Jellyfin container $container."
REMOTE
)"
REMOTE_COMMAND="KAEVO_PLUGIN_TARGET_DIRECTORY=$(printf '%q' "$PLUGIN_TARGET_DIRECTORY") KAEVO_PLUGIN_DLL_SHA256=$(printf '%q' "$PLUGIN_DLL_SHA256") bash -c $(printf '%q' "$REMOTE_SCRIPT")"
tar -C "$PACKAGE_ROOT" -cf - Kaevo | ssh "${SSH_ARGS[@]}" "$TRUENAS_SSH" "$REMOTE_COMMAND"
