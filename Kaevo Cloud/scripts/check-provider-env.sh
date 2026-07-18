#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
source "$SCRIPT_DIR/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$SCRIPT_DIR" || { status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; }
ENV_FILE="$ROOT/config/providers.env.local"

if [ ! -f "$ENV_FILE" ]; then
  echo "❌ Missing provider config:"
  echo "$ENV_FILE"
  echo ""
  echo "Create it with:"
  echo "cp \"$ROOT/config/providers.env.example\" \"$ENV_FILE\""
  exit 1
fi

source "$ENV_FILE"

check_var() {
  local name="$1"
  local value="${!name:-}"

  if [ -z "$value" ] || [[ "$value" == YOUR_* ]]; then
    echo "❌ $name missing"
  else
    echo "✅ $name set"
  fi
}

echo "Checking provider config..."
echo ""

check_var KAEVO_JELLYFIN_BASE_URL
check_var KAEVO_JELLYFIN_USER_ID
check_var KAEVO_JELLYFIN_TOKEN

check_var KAEVO_SEERR_BASE_URL
check_var KAEVO_SEERR_API_KEY

check_var KAEVO_SONARR_BASE_URL
check_var KAEVO_SONARR_API_KEY

check_var KAEVO_RADARR_BASE_URL
check_var KAEVO_RADARR_API_KEY
