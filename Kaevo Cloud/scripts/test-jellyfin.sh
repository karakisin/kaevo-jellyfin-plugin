#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
source "$SCRIPT_DIR/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$SCRIPT_DIR" || { status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; }
source "$ROOT/config/providers.env.local"

OUT="$KAEVO_PROVIDER_TEST_OUTPUT_ROOT/jellyfin-libraries.json"
mkdir -p -m 700 "$KAEVO_PROVIDER_TEST_OUTPUT_ROOT"

echo "Testing Jellyfin libraries..."

curl -s "$KAEVO_JELLYFIN_BASE_URL/Users/$KAEVO_JELLYFIN_USER_ID/Views" \
  -H "X-Emby-Token: $KAEVO_JELLYFIN_TOKEN" \
  | tee "$OUT" \
  | python3 -m json.tool

echo ""
echo "✅ Saved Jellyfin result:"
echo "$OUT"
