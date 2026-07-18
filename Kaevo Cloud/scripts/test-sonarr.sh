#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
source "$SCRIPT_DIR/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$SCRIPT_DIR" || { status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; }
source "$ROOT/config/providers.env.local"

OUT="$KAEVO_PROVIDER_TEST_OUTPUT_ROOT/sonarr-system-status.json"
mkdir -p -m 700 "$KAEVO_PROVIDER_TEST_OUTPUT_ROOT"

echo "Testing Sonarr system status..."

curl -s "$KAEVO_SONARR_BASE_URL/api/v3/system/status" \
  -H "X-Api-Key: $KAEVO_SONARR_API_KEY" \
  | tee "$OUT" \
  | python3 -m json.tool

echo ""
echo "✅ Saved Sonarr result:"
echo "$OUT"
