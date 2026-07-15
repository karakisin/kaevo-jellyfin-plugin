#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Cloud"
source "$ROOT/config/providers.env.local"

OUT="$ROOT/docs/provider-tests/radarr-system-status.json"

echo "Testing Radarr system status..."

curl -s "$KAEVO_RADARR_BASE_URL/api/v3/system/status" \
  -H "X-Api-Key: $KAEVO_RADARR_API_KEY" \
  | tee "$OUT" \
  | python3 -m json.tool

echo ""
echo "✅ Saved Radarr result:"
echo "$OUT"
