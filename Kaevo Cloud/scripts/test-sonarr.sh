#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Cloud"
source "$ROOT/config/providers.env.local"

OUT="$ROOT/docs/provider-tests/sonarr-system-status.json"

echo "Testing Sonarr system status..."

curl -s "$KAEVO_SONARR_BASE_URL/api/v3/system/status" \
  -H "X-Api-Key: $KAEVO_SONARR_API_KEY" \
  | tee "$OUT" \
  | python3 -m json.tool

echo ""
echo "✅ Saved Sonarr result:"
echo "$OUT"
