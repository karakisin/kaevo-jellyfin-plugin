#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Cloud"
source "$ROOT/config/providers.env.local"

OUT="$ROOT/docs/provider-tests/seerr-status.json"

echo "Testing Seerr status..."

curl -s "$KAEVO_SEERR_BASE_URL/api/v1/status" \
  -H "X-Api-Key: $KAEVO_SEERR_API_KEY" \
  | tee "$OUT" \
  | python3 -m json.tool

echo ""
echo "✅ Saved Seerr result:"
echo "$OUT"
