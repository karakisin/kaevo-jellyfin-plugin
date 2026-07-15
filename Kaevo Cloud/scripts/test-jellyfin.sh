#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Cloud"
source "$ROOT/config/providers.env.local"

OUT="$ROOT/docs/provider-tests/jellyfin-libraries.json"

echo "Testing Jellyfin libraries..."

curl -s "$KAEVO_JELLYFIN_BASE_URL/Users/$KAEVO_JELLYFIN_USER_ID/Views" \
  -H "X-Emby-Token: $KAEVO_JELLYFIN_TOKEN" \
  | tee "$OUT" \
  | python3 -m json.tool

echo ""
echo "✅ Saved Jellyfin result:"
echo "$OUT"
