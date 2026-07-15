#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Cloud"
source "$ROOT/.env.local"

BASE="https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev"

echo "Checking Kaevo Cloud..."
echo ""

echo "1. Health"
curl -s "$BASE/health" | python3 -m json.tool

echo ""
echo "2. Personalized Home"
curl -s "$BASE/v1/home/personalized?profile_id=profile_123" \
  -H "x-kaevo-dev-key: $KAEVO_DEV_API_KEY" \
  | python3 -m json.tool
