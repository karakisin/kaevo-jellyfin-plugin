#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
source "$SCRIPT_DIR/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$SCRIPT_DIR" || { status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; }
ENV_FILE="$ROOT/config/providers.env.local"
USERS_JSON="$KAEVO_PROVIDER_TEST_OUTPUT_ROOT/jellyfin-users.json"
USERS_SUMMARY="$KAEVO_PROVIDER_TEST_OUTPUT_ROOT/jellyfin-users-summary.txt"
mkdir -p -m 700 "$KAEVO_PROVIDER_TEST_OUTPUT_ROOT"

source "$ENV_FILE"

TARGET_NAME="${KAEVO_JELLYFIN_USERNAME:-Jefferson}"

echo "Fetching Jellyfin users..."
echo ""

curl -s "$KAEVO_JELLYFIN_BASE_URL/Users" \
  -H "X-Emby-Token: $KAEVO_JELLYFIN_TOKEN" \
  > "$USERS_JSON"

python3 - <<'PY'
from pathlib import Path
import json
import os
import re

root = Path(os.environ["KAEVO_CLOUD_ROOT"])
env_path = root / "config/providers.env.local"
out_dir = Path(os.environ["KAEVO_PROVIDER_TEST_OUTPUT_ROOT"])
users_json = out_dir / "jellyfin-users.json"
users_summary = out_dir / "jellyfin-users-summary.txt"

target_name = os.environ.get("KAEVO_JELLYFIN_USERNAME", "Jefferson")

data = json.loads(users_json.read_text())

if isinstance(data, dict):
    print("❌ Jellyfin did not return a user list.")
    print("Saved response:", users_json)
    raise SystemExit(1)

lines = []
match = None

for user in data:
    name = user.get("Name", "")
    user_id = user.get("Id", "")

    lines.append(f"{name} | {user_id}")

    if name.lower() == target_name.lower():
        match = user

users_summary.write_text("\n".join(lines) + "\n")

print("Jellyfin users:")
print("")
for line in lines:
    print(line)

if not match:
    print("")
    print(f"❌ Could not find target user: {target_name}")
    print("Set KAEVO_JELLYFIN_USERNAME in providers.env.local to one of the names above.")
    raise SystemExit(1)

user_id = match["Id"]
text = env_path.read_text()

if re.search(r'^KAEVO_JELLYFIN_USERNAME=', text, flags=re.MULTILINE):
    text = re.sub(
        r'^KAEVO_JELLYFIN_USERNAME=.*$',
        f'KAEVO_JELLYFIN_USERNAME="{target_name}"',
        text,
        flags=re.MULTILINE
    )
else:
    text += f'\nKAEVO_JELLYFIN_USERNAME="{target_name}"\n'

if re.search(r'^KAEVO_JELLYFIN_USER_ID=', text, flags=re.MULTILINE):
    text = re.sub(
        r'^KAEVO_JELLYFIN_USER_ID=.*$',
        f'KAEVO_JELLYFIN_USER_ID="{user_id}"',
        text,
        flags=re.MULTILINE
    )
else:
    text += f'\nKAEVO_JELLYFIN_USER_ID="{user_id}"\n'

env_path.write_text(text)

print("")
print("✅ Updated providers.env.local")
print("Selected Jellyfin user:", match.get("Name"))
print("Selected Jellyfin user ID:", user_id)
print("")
print("Saved user list:")
print(users_summary)
PY
