#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
source "$SCRIPT_DIR/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$SCRIPT_DIR" || { status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; }

# Export provider values so Python can read them.
set -a
source "$ROOT/config/providers.env.local"
set +a

OUT_DIR="$KAEVO_PROVIDER_TEST_OUTPUT_ROOT"
mkdir -p -m 700 "$OUT_DIR"
SUMMARY="$OUT_DIR/jellyfin-media-summary.json"
OUT="$OUT_DIR/jellyfin-playback-probe.json"

python3 - <<'PY'
from pathlib import Path
import json
import os
import urllib.parse
import urllib.request

root = Path(os.environ["KAEVO_CLOUD_ROOT"])
out_dir = Path(os.environ["KAEVO_PROVIDER_TEST_OUTPUT_ROOT"])
summary_path = out_dir / "jellyfin-media-summary.json"
out_path = out_dir / "jellyfin-playback-probe.json"

required = [
    "KAEVO_JELLYFIN_BASE_URL",
    "KAEVO_JELLYFIN_USER_ID",
    "KAEVO_JELLYFIN_TOKEN"
]

missing = [name for name in required if not os.environ.get(name)]
if missing:
    print("❌ Missing Jellyfin env values:")
    for name in missing:
        print("-", name)
    raise SystemExit(1)

base = os.environ["KAEVO_JELLYFIN_BASE_URL"].rstrip("/")
user_id = os.environ["KAEVO_JELLYFIN_USER_ID"]
token = os.environ["KAEVO_JELLYFIN_TOKEN"]

summary = json.loads(summary_path.read_text())
movies = summary.get("movies", [])

candidate = None
for item in movies:
    name = item.get("name", "")
    item_type = item.get("type", "")
    if "Collection" not in name and item.get("id") and item_type == "Movie":
        candidate = item
        break

if not candidate:
    for item in movies:
        name = item.get("name", "")
        if "Collection" not in name and item.get("id"):
            candidate = item
            break

if not candidate:
    raise SystemExit("❌ Could not find a non-collection movie candidate.")

item_id = candidate["id"]

url = f"{base}/Items/{item_id}/PlaybackInfo?" + urllib.parse.urlencode({
    "UserId": user_id
})

req = urllib.request.Request(
    url,
    headers={
        "X-Emby-Token": token,
        "Accept": "application/json"
    }
)

with urllib.request.urlopen(req, timeout=60) as response:
    data = json.loads(response.read().decode("utf-8"))

out_path.write_text(json.dumps(data, indent=2))

media_sources = data.get("MediaSources") or []
first_source = media_sources[0] if media_sources else {}
streams = first_source.get("MediaStreams") or []

video_streams = [s for s in streams if s.get("Type") == "Video"]
audio_streams = [s for s in streams if s.get("Type") == "Audio"]
subtitle_streams = [s for s in streams if s.get("Type") == "Subtitle"]

print("✅ Jellyfin playback probe complete")
print("")
print("Item:")
print(f'- Name: {candidate.get("name")}')
print(f'- Id: {item_id}')
print("")
print("Media source:")
print(f'- Container: {first_source.get("Container")}')
print(f'- Path: {first_source.get("Path")}')
print(f'- Supports Direct Play: {first_source.get("SupportsDirectPlay")}')
print(f'- Supports Direct Stream: {first_source.get("SupportsDirectStream")}')
print(f'- Supports Transcoding: {first_source.get("SupportsTranscoding")}')
print("")
print("Video streams:")
for stream in video_streams:
    print(f'- Codec: {stream.get("Codec")} | {stream.get("Width")}x{stream.get("Height")} | HDR: {stream.get("VideoRange")}')

print("")
print("Audio streams:")
for stream in audio_streams[:5]:
    print(f'- Codec: {stream.get("Codec")} | Channels: {stream.get("Channels")} | Language: {stream.get("Language")}')

print("")
print(f"Subtitles: {len(subtitle_streams)}")
print("")
print("Saved:")
print(out_path)
PY
