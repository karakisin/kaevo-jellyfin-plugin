#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
source "$SCRIPT_DIR/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$SCRIPT_DIR" || { status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; }

set -a
source "$ROOT/config/providers.env.local"
set +a

OUT_DIR="$KAEVO_PROVIDER_TEST_OUTPUT_ROOT"
mkdir -p -m 700 "$OUT_DIR"
SUMMARY="$OUT_DIR/jellyfin-media-summary.json"
OUT="$OUT_DIR/jellyfin-playback-compatibility.json"

python3 - <<'PY'
from pathlib import Path
import json
import os
import urllib.parse
import urllib.request
import urllib.error

root = Path(os.environ["KAEVO_CLOUD_ROOT"])
out_dir = Path(os.environ["KAEVO_PROVIDER_TEST_OUTPUT_ROOT"])
summary_path = out_dir / "jellyfin-media-summary.json"
out_path = out_dir / "jellyfin-playback-compatibility.json"

base = os.environ["KAEVO_JELLYFIN_BASE_URL"].rstrip("/")
user_id = os.environ["KAEVO_JELLYFIN_USER_ID"]
token = os.environ["KAEVO_JELLYFIN_TOKEN"]

summary = json.loads(summary_path.read_text())
movies = summary.get("movies", [])

friendly_containers = {"mp4", "m4v", "mov"}
friendly_video = {"h264", "hevc"}
friendly_audio = {"aac", "ac3", "eac3", "mp3", "alac"}

def playback_info(item_id):
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
        return json.loads(response.read().decode("utf-8"))

def classify(container, video_codecs, audio_codecs):
    container_set = set(x.strip().lower() for x in str(container or "").split(",") if x.strip())
    video_set = set(x.lower() for x in video_codecs if x)
    audio_set = set(x.lower() for x in audio_codecs if x)

    has_friendly_container = bool(container_set & friendly_containers)
    has_friendly_video = bool(video_set & friendly_video)
    has_friendly_audio = bool(audio_set & friendly_audio)

    if has_friendly_container and has_friendly_video and has_friendly_audio:
        return "likely_avplayer_friendly"

    if not has_friendly_container:
        return "needs_container_remux_or_jellyfin_stream"

    if not has_friendly_audio:
        return "needs_audio_transcode_or_fallback_audio"

    if not has_friendly_video:
        return "needs_video_transcode_or_unsupported_video"

    return "needs_manual_test"

results = []

for item in movies:
    name = item.get("name", "")
    item_id = item.get("id", "")

    if not item_id:
        continue

    if "Collection" in name:
        continue

    try:
        data = playback_info(item_id)
        media_sources = data.get("MediaSources") or []
        first_source = media_sources[0] if media_sources else {}
        streams = first_source.get("MediaStreams") or []

        video_streams = [s for s in streams if s.get("Type") == "Video"]
        audio_streams = [s for s in streams if s.get("Type") == "Audio"]
        subtitle_streams = [s for s in streams if s.get("Type") == "Subtitle"]

        container = first_source.get("Container") or ""
        video_codecs = [s.get("Codec") for s in video_streams]
        audio_codecs = [s.get("Codec") for s in audio_streams]

        results.append({
            "id": item_id,
            "name": name,
            "year": item.get("production_year"),
            "container": container,
            "path": first_source.get("Path"),
            "supports_direct_play": first_source.get("SupportsDirectPlay"),
            "supports_direct_stream": first_source.get("SupportsDirectStream"),
            "supports_transcoding": first_source.get("SupportsTranscoding"),
            "video_codecs": video_codecs,
            "audio_codecs": audio_codecs,
            "subtitle_count": len(subtitle_streams),
            "classification": classify(container, video_codecs, audio_codecs)
        })

    except Exception as error:
        results.append({
            "id": item_id,
            "name": name,
            "year": item.get("production_year"),
            "error": str(error),
            "classification": "probe_failed"
        })

summary_out = {
    "total_checked": len(results),
    "counts": {},
    "items": results
}

for result in results:
    key = result.get("classification", "unknown")
    summary_out["counts"][key] = summary_out["counts"].get(key, 0) + 1

out_path.write_text(json.dumps(summary_out, indent=2))

print("✅ Jellyfin playback compatibility scan complete")
print("")
print("Counts:")
for key, value in summary_out["counts"].items():
    print(f"- {key}: {value}")

print("")
print("Sample results:")
for result in results[:15]:
    print(f'- {result.get("name")} ({result.get("year")})')
    print(f'  Container: {result.get("container")}')
    print(f'  Video: {", ".join([str(x) for x in result.get("video_codecs", []) if x])}')
    print(f'  Audio: {", ".join([str(x) for x in result.get("audio_codecs", [])[:4] if x])}')
    print(f'  Classification: {result.get("classification")}')

print("")
print("Saved:")
print(out_path)
PY
