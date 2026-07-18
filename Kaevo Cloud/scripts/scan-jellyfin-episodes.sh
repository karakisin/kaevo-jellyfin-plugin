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
OUT="$OUT_DIR/jellyfin-episodes-summary.json"

python3 - <<'PY'
from pathlib import Path
import json
import os
import urllib.parse
import urllib.request

root = Path(os.environ["KAEVO_CLOUD_ROOT"])
out_dir = Path(os.environ["KAEVO_PROVIDER_TEST_OUTPUT_ROOT"])
summary_path = out_dir / "jellyfin-media-summary.json"
out_path = out_dir / "jellyfin-episodes-summary.json"

base = os.environ["KAEVO_JELLYFIN_BASE_URL"].rstrip("/")
user_id = os.environ["KAEVO_JELLYFIN_USER_ID"]
token = os.environ["KAEVO_JELLYFIN_TOKEN"]

summary = json.loads(summary_path.read_text())
shows = summary.get("shows", [])

def get_json(path, params=None):
    query = ""
    if params:
        query = "?" + urllib.parse.urlencode(params)

    url = base + path + query
    req = urllib.request.Request(
        url,
        headers={
            "X-Emby-Token": token,
            "Accept": "application/json"
        }
    )

    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))

def image_url(item, image_type="Primary"):
    item_id = item.get("Id") or item.get("id")
    tags = item.get("ImageTags") or item.get("image_tags") or {}

    if image_type == "Primary":
        tag = tags.get("Primary")
    else:
        backdrop_tags = item.get("BackdropImageTags") or []
        tag = backdrop_tags[0] if backdrop_tags else None

    if not item_id or not tag:
        return ""

    return f"{base}/Items/{item_id}/Images/{image_type}?tag={tag}"

def normalize_episode(ep, series_name, season_name):
    return {
        "id": ep.get("Id"),
        "series_id": ep.get("SeriesId"),
        "series_name": series_name,
        "season_id": ep.get("SeasonId"),
        "season_name": season_name,
        "name": ep.get("Name"),
        "index_number": ep.get("IndexNumber"),
        "parent_index_number": ep.get("ParentIndexNumber"),
        "production_year": ep.get("ProductionYear"),
        "premiere_date": ep.get("PremiereDate", ""),
        "overview": ep.get("Overview", ""),
        "runtime_ticks": ep.get("RunTimeTicks"),
        "primary_image_url": image_url(ep, "Primary"),
        "user_data": ep.get("UserData", {}),
        "media_sources_count": len(ep.get("MediaSources") or []),
        "location_type": ep.get("LocationType", ""),
        "type": ep.get("Type")
    }

def fetch_seasons(series_id):
    return get_json(f"/Shows/{series_id}/Seasons", {
        "UserId": user_id,
        "Fields": "Overview,ImageTags,BackdropImageTags,UserData"
    }).get("Items", [])

def fetch_episodes(series_id, season_id):
    return get_json(f"/Shows/{series_id}/Episodes", {
        "UserId": user_id,
        "SeasonId": season_id,
        "Fields": "Overview,PremiereDate,ProductionYear,RunTimeTicks,ImageTags,BackdropImageTags,MediaSources,UserData"
    }).get("Items", [])

series_summaries = []

# Keep it bounded for dev docs: scan first 10 shows fully.
for show in shows[:10]:
    series_id = show.get("id")
    series_name = show.get("name")

    if not series_id:
        continue

    seasons = fetch_seasons(series_id)
    season_summaries = []

    for season in seasons:
        season_id = season.get("Id")
        season_name = season.get("Name")

        episodes = fetch_episodes(series_id, season_id)

        season_summaries.append({
            "season_id": season_id,
            "season_name": season_name,
            "index_number": season.get("IndexNumber"),
            "episode_count": len(episodes),
            "episodes": [
                normalize_episode(ep, series_name, season_name)
                for ep in episodes[:10]
            ]
        })

    series_summaries.append({
        "series_id": series_id,
        "series_name": series_name,
        "year": show.get("production_year"),
        "season_count": len(seasons),
        "seasons": season_summaries
    })

result = {
    "scanned_series_count": len(series_summaries),
    "scanned_series_limit": 10,
    "series": series_summaries
}

out_path.write_text(json.dumps(result, indent=2))

print("✅ Jellyfin seasons/episodes scan complete")
print("")
for series in series_summaries:
    total_episodes = sum(s["episode_count"] for s in series["seasons"])
    print(f'- {series["series_name"]} ({series["year"]})')
    print(f'  Seasons: {series["season_count"]} | Episodes scanned: {total_episodes}')
    for season in series["seasons"][:3]:
        print(f'    - {season["season_name"]}: {season["episode_count"]} episodes')

print("")
print("Saved:")
print(out_path)
PY
