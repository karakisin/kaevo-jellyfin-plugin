#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
source "$SCRIPT_DIR/lib/kaevo-workspace.sh"
kaevo_init_cloud_root "$SCRIPT_DIR" || { status=$?; [[ $status -eq 10 ]] && exit 0; exit "$status"; }
ENV_FILE="$ROOT/config/providers.env.local"
OUT_DIR="$KAEVO_PROVIDER_TEST_OUTPUT_ROOT"

mkdir -p -m 700 "$OUT_DIR"

set -a
source "$ENV_FILE"
set +a

python3 - <<'PY'
from pathlib import Path
import json
import os
import urllib.parse
import urllib.request

root = Path(os.environ["KAEVO_CLOUD_ROOT"])
out_dir = Path(os.environ["KAEVO_PROVIDER_TEST_OUTPUT_ROOT"])

base = os.environ["KAEVO_JELLYFIN_BASE_URL"].rstrip("/")
user_id = os.environ["KAEVO_JELLYFIN_USER_ID"]
token = os.environ["KAEVO_JELLYFIN_TOKEN"]

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
    item_id = item.get("Id")
    tags = item.get("ImageTags") or {}

    if image_type == "Primary":
        tag = tags.get("Primary")
    else:
        backdrop_tags = item.get("BackdropImageTags") or []
        tag = backdrop_tags[0] if backdrop_tags else None

    if not item_id or not tag:
        return ""

    return f"{base}/Items/{item_id}/Images/{image_type}?tag={tag}"

def normalize_item(item):
    return {
        "id": item.get("Id", ""),
        "name": item.get("Name", ""),
        "type": item.get("Type", ""),
        "media_type": item.get("MediaType", ""),
        "production_year": item.get("ProductionYear"),
        "premiere_date": item.get("PremiereDate", ""),
        "overview": item.get("Overview", ""),
        "genres": item.get("Genres", []),
        "provider_ids": item.get("ProviderIds", {}),
        "runtime_ticks": item.get("RunTimeTicks"),
        "primary_image_url": image_url(item, "Primary"),
        "backdrop_image_url": image_url(item, "Backdrop"),
        "user_data": item.get("UserData", {}),
        "has_media_sources": bool(item.get("MediaSources")),
        "location_type": item.get("LocationType", "")
    }

libraries = get_json(f"/Users/{user_id}/Views")

(out_dir / "jellyfin-libraries.json").write_text(json.dumps(libraries, indent=2))

items = libraries.get("Items", [])

movie_library = next((x for x in items if x.get("CollectionType") == "movies"), None)
show_library = next((x for x in items if x.get("CollectionType") == "tvshows"), None)
collection_library = next((x for x in items if x.get("CollectionType") == "boxsets"), None)

def fetch_items(parent_id, include_types):
    if not parent_id:
        return {"Items": [], "TotalRecordCount": 0}

    return get_json(
        f"/Users/{user_id}/Items",
        {
            "ParentId": parent_id,
            "Recursive": "true",
            "IncludeItemTypes": include_types,
            "Fields": "Overview,Genres,Tags,DateCreated,PremiereDate,ProductionYear,ProviderIds,People,Studios,ImageTags,BackdropImageTags,MediaSources,UserData,Path,RunTimeTicks"
        }
    )

movies = fetch_items(movie_library["Id"] if movie_library else "", "Movie")
shows = fetch_items(show_library["Id"] if show_library else "", "Series")
collections = fetch_items(collection_library["Id"] if collection_library else "", "BoxSet")

(out_dir / "jellyfin-movies.json").write_text(json.dumps(movies, indent=2))
(out_dir / "jellyfin-shows.json").write_text(json.dumps(shows, indent=2))
(out_dir / "jellyfin-collections.json").write_text(json.dumps(collections, indent=2))

summary = {
    "server_base_url": base,
    "user_id": user_id,
    "libraries": [
        {
            "id": lib.get("Id"),
            "name": lib.get("Name"),
            "collection_type": lib.get("CollectionType"),
            "child_count": lib.get("ChildCount")
        }
        for lib in items
    ],
    "movies_count": movies.get("TotalRecordCount", len(movies.get("Items", []))),
    "shows_count": shows.get("TotalRecordCount", len(shows.get("Items", []))),
    "collections_count": collections.get("TotalRecordCount", len(collections.get("Items", []))),
    "movies": [normalize_item(x) for x in movies.get("Items", [])],
    "shows": [normalize_item(x) for x in shows.get("Items", [])],
    "collections": [normalize_item(x) for x in collections.get("Items", [])]
}

(out_dir / "jellyfin-media-summary.json").write_text(json.dumps(summary, indent=2))

print("✅ Jellyfin media scan complete")
print("")
print("Libraries:")
for lib in summary["libraries"]:
    print(f'- {lib["name"]} ({lib["collection_type"]}) — {lib["child_count"]} items')

print("")
print(f'Movies found: {summary["movies_count"]}')
for movie in summary["movies"][:10]:
    print(f'- {movie["name"]} ({movie["production_year"]})')

print("")
print(f'Shows found: {summary["shows_count"]}')
for show in summary["shows"][:10]:
    print(f'- {show["name"]} ({show["production_year"]})')

print("")
print("Saved:")
print(out_dir / "jellyfin-media-summary.json")
PY
