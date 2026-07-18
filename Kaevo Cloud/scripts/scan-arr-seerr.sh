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
import urllib.request
import urllib.error
import urllib.parse

root = Path(os.environ["KAEVO_CLOUD_ROOT"])
out_dir = Path(os.environ["KAEVO_PROVIDER_TEST_OUTPUT_ROOT"])

sonarr_base = os.environ["KAEVO_SONARR_BASE_URL"].rstrip("/")
sonarr_key = os.environ["KAEVO_SONARR_API_KEY"]

radarr_base = os.environ["KAEVO_RADARR_BASE_URL"].rstrip("/")
radarr_key = os.environ["KAEVO_RADARR_API_KEY"]

seerr_base = os.environ["KAEVO_SEERR_BASE_URL"].rstrip("/")
seerr_key = os.environ["KAEVO_SEERR_API_KEY"]


def get_json(url, headers=None):
    req = urllib.request.Request(
        url,
        headers=headers or {
            "Accept": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read().decode("utf-8")
            return {
                "ok": True,
                "status": response.status,
                "json": json.loads(raw) if raw else None
            }
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        parsed = None
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw

        return {
            "ok": False,
            "status": error.code,
            "error": parsed
        }
    except Exception as error:
        return {
            "ok": False,
            "status": None,
            "error": str(error)
        }


def save(name, data):
    path = out_dir / name
    path.write_text(json.dumps(data, indent=2))
    return path


sonarr_headers = {
    "Accept": "application/json",
    "X-Api-Key": sonarr_key
}

radarr_headers = {
    "Accept": "application/json",
    "X-Api-Key": radarr_key
}

seerr_headers = {
    "Accept": "application/json",
    "X-Api-Key": seerr_key
}

sonarr_status = get_json(f"{sonarr_base}/api/v3/system/status", sonarr_headers)
sonarr_series = get_json(f"{sonarr_base}/api/v3/series", sonarr_headers)
sonarr_queue = get_json(f"{sonarr_base}/api/v3/queue?page=1&pageSize=20", sonarr_headers)

radarr_status = get_json(f"{radarr_base}/api/v3/system/status", radarr_headers)
radarr_movies = get_json(f"{radarr_base}/api/v3/movie", radarr_headers)
radarr_queue = get_json(f"{radarr_base}/api/v3/queue?page=1&pageSize=20", radarr_headers)

seerr_status = get_json(f"{seerr_base}/api/v1/status", seerr_headers)

# Safe read-only request check. If unsupported, we just record the failure.
seerr_requests = get_json(f"{seerr_base}/api/v1/request?take=20&skip=0", seerr_headers)

save("sonarr-series.json", sonarr_series)
save("sonarr-queue.json", sonarr_queue)
save("radarr-movies.json", radarr_movies)
save("radarr-queue.json", radarr_queue)
save("seerr-requests.json", seerr_requests)

sonarr_series_items = sonarr_series.get("json") if sonarr_series.get("ok") else []
radarr_movie_items = radarr_movies.get("json") if radarr_movies.get("ok") else []

if not isinstance(sonarr_series_items, list):
    sonarr_series_items = []

if not isinstance(radarr_movie_items, list):
    radarr_movie_items = []

sonarr_queue_json = sonarr_queue.get("json") if sonarr_queue.get("ok") else {}
radarr_queue_json = radarr_queue.get("json") if radarr_queue.get("ok") else {}

sonarr_queue_records = []
radarr_queue_records = []

if isinstance(sonarr_queue_json, dict):
    sonarr_queue_records = sonarr_queue_json.get("records") or []

if isinstance(radarr_queue_json, dict):
    radarr_queue_records = radarr_queue_json.get("records") or []

summary = {
    "sonarr": {
        "ok": sonarr_status.get("ok") and sonarr_series.get("ok"),
        "version": (sonarr_status.get("json") or {}).get("version") if isinstance(sonarr_status.get("json"), dict) else "",
        "series_count": len(sonarr_series_items),
        "queue_count": len(sonarr_queue_records),
        "sample_series": [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "year": item.get("year"),
                "monitored": item.get("monitored"),
                "status": item.get("status"),
                "statistics": item.get("statistics", {})
            }
            for item in sonarr_series_items[:10]
        ]
    },
    "radarr": {
        "ok": radarr_status.get("ok") and radarr_movies.get("ok"),
        "version": (radarr_status.get("json") or {}).get("version") if isinstance(radarr_status.get("json"), dict) else "",
        "movie_count": len(radarr_movie_items),
        "queue_count": len(radarr_queue_records),
        "sample_movies": [
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "year": item.get("year"),
                "monitored": item.get("monitored"),
                "hasFile": item.get("hasFile"),
                "movieFile": bool(item.get("movieFile"))
            }
            for item in radarr_movie_items[:10]
        ]
    },
    "seerr": {
        "ok": seerr_status.get("ok"),
        "version": (seerr_status.get("json") or {}).get("version") if isinstance(seerr_status.get("json"), dict) else "",
        "requests_endpoint_ok": seerr_requests.get("ok"),
        "requests_status": seerr_requests.get("status")
    }
}

save("arr-seerr-summary.json", summary)

print("✅ Sonarr/Radarr/Seerr scan complete")
print("")
print("Sonarr:")
print(f'- OK: {summary["sonarr"]["ok"]}')
print(f'- Version: {summary["sonarr"]["version"]}')
print(f'- Series: {summary["sonarr"]["series_count"]}')
print(f'- Queue records: {summary["sonarr"]["queue_count"]}')
for item in summary["sonarr"]["sample_series"][:10]:
    print(f'  - {item["title"]} ({item["year"]})')

print("")
print("Radarr:")
print(f'- OK: {summary["radarr"]["ok"]}')
print(f'- Version: {summary["radarr"]["version"]}')
print(f'- Movies: {summary["radarr"]["movie_count"]}')
print(f'- Queue records: {summary["radarr"]["queue_count"]}')
for item in summary["radarr"]["sample_movies"][:10]:
    print(f'  - {item["title"]} ({item["year"]})')

print("")
print("Seerr:")
print(f'- OK: {summary["seerr"]["ok"]}')
print(f'- Version: {summary["seerr"]["version"]}')
print(f'- Requests endpoint OK: {summary["seerr"]["requests_endpoint_ok"]}')
print(f'- Requests status: {summary["seerr"]["requests_status"]}')

print("")
print("Saved:")
print(out_dir / "arr-seerr-summary.json")
PY
