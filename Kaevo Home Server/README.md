# Kaevo Helper Prototype

Optional local helper prototype for Kaevo.

K62 no longer uses this service for normal provider execution. Native iOS owns
Seerr requests, Household-approved submissions, provider health, removal,
reconciliation, and downloader controls as those foundations are completed.

This source tree is separate from the deployed TrueNAS copy at:

`/mnt/HomeLab/AppData/StageDoorV2/app`

Do not edit the deployed path directly before review. Build and validate changes here first.

## Reserved Responsibilities

- transcoding.
- remuxing.
- batch conversion.
- CPU-intensive media processing.
- filesystem-heavy background jobs.
- long-running media optimization.

## Safety

- Provider secrets are never returned to iOS.
- qBittorrent SID cookies are memory-only.
- Import exclusions are always false.
- No title/folder/category/date guessing is used for deletion.
- No arbitrary filesystem deletion is exposed.
- No Jellyfin delete endpoint is implemented.

## Run Locally

```bash
cd "Kaevo Home Server"
export KAEVO_HOME_SERVER_SECRET_KEY="replace-with-local-secret"
uvicorn kaevo_home_server.main:app --reload
```
