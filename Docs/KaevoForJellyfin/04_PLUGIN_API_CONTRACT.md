# Plugin API Contract — Kaevo for Jellyfin

These endpoints describe the desired Kaevo-facing local API exposed by the Jellyfin plugin.

The exact Jellyfin controller route names can be adjusted during implementation, but the contract should stay stable.

## GET /kaevo/status

Purpose:
Return plugin health and setup status.

Expected response fields:
- state
- plugin
- version
- setup_complete
- paired
- jellyfin.server_name
- jellyfin.server_id
- jellyfin.version
- features.read_users
- features.read_libraries
- features.compatibility_scan
- features.media_prep
- features.smart_download_recovery

## GET /kaevo/setup

Purpose:
Return current setup configuration.

Expected response fields:
- setup_complete
- selected_user_ids
- selected_library_ids
- cloud_paired
- providers.seerr
- providers.sonarr
- providers.radarr

## PUT /kaevo/setup

Purpose:
Save setup selections.

Allowed fields:
- selected_user_ids
- selected_library_ids
- features.smart_home_rows
- features.compatibility_scan
- features.travel_downloads_foundation
- features.smart_download_recovery

## POST /kaevo/pair/start

Purpose:
Generate short-lived pairing code.

Expected response fields:
- pairing_code
- expires_in_seconds
- pairing_url_available

## POST /kaevo/pair/complete

Purpose:
Complete cloud pairing.

Expected response fields:
- paired
- kaevo_server_id

## GET /kaevo/users

Purpose:
Return Jellyfin users visible to setup.

Expected response fields:
- users[].id
- users[].name
- users[].is_disabled
- users[].is_hidden
- users[].selected

## GET /kaevo/libraries

Purpose:
Return Jellyfin libraries.

Expected response fields:
- libraries[].id
- libraries[].name
- libraries[].collection_type
- libraries[].selected
- libraries[].item_count_known
- libraries[].item_count

## POST /kaevo/scan/start

Purpose:
Start a read-only compatibility scan.

Expected response fields:
- job_id
- state

## GET /kaevo/scan/status

Purpose:
Return latest scan status.

Expected response fields:
- job_id
- state
- progress
- items_scanned
- items_total
- summary.direct_play_likely
- summary.remux_likely
- summary.transcode_likely
- summary.unknown

## GET /kaevo/media/capabilities

Purpose:
Return compatibility hints for one item.

Expected query:
- item_id

Expected response fields:
- item_id
- container
- video_codec
- audio_codecs
- subtitle_formats
- direct_play_likely
- remux_likely
- transcode_likely
- notes

## GET /kaevo/providers/status

Purpose:
Return provider connection status.

Expected response fields:
- seerr.configured
- seerr.healthy
- sonarr.configured
- sonarr.healthy
- radarr.configured
- radarr.healthy

## POST /kaevo/providers/test

Purpose:
Test a provider connection.

Important:
Never return provider API keys.

## Security Rules

- Never return provider API keys.
- Never log provider API keys.
- Never return full raw logs by default.
- Pairing code should expire.
- Phase 1 APIs are read-only except setup/configuration saves.
