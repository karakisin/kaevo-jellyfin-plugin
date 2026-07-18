# Kaevo Home Server Provider Orchestrator

K62 moves provider orchestration out of SwiftUI screens and into the local Kaevo Home Server.

## Why

Direct iOS orchestration could not durably coordinate Seerr, Sonarr/Radarr, qBittorrent/SABnzbd, request attribution, deletion planning, reconciliation, and retry. The Home Server now owns provider execution and durable operation state.

## Provider Contracts

- Seerr request creation uses `userId` in the original `POST /request` when a verified linked Seerr identity is selected.
- Sonarr/Radarr correlation uses exact TMDB/TVDB identity, exact Arr item id, queue/history `downloadId`, and managed-file records.
- qBittorrent uses username/password login, memory-only SID cookie, exact hash lookup, file list, and exact torrent deletion.
- SABnzbd uses API key, exact NZO queue/history lookups, and exact job deletion with `del_files`.

## API Surface

- `GET /api/v1/status`
- `GET /api/v1/providers`
- `PUT /api/v1/providers/{kind}`
- `DELETE /api/v1/providers/{kind}`
- `GET /api/v1/providers/audit`
- `POST /api/v1/requests`
- `POST /api/v1/removals/plan`
- `POST /api/v1/removals/{planID}/execute-keep-media`
- `POST /api/v1/removals/{planID}/execute-permanent`
- `GET /api/v1/operations/{operationID}`
- `POST /api/v1/operations/{operationID}/reconcile`
- `POST /api/v1/operations/{operationID}/retry-step`

Mutation routes require `X-Kaevo-Home-Server-Token` when `KAEVO_HOME_SERVER_IOS_TOKEN` is configured. Operation ids provide idempotency and lookup, but they are not treated as authorization.

## Safety Boundaries

- No secrets are returned to iOS.
- No raw filesystem paths are accepted from UI.
- No title/folder/category/date guessing is allowed.
- No bulk downloader deletion is allowed.
- Import exclusions remain false.
- No Jellyfin delete endpoint exists.
