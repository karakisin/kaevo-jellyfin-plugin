# Provider Integrations — Seerr, Sonarr, Radarr

## Product Rule

Provider connections should be optional.

Kaevo should work with Jellyfin alone first.

## Provider Priority

Jellyfin:
- Available library content
- Users
- Libraries
- Watch progress
- Playback state
- Media metadata

Seerr:
- Discovery
- Trending
- Requests
- Request status
- Cast/person pages later

Sonarr:
- Show automation
- Queue status
- Failed show download recovery later
- Search-again actions later

Radarr:
- Movie automation
- Queue status
- Failed movie download recovery later
- Search-again actions later

## Phase 1 Scope

Build:
- Provider settings model
- Provider health check interface
- Redacted provider status
- UI placeholders

Do not build yet:
- Automatic requests
- Failed download fixes
- Queue mutation
- Blocklist mutation
- Search-again mutation
- Provider configuration changes

## Secret Handling

Provider secrets must stay server-side.

The Apple app must never receive:
- Seerr API key
- Sonarr API key
- Radarr API key
- TMDb API key
- Jellyfin admin token
