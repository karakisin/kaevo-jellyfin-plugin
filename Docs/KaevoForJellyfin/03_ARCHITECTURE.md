# Architecture — Kaevo for Jellyfin

## Desired User Experience

One install:
Kaevo for Jellyfin Plugin

Behind the scenes:
The plugin has modules for Jellyfin, Kaevo Cloud pairing, local API, provider integrations, scans, and future media prep orchestration.

## High-Level Architecture

Kaevo iOS/tvOS
    |
    v
Kaevo Cloud
    |
    v
Kaevo for Jellyfin Plugin
    |
    +--> Jellyfin users/libraries/items/progress
    +--> Optional Seerr
    +--> Optional Sonarr
    +--> Optional Radarr
    +--> Optional future local media worker

## Plugin Modules

1. Setup Module
- First-run wizard
- Pairing code
- Selected users
- Selected libraries
- Setup complete state
- Diagnostics

2. Jellyfin Bridge Module
- Read Jellyfin users
- Read Jellyfin libraries
- Read item metadata
- Read watch progress
- Read media source/container/codec metadata when available
- Never modify media in Phase 1

3. Kaevo Local API Module
- Expose Kaevo endpoints from the plugin
- Return status to Kaevo apps
- Return selected users/libraries
- Return scan state
- Return provider health

4. Cloud Pairing Module
- Generate pairing state
- Register server with Kaevo Cloud
- Store non-sensitive cloud pairing metadata
- Never upload user media

5. Provider Module
- Optional Seerr connection
- Optional Sonarr connection
- Optional Radarr connection
- Health checks
- Store secrets server-side only
- Never expose secrets to Apple apps

6. Scan Module
- Run safe read-only compatibility scans
- Store scan summary
- Detect likely playback/download compatibility
- No file writes in Phase 1

7. Future Media Worker Module
- Coordinate heavy jobs later
- Check if FFmpeg exists later
- Check if media path is writable later
- Possibly manage an optional sidecar worker later

## Cloud Boundary

Kaevo Cloud may store:
- Server ID
- User-selected settings
- Entitlement status
- Device registrations
- Pairing state
- Job metadata
- Non-sensitive scan summaries

Kaevo Cloud must not store:
- User media
- Media files
- Streams
- Transcoded output
- Raw provider API keys in Apple app
- Full raw logs with secrets

## Apple App Boundary

The Apple app should not store:
- Seerr API keys
- Sonarr API keys
- Radarr API keys
- TMDb API keys
- Jellyfin admin tokens
