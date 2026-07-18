# Product Spec — Kaevo for Jellyfin

## Feature Name

Kaevo for Jellyfin

## Product Goal

Make Kaevo easy for self-hosted Jellyfin users by giving them a single installable plugin that connects their Jellyfin server to Kaevo.

The ideal user experience:

1. User opens Jellyfin Dashboard.
2. User adds the Kaevo plugin repository.
3. User installs Kaevo for Jellyfin.
4. User restarts Jellyfin.
5. User opens the Kaevo setup page.
6. User pairs the server with Kaevo.
7. User chooses Jellyfin users/profiles.
8. User chooses libraries.
9. User optionally connects Seerr, Sonarr, and Radarr.
10. User finishes setup.

## Why Plugin First

A Jellyfin plugin is the lowest-friction install path.

A separate Docker companion can still be useful later, but only for heavy media prep. It should not be required for the basic Kaevo experience.

## Primary Jobs

Kaevo for Jellyfin should:

- Pair Jellyfin with Kaevo
- Read Jellyfin users
- Read Jellyfin libraries
- Map Jellyfin users to Kaevo profiles
- Report server status
- Expose a local Kaevo API
- Run safe read-only checks
- Prepare for Travel Downloads
- Prepare for Smart Download Recovery
- Prepare for Seerr/Sonarr/Radarr connections

## Phase 1 Non-Goals

Do not implement:

- Real downloads
- Real transcoding
- FFmpeg jobs
- MKV to MP4 conversion
- Automatic deletion
- Sonarr/Radarr write actions
- Provider secret storage in the Apple app
- Direct third-party API keys in iOS/tvOS
- Cloud media hosting
- Cloud media streaming
