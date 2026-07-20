# Kaevo Plugin Current Status

Updated: 2026-07-20

## Foundation

- Plugin name: Kaevo
- Jellyfin target: `10.11.x`
- .NET target: `net8.0`
- Foundation version: `0.1.0`
- Current repository candidate: `0.2.54`
- `0.2.54` makes every Media Services provider toggle use the same large,
  left-aligned checkbox, spacing, and label treatment as Media Management.
- `0.2.53` adds embedded transparent Kaevo logo and wordmark assets, a concise
  privacy boundary, aligned configuration cards, and the live single-use pairing
  countdown. Live installation remains a separate operator action.
- `0.2.28` keeps relay protocol `hls-bounded-buffer-v3`, advertises an Apple-compatible H.264/HEVC + AAC HLS profile, and permits only media-source-bound subtitle resources.
- Multi-language audio selection restarts the approved HLS item at the same playhead with Jellyfin's selected stream index. Text subtitles are fetched as grant-bound WebVTT and rendered without replacing the active video session.

## Files created for the foundation

- `src/Kaevo.Plugin.KaevoForJellyfin/Kaevo.Plugin.KaevoForJellyfin.csproj`
- `src/Kaevo.Plugin.KaevoForJellyfin/KaevoPlugin.cs`
- `src/Kaevo.Plugin.KaevoForJellyfin/Api/KaevoController.cs`
- `src/Kaevo.Plugin.KaevoForJellyfin/Configuration/PluginConfiguration.cs`
- `src/Kaevo.Plugin.KaevoForJellyfin/Configuration/configPage.html`
- `src/Kaevo.Plugin.KaevoForJellyfin/Models/KaevoModels.cs`
- `scripts/build-plugin-docker.sh`
- `scripts/package-plugin.sh`
- `scripts/install-plugin-to-truenas.sh`

## Current endpoints

- `GET /kaevo/status`
- `GET /kaevo/branding/{logo|wordmark}` (local embedded public artwork only)
- `POST /kaevo/local-pairing/start` (elevated Jellyfin administrator only)
- `POST /kaevo/local-pairing/claim` (elevated Jellyfin administrator only)
- `GET /kaevo/media-scan`
- `GET /kaevo/main-snapshot`
- `POST /kaevo/cloud/activate` (authenticated Jellyfin administrator only)
- `GET /kaevo/providers/status` (authenticated Jellyfin administrator only)
- `POST /kaevo/providers/{provider}` (authenticated Jellyfin administrator only)

These endpoints provide bounded, read-only metadata. They do not provide image
binaries, stream URLs, provider secrets, or credentials.

## Current build limitation

The Mac does not have host `dotnet`. Builds must use the .NET 8 SDK Docker image.
TrueNAS cannot read the Mac `/Users` path, so only the completed package can be
copied or installed there.

## Cloud activation

- The Kaevo iOS app creates and exchanges pairing material automatically.
- Users do not enter Cloud URLs, pairing codes, or server environment credentials.
- The Jellyfin credential is stored only in the plugin's owner-only secret file.
- Remote playback uses short-lived device-bound authorization and a bounded active session.
- Jellyfin can locally transcode unsupported audio to AAC while copying compatible video.
- Playback started, progress, and stopped commands report Kaevo playback to
  Jellyfin session endpoints.
- Remote writes and optimizer execution remain off.

## User-facing privacy boundary

- Jellyfin passwords, provider API keys, local addresses, and media remain on
  the home server.
- Kaevo Cloud coordinates authenticated owner sign-in, device pairing,
  connector status, and approved Kaevo actions through this plugin.
- Kaevo Cloud does not receive Jellyfin passwords, provider credentials, media
  files, or unrestricted access to the home network.
- Official logo and wordmark artwork are embedded in the plugin assembly and
  served locally; the settings page does not depend on an external asset host.
- Local pairing tickets expire after ten minutes and are single-use.

## Local media services

- Administrators can independently connect or disable Sonarr, Radarr, Seerr,
  Lidarr, Readarr, Prowlarr, Bazarr, and Tdarr from the plugin settings page.
- Local addresses and API keys stay in the plugin's owner-only secret file.
- Sonarr missing-episode search, live queue progress, cancellation, and guarded
  removal are active. The remaining connections are ready for later workflows.

## Current product boundary

Remote playback is supported through the plugin-backed secure path. Remote
mutations and real-media optimizer execution remain outside the supported phase.

## Next validation

Update to `0.2.53`, restart Jellyfin, hard-refresh the plugin
page, and verify the transparent brand lockup, aligned cards, privacy summary,
centered pairing ticket, live countdown, and single-use expiration behavior.
