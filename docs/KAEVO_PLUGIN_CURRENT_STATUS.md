# Kaevo Plugin Current Status

Updated: 2026-07-14

## Foundation

- Plugin name: Kaevo
- Jellyfin target: `10.11.x`
- .NET target: `net8.0`
- Foundation version: `0.1.0`
- Current repository version: `0.2.6`

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
- `GET /kaevo/media-scan`
- `GET /kaevo/main-snapshot`
- `POST /kaevo/cloud/activate` (authenticated Jellyfin administrator only)

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
- Remote writes, remote playback, and optimizer execution are forced off.

## Current product boundary

Remote playback, remote mutations, and real-media optimizer execution remain
outside the supported phase.

## Next validation

Run the Docker build and package scripts, install through the Jellyfin catalog,
restart Jellyfin, then validate all three endpoints from the local network.
