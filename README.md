# Kaevo Jellyfin Plugin

The Kaevo Jellyfin Plugin is the local foundation for Kaevo. It runs inside the
user's existing Jellyfin server and gives the Kaevo app bounded, read-only
metadata access without requiring a separate Kaevo server installation.

## Current scope

- Jellyfin: `10.11.x`
- .NET target: `net8.0`
- Foundation baseline: `0.1.0`
- Current repository build: `0.2.18`
- Supported phase: local metadata, app-guided Cloud activation, and guarded remote playback

Current endpoints:

- `GET /kaevo/status`
- `GET /kaevo/media-scan`
- `GET /kaevo/main-snapshot`
- `POST /kaevo/cloud/activate` (authenticated Jellyfin administrator only)
- `GET /kaevo/providers/status` (authenticated Jellyfin administrator only)
- `POST /kaevo/providers/{provider}` (authenticated Jellyfin administrator only)

The snapshot may contain libraries, movies, shows, collections, Continue
Watching items, item IDs, and image tags. It does not return image binaries,
stream URLs, provider secrets, or local credentials.

The Kaevo app can activate the plugin without asking the user for a Cloud URL,
pairing code, or TrueNAS environment credential. Playback stays on the Jellyfin
server: compatible video is copied directly and unsupported audio can be
transcoded to AAC before secure delivery. Remote mutations and optimizer
execution remain disabled.

The plugin settings page can privately store and independently enable local
connections for Sonarr, Radarr, Seerr, Lidarr, Readarr, Prowlarr, Bazarr, and
Tdarr. API keys and local addresses remain on the Jellyfin server. Sonarr
missing-episode search, progress, cancellation, and guarded removal are the
first active provider workflow; the other connections are foundations for the
next provider-specific features.

Kaevo can independently verify Local, DNS / Proxy, and Cloud connectivity for
each supported service. The Cloud check travels through Kaevo Cloud to this
plugin and then performs a bounded read-only health request on the home network.

## Install from the Jellyfin catalog

Add this repository in **Dashboard → Plugins → Repositories**:

```text
https://raw.githubusercontent.com/karakisin/kaevo-jellyfin-plugin/main/manifest.json
```

Open **Catalog**, find **Kaevo**, install it, and restart Jellyfin.

## Build on the Mac

The Mac has Docker and does not require host `dotnet`. The build script uses the
.NET 8 SDK container.

```bash
cd "/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Jellyfin Plugin"
bash -n scripts/build-plugin-docker.sh
bash -n scripts/package-plugin.sh
bash -n scripts/install-plugin-to-truenas.sh
scripts/build-plugin-docker.sh
scripts/package-plugin.sh
```

Artifacts:

- `artifacts/build/Kaevo.Plugin.KaevoForJellyfin.dll`
- `artifacts/package/Kaevo/`
- `artifacts/package/Kaevo.Plugin.KaevoForJellyfin.zip`

TrueNAS cannot access the Mac's `/Users/...` path. Build and package on the Mac,
then copy or install the finished artifact to Jellyfin.

See [docs/JELLYFIN_PLUGIN_INSTALL_TEST.md](docs/JELLYFIN_PLUGIN_INSTALL_TEST.md)
for installation and validation.

## License

GPL-3.0. See [LICENSE](LICENSE).
