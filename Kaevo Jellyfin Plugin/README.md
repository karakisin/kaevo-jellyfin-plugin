# Kaevo Jellyfin Plugin

The Kaevo Jellyfin Plugin is the local foundation for Kaevo. It runs inside the
user's existing Jellyfin server and gives the Kaevo app bounded metadata access
and explicitly authorized controls without requiring a separate Kaevo server
installation.

## Current scope

- Jellyfin: `10.11.x`
- .NET target: `net8.0`
- Foundation baseline: `0.1.0`
- Current repository build: `0.2.95`
- Supported phase: local metadata, app-guided Cloud activation, guarded remote playback, and owner-authorized download controls

Current endpoints:

- `GET /kaevo/status`
- `GET /kaevo/branding/{logo|wordmark}`
- `POST /kaevo/local-pairing/start` (elevated Jellyfin administrator only)
- `POST /kaevo/local-pairing/claim` (elevated Jellyfin administrator only)
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
transcoded to AAC before secure delivery. Unbounded remote mutations and remote
optimizer execution remain disabled.

The plugin settings page can privately store and independently enable local
connections for Sonarr, Radarr, Seerr, Lidarr, Readarr, Prowlarr, Bazarr,
Tdarr, SABnzbd, and qBittorrent. API keys, download-client credentials, and
local addresses remain on the Jellyfin server. SABnzbd and qBittorrent expose
bounded health and queue reads. An authorized household owner can start or pause
only an exact queue job after the plugin verifies its immutable Arr client ID,
configured endpoint, and downloader job. Kaevo Cloud cannot submit or remove
downloads through these integrations.

## Privacy boundary

The plugin keeps Jellyfin credentials, provider API keys, local service
addresses, and media on the home server. Kaevo Cloud coordinates owner sign-in,
device pairing, connector status, and explicitly approved Kaevo actions through
the plugin. It does not receive the user's Jellyfin password, provider
credentials, media files, or unrestricted access to the home network.

The configuration page uses embedded transparent Kaevo logo and wordmark assets;
it does not contact an external image host. Its local pairing QR code and
one-time code expire after ten minutes and can be used only once.

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
