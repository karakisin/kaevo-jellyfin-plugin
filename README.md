# Kaevo Jellyfin Plugin

The Kaevo Jellyfin Plugin is the local foundation for Kaevo. It runs inside the
user's existing Jellyfin server and gives the Kaevo app bounded, read-only
metadata access without requiring a separate Kaevo server installation.

## Current scope

- Jellyfin: `10.11.x`
- .NET target: `net8.0`
- Foundation baseline: `0.1.0`
- Current repository build: `0.2.1`
- Supported phase: local metadata plus app-guided Cloud activation

Current endpoints:

- `GET /kaevo/status`
- `GET /kaevo/media-scan`
- `GET /kaevo/main-snapshot`
- `POST /kaevo/cloud/activate` (authenticated Jellyfin administrator only)

The snapshot may contain libraries, movies, shows, collections, Continue
Watching items, item IDs, and image tags. It does not return image binaries,
stream URLs, provider secrets, or local credentials.

The Kaevo app can activate the plugin without asking the user for a Cloud URL,
pairing code, or TrueNAS environment credential. Remote playback, remote
mutations, and optimizer execution remain disabled in this release.

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