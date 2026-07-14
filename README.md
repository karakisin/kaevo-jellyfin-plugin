# Kaevo Jellyfin Plugin

Kaevo 0.1.1 is a small, local, read-only metadata plugin for Jellyfin 10.11.x.
It exposes status, library counts, and a bounded home-screen snapshot. It does
not connect to Kaevo Cloud, AWS, or any relay service.

## Install from the Jellyfin Catalog

Add the Kaevo repository in **Dashboard → Plugins → Repositories**:

```text
https://raw.githubusercontent.com/karakisin/kaevo-jellyfin-plugin/main/manifest.json
```

Then open **Catalog**, search for **Kaevo**, select it, and press **Install**.
Restart Jellyfin when prompted. The catalog repository is third-party and must
be added once before Kaevo appears in search.

## Compatibility

- Plugin target framework: `net8.0`
- Intended server: Jellyfin `10.11.x`
- Build environment: Docker image `mcr.microsoft.com/dotnet/sdk:8.0`
- API compile contract: Jellyfin `10.10.7` (the final Jellyfin API line that
  targets .NET 8). Jellyfin 10.11 itself targets .NET 9, whose runtime can load
  this `net8.0` plugin. Test against the exact installed 10.11 server release.

## Build and package on the Mac

```bash
cd "/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Jellyfin Plugin"
scripts/build-plugin-docker.sh
scripts/package-plugin.sh
```

No host installation of `dotnet` is used or required.

Build output is written to `artifacts/build/`. The installable directory and
archive are written to `artifacts/package/Kaevo/` and
`artifacts/package/Kaevo.Plugin.KaevoForJellyfin.zip`.

## Endpoints

- `GET /kaevo/status`
- `GET /kaevo/media-scan`
- `GET /kaevo/main-snapshot`

The snapshot caps each item section at 50 by default (hard maximum 100). It
contains metadata, item IDs, and image cache tags only. It never returns image
binaries, stream URLs, provider credentials, or provider IDs.

See [docs/JELLYFIN_PLUGIN_INSTALL_TEST.md](docs/JELLYFIN_PLUGIN_INSTALL_TEST.md)
for installation and test commands.

## License

Kaevo Jellyfin Plugin is licensed under GPL-3.0. See [LICENSE](LICENSE).
