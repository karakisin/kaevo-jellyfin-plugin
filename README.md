# Kaevo Jellyfin Plugin

Kaevo 0.2.0 is the only home-side component required by Kaevo Cloud. The plugin
runs inside Jellyfin 10.11.x and maintains outbound-only authenticated
connections to the Kaevo control plane and playback relay. There is no separate
Kaevo Home Server service.

## Architecture

```text
Kaevo iOS → Kaevo Cloud/relay ← outbound Kaevo Jellyfin Plugin → Jellyfin/FFmpeg
```

- Jellyfin, FFmpeg, and the home server perform direct play, live remux, and
  live transcoding.
- Kaevo Cloud carries bounded metadata, artwork, commands, and encrypted
  transport traffic. It does not receive provider credentials or filesystem
  paths and does not transcode media.
- Jellyfin is not exposed with router port forwarding.
- The plugin locally revalidates every command and playback request.

## Capabilities and safeguards

- Bounded metadata and artwork retrieval.
- Favorite/unfavorite and played/unplayed writes, disabled by default.
- Device-, profile-, connector-, item-, media-source-, session-, mode-, and
  bitrate-bound playback grants.
- Strict Jellyfin playback route and query allowlists.
- Outbound WebSocket relay with 256 KiB chunks and HLS URL rewriting.
- Bounded read-only media scan.
- One-item optimizer planning, disabled by default.
- Real-media optimizer execution is unconditionally disabled in 0.2.0.
- Connector credentials are stored locally with owner-only file permissions.

## Install from the Jellyfin Catalog

Add this repository in **Dashboard → Plugins → Repositories**:

```text
https://raw.githubusercontent.com/karakisin/kaevo-jellyfin-plugin/main/manifest.json
```

Open **Catalog**, search for **Kaevo**, install it, and restart Jellyfin.

## Compatibility and build

- Plugin target: `net8.0`
- Jellyfin target: `10.11.x`
- Docker SDK: `mcr.microsoft.com/dotnet/sdk:8.0`
- No host `dotnet` installation is required.

```bash
cd "/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Jellyfin Plugin"
scripts/test-plugin-docker.sh
scripts/build-plugin-docker.sh
scripts/package-plugin.sh
```

## Configuration

The Jellyfin application must receive its API key as a secret environment
variable. Never put it in source control or the plugin configuration page.

```text
KAEVO_JELLYFIN_API_KEY=<Jellyfin API key scoped to this server>
```

In **Dashboard → Plugins → Kaevo** configure the HTTPS Cloud URL, WSS relay
URL, Kaevo profile ID, connector ID, one-time pairing code, loopback Jellyfin
URL, and Jellyfin user ID. Enable writes and playback only after the connector
shows online.

## Local diagnostic endpoints

- `GET /kaevo/status`
- `GET /kaevo/cloud/status`
- `GET /kaevo/media-scan`
- `GET /kaevo/main-snapshot`

These endpoints never return connector tokens, pairing codes, playback grants,
Jellyfin API keys, or local media paths.

See [docs/JELLYFIN_PLUGIN_INSTALL_TEST.md](docs/JELLYFIN_PLUGIN_INSTALL_TEST.md)
for installation, pairing, validation, and rollback.

## License

GPL-3.0. See [LICENSE](LICENSE).
