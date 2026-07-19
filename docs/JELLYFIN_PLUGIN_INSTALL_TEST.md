# Kaevo Jellyfin Plugin Install and Test

## 1. Validate scripts on the Mac

```bash
cd "/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Jellyfin Plugin"
bash -n scripts/build-plugin-docker.sh
bash -n scripts/package-plugin.sh
bash -n scripts/install-plugin-to-truenas.sh
```

## 2. Build and package with Docker

```bash
scripts/build-plugin-docker.sh
scripts/package-plugin.sh
```

Expected artifacts:

- `artifacts/build/Kaevo.Plugin.KaevoForJellyfin.dll`
- `artifacts/package/Kaevo/`
- `artifacts/package/Kaevo.Plugin.KaevoForJellyfin.zip`

Host `dotnet` is not required. TrueNAS does not share the Mac `/Users` path, so
the plugin must be built on the Mac before installation.

## 3. Install

Preferred: install Kaevo from the Jellyfin plugin catalog and restart Jellyfin.

Direct-install fallback:

```bash
scripts/install-plugin-to-truenas.sh root@192.168.68.203
```

The script backs up an existing plugin directory before replacement.

## 4. Verify the read-only endpoints

```bash
curl -fsS http://192.168.68.203:30013/kaevo/status | jq
curl -fsS http://192.168.68.203:30013/kaevo/media-scan | jq
curl -fsS http://192.168.68.203:30013/kaevo/main-snapshot | jq
```

Confirm:

- Status is `ok` and the plugin version is present.
- Scan counts are plausible for the Jellyfin library.
- Snapshot sections are bounded.
- Item IDs and image tags may be present.
- No image binaries, stream URLs, media paths, API keys, tokens, or passwords
  appear.

## Current phase boundary

- No Cloud relay validation.
- No playback relay validation.
- No remote mutations.
- No real-media optimizer execution.

## Rollback

Uninstall Kaevo in Jellyfin, restart Jellyfin, and restore the most recent plugin
backup only if needed. Removing the plugin does not delete the media library.
