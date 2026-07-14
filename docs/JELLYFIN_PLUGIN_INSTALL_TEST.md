# Kaevo 0.2.0 Install, Pair, and Test

## 1. Validate and package on the Mac

```bash
cd "/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Jellyfin Plugin"
bash -n scripts/build-plugin-docker.sh
bash -n scripts/package-plugin.sh
bash -n scripts/install-plugin-to-truenas.sh
bash -n scripts/test-plugin-docker.sh
scripts/test-plugin-docker.sh
scripts/build-plugin-docker.sh
scripts/package-plugin.sh
```

## 2. Install

Catalog URL:

```text
https://raw.githubusercontent.com/karakisin/kaevo-jellyfin-plugin/main/manifest.json
```

Direct-install fallback:

```bash
scripts/install-plugin-to-truenas.sh root@192.168.68.203
```

Restart Jellyfin and confirm **Kaevo 0.2.0** appears under Plugins.

## 3. Add the local Jellyfin secret

Create a dedicated Jellyfin API key. Add it to the Jellyfin TrueNAS application
as a secret environment variable, then restart Jellyfin:

```text
KAEVO_JELLYFIN_API_KEY=<secret value>
```

The plugin accepts only a loopback local Jellyfin URL. The key is injected only
into local requests and is never sent to Cloud or the playback relay.

## 4. Pair

Create a connector pairing code from Kaevo Cloud/iOS. In Jellyfin open
**Dashboard → Plugins → Kaevo** and enter:

- Cloud API URL (`https://...`)
- Relay WebSocket URL (`wss://...`)
- Kaevo profile ID
- Connector ID
- One-time pairing code
- Local Jellyfin URL (`http://127.0.0.1:8096` by default)
- Jellyfin user ID

Enable the connector and metadata, save, and wait for `/kaevo/cloud/status` to
report `online`. The pairing code is cleared after exchange.

## 5. Verify local endpoints

```bash
curl -fsS http://192.168.68.203:30013/kaevo/status | jq
curl -fsS http://192.168.68.203:30013/kaevo/cloud/status | jq
curl -fsS http://192.168.68.203:30013/kaevo/media-scan | jq
curl -fsS http://192.168.68.203:30013/kaevo/main-snapshot | jq
```

Expected: version `0.2.0`, connector `online`, recent heartbeat, bounded counts,
and no secrets or filesystem paths.

## 6. Enable capabilities progressively

1. Metadata and artwork.
2. Remote playback.
3. Reversible writes.
4. Optimizer planning.

Verify iOS on cellular after each step. Favorite/unfavorite is the recommended
first write test because it is reversible. Do not enable or test real-media
optimizer execution in 0.2.0.

## 7. Playback verification

From the Kaevo iOS app on cellular, start one known test item. Confirm:

- Jellyfin Dashboard shows the playback session.
- Jellyfin/FFmpeg performs direct play, remux, or transcode locally.
- Seeking works.
- The iOS URL points to the Kaevo relay, not the LAN address.
- Jellyfin, connector, and relay logs contain no API key or grant URL.

## 8. Rollback

Disable **Kaevo Cloud connector** in plugin settings and restart Jellyfin. This
stops all outbound activity while retaining the local diagnostic endpoints.
For complete removal, uninstall Kaevo from Jellyfin and delete its plugin data
directory after making a backup. Revoking the connector in Cloud invalidates
the stored connector token.
