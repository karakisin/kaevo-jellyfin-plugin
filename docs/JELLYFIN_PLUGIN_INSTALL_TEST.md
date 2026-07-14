# Jellyfin Plugin Install and Test

Run all build commands on the Mac from:

```bash
cd "/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Jellyfin Plugin"
```

## Validate, build, and package

```bash
bash -n scripts/build-plugin-docker.sh
bash -n scripts/package-plugin.sh
bash -n scripts/install-plugin-to-truenas.sh
scripts/build-plugin-docker.sh
scripts/package-plugin.sh
```

## Install to TrueNAS

### Jellyfin Catalog installation

In Jellyfin, open **Dashboard → Plugins → Repositories**, add a repository named
`Kaevo`, and use this URL:

```text
https://raw.githubusercontent.com/karakisin/kaevo-jellyfin-plugin/main/manifest.json
```

Save it, open **Catalog**, search for `Kaevo`, press **Install**, and restart
Jellyfin when prompted.

### Direct installation fallback

The installer streams the packaged `Kaevo` directory over SSH, discovers the
running Docker container whose name or image contains `jellyfin`, copies the
plugin to `/config/plugins/Kaevo`, and restarts that container.

```bash
scripts/install-plugin-to-truenas.sh root@192.168.68.203
```

If the TrueNAS SSH account is not `root`, pass the correct SSH destination. It
must have permission to run Docker commands. This script assumes the current
TrueNAS Apps Docker runtime and a Jellyfin `/config` mount.

After the restart, confirm that **Kaevo 0.1.1** appears in Jellyfin Dashboard →
Plugins. Check the Jellyfin log if the plugin is not listed.

## Test

```bash
curl --fail-with-body --silent --show-error \
  http://192.168.68.203:30013/kaevo/status | jq

curl --fail-with-body --silent --show-error \
  http://192.168.68.203:30013/kaevo/media-scan | jq

curl --fail-with-body --silent --show-error \
  http://192.168.68.203:30013/kaevo/main-snapshot | jq
```

If Jellyfin requires authentication for plugin controller routes, add:

```bash
-H "X-Emby-Token: YOUR_JELLYFIN_API_KEY"
```

Do not put an API key in the plugin configuration or source tree.
