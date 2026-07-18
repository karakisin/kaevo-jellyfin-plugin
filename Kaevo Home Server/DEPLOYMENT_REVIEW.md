# K62 Home Server Deployment Review

This review intentionally does not edit `/mnt/HomeLab/AppData/StageDoorV2/app`
and does not restart `stagedoor-v2`.

## Selected Deployment Model

Use a sidecar service first.

Reason: the deployed StageDoorV2 source and container are not visible from the
current development machine, and the existing `stagedoor-v2` service owns port
8099 plus the media API routes used by iOS and tvOS. A sidecar on a separate
port lets K62 provider orchestration be verified without risking `/api/home`,
`/api/image/{id}`, `/api/item/{id}`, episode, trailer, or playback behavior.

## Persistent Paths

Recommended release root:

`/mnt/HomeLab/AppData/KaevoHomeServer/releases/<version>/`

Recommended current symlink:

`/mnt/HomeLab/AppData/KaevoHomeServer/current`

Recommended persistent data directory:

`/mnt/HomeLab/AppData/KaevoHomeServer/data`

The data directory stores:

- `operations.sqlite3`
- `provider_credentials.json`
- future migration metadata

## Required Environment Variables

- `KAEVO_HOME_SERVER_DATA_DIR`
- `KAEVO_HOME_SERVER_SECRET_KEY`
- `KAEVO_HOME_SERVER_IOS_TOKEN`

Generate values on the NAS with:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

Do not paste generated values into logs or source files.

## TrueNAS Read-Only Inspection Commands

Run these on the NAS before deployment:

```bash
docker inspect stagedoor-v2 > /tmp/stagedoor-v2.inspect.json
python3 - <<'PY'
import json
c=json.load(open('/tmp/stagedoor-v2.inspect.json'))[0]
print('image', c['Config'].get('Image'))
print('entrypoint', c['Config'].get('Entrypoint'))
print('cmd', c['Config'].get('Cmd'))
print('workdir', c['Config'].get('WorkingDir'))
print('ports', c['NetworkSettings'].get('Ports'))
print('restart', c['HostConfig'].get('RestartPolicy'))
print('network', c['HostConfig'].get('NetworkMode'))
print('mounts')
for m in c.get('Mounts', []):
    print(m.get('Type'), m.get('Source'), '->', m.get('Destination'), 'rw=', m.get('RW'))
print('env names')
for e in c['Config'].get('Env') or []:
    print(e.split('=', 1)[0])
PY
find /mnt/HomeLab/AppData/StageDoorV2/app -maxdepth 2 -type f | sed 's#^#/file #'
```

Do not print environment values.

## Backup Commands

```bash
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/mnt/HomeLab/AppData/StageDoorV2/backups/$TS"
mkdir -p "$BACKUP"
cp -a /mnt/HomeLab/AppData/StageDoorV2/app "$BACKUP/app"
docker inspect stagedoor-v2 > "$BACKUP/stagedoor-v2.inspect.json"
docker image inspect "$(docker inspect -f '{{.Image}}' stagedoor-v2)" > "$BACKUP/stagedoor-v2.image.json"
```

## Sidecar Deployment Commands

These are approval-gated. Do not run before Jefferson approves.

```bash
VERSION="k62-$(date -u +%Y%m%dT%H%M%SZ)"
ROOT="/mnt/HomeLab/AppData/KaevoHomeServer"
RELEASE="$ROOT/releases/$VERSION"
mkdir -p "$RELEASE" "$ROOT/data"

# Copy the reviewed local source into $RELEASE by rsync/scp from the Mac.
# Example from the Mac:
# rsync -av --delete "/Users/jeffersonsumagang/Developer/StageDoorNative/Kaevo Home Server/" \
#   "truenas:$RELEASE/"

ln -sfn "$RELEASE" "$ROOT/current"
cd "$ROOT/current"
docker build -t kaevo-home-server:"$VERSION" .
docker rm -f kaevo-home-server-k62 2>/dev/null || true
docker run -d \
  --name kaevo-home-server-k62 \
  --restart unless-stopped \
  -p 8100:8100 \
  -e KAEVO_HOME_SERVER_DATA_DIR=/data \
  -e KAEVO_HOME_SERVER_SECRET_KEY="$KAEVO_HOME_SERVER_SECRET_KEY" \
  -e KAEVO_HOME_SERVER_IOS_TOKEN="$KAEVO_HOME_SERVER_IOS_TOKEN" \
  -v "$ROOT/data:/data" \
  kaevo-home-server:"$VERSION"
```

## Non-Destructive Verification

```bash
curl -fsS http://127.0.0.1:8100/api/v1/status
curl -fsS http://127.0.0.1:8100/openapi.json | python3 -m json.tool >/tmp/kaevo-openapi.json
curl -fsS http://127.0.0.1:8099/api/home >/tmp/stagedoor-home.json
curl -fsS http://127.0.0.1:8100/api/v1/providers/audit
curl -i -X POST http://127.0.0.1:8100/api/v1/removals/plan \
  -H 'Content-Type: application/json' \
  -d '{"requestCorrelationId":"auth-check","seerrRequestId":1,"mediaType":"movie","tmdbId":1,"requestedMode":"keepMedia"}'
curl -i -X POST http://127.0.0.1:8100/api/v1/removals/plan \
  -H "X-Kaevo-Home-Server-Token: $KAEVO_HOME_SERVER_IOS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"requestCorrelationId":"auth-check","seerrRequestId":1,"mediaType":"movie","tmdbId":1,"requestedMode":"keepMedia"}'
```

The unauthenticated mutation request should fail when the token is configured.

## Rollback

Sidecar rollback does not alter `stagedoor-v2`:

```bash
docker rm -f kaevo-home-server-k62
curl -fsS http://127.0.0.1:8099/api/home >/tmp/stagedoor-home-after-rollback.json
docker inspect stagedoor-v2 >/tmp/stagedoor-v2.after-rollback.inspect.json
```

If a future merge into `stagedoor-v2` is approved, use the timestamped backup
under `/mnt/HomeLab/AppData/StageDoorV2/backups/<timestamp>/` to restore source
and container configuration before restarting the original service.
