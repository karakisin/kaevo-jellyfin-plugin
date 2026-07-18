# Kaevo Local Bridge Contract — Future Home Server Worker

## Purpose

The Kaevo Local Bridge is the future home-server component that actually inspects, prepares, previews, and serves Travel Downloads. It can run beside Jellyfin on TrueNAS, Unraid, Synology, Docker, Mac, Windows, or Linux.

Kaevo Cloud does not host or transcode media.

## Local Bridge responsibilities

- Inspect selected media.
- Report source resolution, runtime, codecs, and estimated original size.
- Generate local-only preview frames later.
- Prepare mobile-friendly 480p/720p/1080p versions.
- Validate output duration and file integrity.
- Serve the prepared file directly to the iPhone.
- Clean up temporary Travel Download files after user-approved retention rules.

## Non-goals

The Local Bridge must not:

- expose arbitrary file browsing
- run arbitrary shell commands from Cloud
- delete original media
- change Jellyfin library paths
- change Sonarr/Radarr settings
- expose provider API keys to the Apple app

## Suggested endpoints

Base path:

```text
/v1
```

### GET `/health`

Response:

```json
{
  "state": "ok",
  "version": "0.1.0",
  "serverId": "server_home_123",
  "capabilities": ["inspect", "estimate", "prepare", "download", "preview"]
}
```

### POST `/media/inspect`

Request:

```json
{
  "mediaProvider": "jellyfin",
  "mediaItemId": "jellyfin_item_123"
}
```

Response:

```json
{
  "mediaProvider": "jellyfin",
  "mediaItemId": "jellyfin_item_123",
  "mediaType": "movie",
  "sourceHeight": 1080,
  "sourceWidth": 1920,
  "durationSeconds": 7200,
  "sourceSizeBytes": 18000000000,
  "videoCodec": "h264",
  "audioCodec": "eac3",
  "container": "mkv",
  "isHdr": false,
  "isDolbyVision": false,
  "availableQualities": ["p480", "p720", "original"]
}
```

### POST `/travel-downloads/estimate`

Request:

```json
{
  "mediaItemId": "jellyfin_item_123",
  "qualities": ["p480", "p720", "original"],
  "observedBytesPerSecond": 8000000
}
```

Response:

```json
{
  "estimates": [
    {
      "quality": "p480",
      "estimatedSizeBytes": 1100000000,
      "estimatedPrepareSeconds": 900,
      "estimatedDownloadSeconds": 138,
      "confidence": "medium"
    }
  ]
}
```

### POST `/travel-downloads/prepare`

Starts local preparation.

Request:

```json
{
  "jobId": "td_job_123",
  "mediaProvider": "jellyfin",
  "mediaItemId": "jellyfin_item_123",
  "requestedQuality": "p720",
  "profileId": "profile_abc",
  "deviceId": "device_iphone_123"
}
```

Response:

```json
{
  "jobId": "td_job_123",
  "status": "preparing",
  "progress": 0.0
}
```

### GET `/travel-downloads/{jobId}/status`

Response:

```json
{
  "jobId": "td_job_123",
  "status": "readyToDownload",
  "progress": 1.0,
  "preparedSizeBytes": 3000000000,
  "expiresAt": "2026-07-10T00:00:00Z"
}
```

### GET `/travel-downloads/{jobId}/file`

Serves the prepared file directly to the requesting device. This endpoint must support range requests and resumable downloads.

Requirements:

- support `Range` headers
- support `ETag` or equivalent validation
- send content length
- token-gated access
- expire prepared download tokens

### GET `/travel-downloads/{jobId}/preview?quality=p720`

Future feature. Returns local-only preview frame. Do not route through Kaevo Cloud.

### POST `/travel-downloads/{jobId}/cancel`

Cancels preparation or marks a ready file for cleanup.

### POST `/travel-downloads/{jobId}/cleanup`

Cleans prepared temporary files only when user policy allows it.

## Preparation validation

Before marking a prepared file ready, validate:

- output file exists
- output file size is non-zero
- output duration roughly matches source duration
- output is readable
- output does not overwrite original media
- output path is inside the configured Travel Downloads temp directory

## Suggested temp directory

```text
<KAEVO_APP_DATA>/travel_downloads/prepared
```

Never write into the main Jellyfin library unless the user explicitly chooses a future advanced mode.

## Relationship to existing StageDoor/FastAPI work

The current project already has a Docker/FastAPI-style foundation pattern with a health/status endpoint and scanner-style background worker. The Local Bridge can follow that same style later: FastAPI server plus background preparation jobs. Keep the first Local Bridge simple and observable.
