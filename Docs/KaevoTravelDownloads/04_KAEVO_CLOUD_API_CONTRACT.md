# Kaevo Cloud API Contract — Travel Downloads

## Rule

Kaevo Cloud stores metadata only. No media files, preview frames, or transcoded files should be uploaded to Cloud.

## Settings endpoints

### GET `/profiles/{profileId}/settings/travel-downloads`

Returns Travel Download settings for a profile.

Response:

```json
{
  "travelDownloads": {
    "enabled": true,
    "defaultQualityMode": "smart",
    "useLastSetup": true,
    "askEveryTime": false,
    "issueHandlingMode": "kaevoAssist",
    "notifyIssues": true,
    "suggestLowerQualityOnFailure": "askFirst",
    "maxRetryCount": 3,
    "allowCellularDownloads": false,
    "lastSetup": {
      "quality": "p720",
      "sourceQuality": "p1080",
      "issueHandlingMode": "kaevoAssist",
      "notifyIssues": true,
      "usedAt": "2026-07-08T00:00:00Z"
    }
  }
}
```

### PUT `/profiles/{profileId}/settings/travel-downloads`

Updates Travel Download settings.

Request:

```json
{
  "defaultQualityMode": "p720",
  "useLastSetup": true,
  "askEveryTime": false,
  "issueHandlingMode": "kaevoAssist",
  "notifyIssues": true,
  "suggestLowerQualityOnFailure": "askFirst",
  "maxRetryCount": 3,
  "allowCellularDownloads": false
}
```

## Job endpoints

### POST `/travel-downloads/jobs`

Creates a metadata job. This does not move media through Cloud.

Request:

```json
{
  "profileId": "profile_abc",
  "deviceId": "device_iphone_123",
  "serverId": "server_home_123",
  "mediaProvider": "jellyfin",
  "mediaItemId": "jellyfin_item_123",
  "mediaType": "movie",
  "requestedQuality": "p720",
  "sourceQuality": "p1080",
  "issueHandlingMode": "kaevoAssist",
  "notifyIssues": true
}
```

Response:

```json
{
  "jobId": "td_job_123",
  "status": "queued",
  "prepareStatus": "waiting",
  "downloadStatus": "notStarted",
  "createdAt": "2026-07-08T00:00:00Z"
}
```

### GET `/travel-downloads/jobs/{jobId}`

Returns job metadata and status.

Response:

```json
{
  "jobId": "td_job_123",
  "profileId": "profile_abc",
  "deviceId": "device_iphone_123",
  "serverId": "server_home_123",
  "mediaProvider": "jellyfin",
  "mediaItemId": "jellyfin_item_123",
  "mediaType": "movie",
  "requestedQuality": "p720",
  "sourceQuality": "p1080",
  "status": "preparing",
  "prepareStatus": "running",
  "downloadStatus": "notStarted",
  "issueHandlingMode": "kaevoAssist",
  "notifyIssues": true,
  "retryCount": 1,
  "maxRetryCount": 3,
  "failureReason": null,
  "createdAt": "2026-07-08T00:00:00Z",
  "updatedAt": "2026-07-08T00:04:00Z"
}
```

### PATCH `/travel-downloads/jobs/{jobId}`

Updates metadata/status only.

Request:

```json
{
  "status": "failed",
  "failureReason": "serverOffline",
  "retryCount": 2
}
```

### POST `/travel-downloads/jobs/{jobId}/cancel`

Cancels a job metadata record and asks the local bridge to cancel future/active preparation if connected.

Response:

```json
{
  "jobId": "td_job_123",
  "status": "cancelled"
}
```

## Estimate endpoint

### POST `/travel-downloads/estimate`

Returns metadata estimates only. It may use known source file size, runtime, current transfer speed reported by device, and local bridge preparation hints.

Request:

```json
{
  "profileId": "profile_abc",
  "deviceId": "device_iphone_123",
  "serverId": "server_home_123",
  "items": [
    {
      "mediaProvider": "jellyfin",
      "mediaItemId": "jellyfin_item_123",
      "mediaType": "movie",
      "durationSeconds": 7200,
      "sourceHeight": 1080,
      "sourceSizeBytes": 18000000000
    }
  ],
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
    },
    {
      "quality": "p720",
      "estimatedSizeBytes": 3000000000,
      "estimatedPrepareSeconds": 1200,
      "estimatedDownloadSeconds": 375,
      "confidence": "medium"
    },
    {
      "quality": "original",
      "estimatedSizeBytes": 18000000000,
      "estimatedPrepareSeconds": 0,
      "estimatedDownloadSeconds": 2250,
      "confidence": "high"
    }
  ]
}
```

## Audit endpoint

### GET `/travel-downloads/jobs/{jobId}/audit`

Returns safe user-readable audit events.

Example:

```json
{
  "events": [
    {
      "timestamp": "2026-07-08T00:05:00Z",
      "type": "retryStarted",
      "message": "Download stopped. Kaevo Assist started retry 1 of 3."
    }
  ]
}
```

## Security rules

- Cloud never receives media bytes.
- Cloud never receives preview frames.
- Apple clients never receive provider API keys.
- Job IDs are metadata IDs, not file paths.
- Local paths must never be exposed to the Apple app except as sanitized display text.
- Audit logs must not include secrets or raw headers.
