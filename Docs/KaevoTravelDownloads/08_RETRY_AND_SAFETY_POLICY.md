# Kaevo Assist — Retry and Safety Policy

## Core principle

Kaevo Assist is not unrestricted AI control. It is a permission-based automation layer for Travel Downloads only.

Kaevo Assist can recover common download issues, but it must stay inside a strict allowlist.

## Allowed automatically when mode is `Kaevo Assist Recommended`

These are safe because they only affect the Travel Download job:

- Retry failed download.
- Resume interrupted download.
- Reconnect to home server.
- Recheck phone storage.
- Recheck server availability.
- Validate prepared file.
- Rebuild failed mobile version.
- Pause on poor connection and resume later.

## Must ask first

These can affect user experience, quality, storage, or data use, so Kaevo must ask:

- Try smaller quality.
- Delete prepared temporary files.
- Clear local offline downloads.
- Switch from Wi-Fi to cellular.
- Use cellular for large download.

## Never allowed automatically

These are outside the Travel Download recovery boundary:

- Delete original media.
- Change Jellyfin library paths.
- Change server paths.
- Change provider settings.
- Remove user files.
- Downgrade quality silently.

## Retry limits

Default:

```text
maxRetryCount = 3
```

Rules:

- Do not retry forever.
- Retry count should be per job.
- If the same failure repeats, fall back to user decision.
- If the issue is ambiguous, ask before fixing.
- If server is offline, wait and retry later if allowed.
- If storage is insufficient, do not retry until storage changes or user selects smaller quality.

## Failure handling matrix

| Failure | Kaevo Assist Recommended | Ask Before Fixing | Manual |
|---|---|---|---|
| serverOffline | Retry later, notify if still failing | Ask | Show issue only |
| downloadInterrupted | Resume/retry | Ask | Show issue only |
| prepareFailed | Retry once, then ask | Ask | Show issue only |
| fileValidationFailed | Rebuild prepared file | Ask | Show issue only |
| insufficientPhoneStorage | Ask user | Ask user | Show issue only |
| insufficientServerStorage | Ask user | Ask user | Show issue only |
| networkTooSlow | Pause/resume or ask | Ask | Show issue only |
| unsupportedSource | Ask user | Ask user | Show issue only |
| permissionDenied | Ask user | Ask user | Show issue only |
| unknown | Ask user | Ask user | Show issue only |

## User-facing explanation

```text
Kaevo Assist can retry safe Travel Download issues automatically and notify you if something needs attention. It will not delete your movies, change your server settings, or silently lower your selected quality.
```

## Audit events

Every automatic action should produce a user-readable audit event:

```json
{
  "timestamp": "2026-07-08T00:05:00Z",
  "jobId": "td_job_123",
  "action": "retryFailedDownload",
  "result": "started",
  "message": "Download stopped. Kaevo Assist started retry 1 of 3."
}
```

## Notification policy

If `notifyIssues` is true:

- Notify when Kaevo needs user decision.
- Notify when all retries failed.
- Notify when a download recovers after a failure.
- Avoid noisy notifications for every small progress update.

If `notifyIssues` is false:

- Still show status inside the app.
- Only send critical notifications if user opted into system-critical alerts later.
