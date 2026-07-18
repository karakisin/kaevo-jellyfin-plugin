# Codex Prompt — Kaevo Travel Downloads Foundation

We are starting the Kaevo “Travel Downloads” feature.

Important architecture rule:
Kaevo Cloud must not host, store, stream, or transcode user media. Kaevo Cloud may only store settings, user preferences, job metadata, entitlement/status metadata, and coordination state. Actual media preparation and download serving will happen later on the user’s home server through Jellyfin or a future Kaevo Local Bridge.

Build as much of the app-side and cloud-preference foundation as possible without implementing real transcoding yet.

Feature name:
Travel Downloads

Helper name:
Kaevo Assist

Goal:
Allow users to select movies/shows for offline travel watching, choose a mobile-friendly quality, reuse their last setup, and choose how Kaevo should handle download issues.

Required user-facing settings location:
Settings > Downloads > Travel Downloads

Settings to support:

1. Default Quality
- Smart Recommended
- Storage Saver 480p
- Recommended 720p
- High Quality 1080p, only relevant when source supports it
- Original Quality
- Ask Every Time

2. Use Last Setup
- On / Off

3. Download Issue Handling
- Kaevo Assist Recommended
- Ask Before Fixing
- Manual
- Ask Every Time

4. Notifications
- On / Off

5. Suggest Smaller Quality If Download Fails
- Ask First
- Never

Store these preferences in the existing Kaevo Cloud/profile settings structure if available. If backend integration is not ready, create local models and persistence stubs that can later sync to Cloud.

Preference model should support something equivalent to:

- travelDownloads.enabled
- travelDownloads.defaultQualityMode
- travelDownloads.useLastSetup
- travelDownloads.askEveryTime
- travelDownloads.issueHandlingMode
- travelDownloads.notifyIssues
- travelDownloads.suggestLowerQualityOnFailure
- travelDownloads.maxRetryCount
- travelDownloads.allowCellularDownloads
- travelDownloads.lastSetup.quality
- travelDownloads.lastSetup.sourceQuality
- travelDownloads.lastSetup.issueHandlingMode
- travelDownloads.lastSetup.notifyIssues
- travelDownloads.lastSetup.usedAt

Quality enum:

- smart
- p480
- p720
- p1080
- original
- askEveryTime

Issue handling enum:

- kaevoAssist
- askBeforeFixing
- manual
- askEveryTime

Build dynamic quality option logic:

- If original source is 4K: show 480p, 720p, 1080p, Original 4K
- If original source is 1080p: show 480p, 720p, Original 1080p
- If original source is 720p: show 480p, Original 720p
- If original source is 480p or lower: show Original only

Do not show duplicate quality choices. For example, if the source is already 720p, do not show “720p”; show “Original 720p.”

Create a Travel Download start flow UI:
When a user starts a new Travel Download, if “Use Last Setup” is enabled and a previous setup exists, show:

“Use your last Travel Download setup?”

Then show:
Last time you chose:
[Quality]
Kaevo Assist: [Issue handling summary]
Notifications: [On/Off]

Buttons:

- Use Last Setup
- Change for This Download
- Ask Me Every Time

Also show this helper text:
“You can change this anytime in Settings > Downloads > Travel Downloads.”

If the user chooses “Use Last Setup,” continue using saved preferences.
If the user chooses “Change for This Download,” show the full quality and issue-handling selectors.
If the user chooses “Ask Me Every Time,” save that preference and always show the full flow in the future.

Quality picker copy:

Storage Saver 480p
Good enough for phone screens. Downloads faster and lets you fit more.

Recommended 720p
Sharper and better for most phones. Uses more storage than 480p.

High Quality 1080p
Great for iPad, hotel TVs, or larger screens. Smaller than 4K but still sharp.

Original Quality
Best available quality. Largest file and may take much longer.

Kaevo Assist copy:

Kaevo Assist Recommended
Kaevo can retry safe download issues automatically and notify you if something needs attention.

Ask Before Fixing
Kaevo will explain the issue and ask before trying to fix it.

Manual
Kaevo will show the issue, but you handle it yourself.

Ask Every Time
Choose how Kaevo handles issues for each Travel Download.

Create job/status models but keep real media work stubbed for now.

Travel Download job fields should support:

- jobId
- userId
- profileId
- deviceId
- serverId
- mediaProvider
- mediaItemId
- mediaType
- requestedQuality
- sourceQuality
- status
- prepareStatus
- downloadStatus
- issueHandlingMode
- notifyIssues
- retryCount
- maxRetryCount
- createdAt
- updatedAt

Job status enum:

- queued
- preparing
- readyToDownload
- downloading
- paused
- completed
- failed
- cancelled
- expired

Failure reason enum:

- serverOffline
- insufficientPhoneStorage
- insufficientServerStorage
- prepareFailed
- downloadInterrupted
- networkTooSlow
- fileValidationFailed
- unsupportedSource
- permissionDenied
- unknown

Kaevo Assist safe automatic actions:

- Retry failed download
- Resume interrupted download
- Reconnect to home server
- Recheck phone storage
- Recheck server availability
- Validate prepared file
- Rebuild failed mobile version
- Pause on poor connection and resume later

Actions that must ask first:

- Try smaller quality
- Delete prepared temporary files
- Clear local offline downloads
- Switch from Wi-Fi to cellular
- Use cellular for large downloads

Actions that must never happen automatically:

- Delete original media
- Change Jellyfin libraries
- Change server paths
- Change provider settings
- Remove user files
- Downgrade quality silently

For this implementation pass:

- Focus on models, settings, UI, dynamic quality logic, saved last setup behavior, and clear placeholder states.
- Do not implement actual FFmpeg/Jellyfin transcoding yet.
- Do not store media in Kaevo Cloud.
- Do not add third-party provider secrets to the app.
- Keep the code consistent with existing Kaevo architecture, naming, tests, and documentation process.
- Add tests for enum decoding/encoding, dynamic quality option generation, last setup behavior, estimate formatting, and issue-handling preference behavior.
- Update PROJECT_STATUS.md, AI_HANDOFF.md, SPRINT_LOG.md, TODO.md, and any relevant docs after implementation.
