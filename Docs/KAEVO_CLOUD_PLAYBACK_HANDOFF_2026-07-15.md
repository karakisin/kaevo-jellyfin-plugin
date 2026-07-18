# Kaevo Cloud Playback Handoff

Updated: 2026-07-15 (Build 20, plugin 0.2.21, relay 0.2.9)

Use this document as the starting point for the next Codex conversation. It
records the completed Cloud-efficiency, playback, audio-transcoding, request,
and Jellyfin progress-sync work.

## Current verified state

- Kaevo iOS: `1.0 (20)` is signed and installed on Jefferson's iPhone.
- Build 19 failed before AVPlayer issued an HTTP request because its detail-owned
  UIKit anchor was dismantled during presentation. Build 20 moves ownership to
  the persistent app root and presents from the real window controller.
- Kaevo Cloud: `0.0.29` is deployed and healthy in `us-west-2`.
- Cloud health: `GET /dev/health` returned `state: ok`.
- Kaevo Jellyfin Plugin: `0.2.21` builds, packages, and is published in the
  Jellyfin catalog.
- The server last verified `0.2.20`. Install `0.2.21` before final playback and
  progress validation; the updated status must report
  `hls-bounded-buffer-v3`.
- Playback relay `0.2.9` is deployed and publicly healthy.
- Remote metadata, playback preparation, provider routing, and local
  transcoding remain plugin-first. AWS does not transcode media.

## Architecture boundary

- The iOS app requests metadata, artwork, provider actions, and playback.
- Kaevo Cloud authenticates the subscription/profile, validates bounded
  commands, prioritizes work, and carries control messages.
- The Kaevo Jellyfin Plugin owns Jellyfin access, provider credentials, local
  media access, playback preparation, and local transcoding.
- Provider secrets, Jellyfin credentials, filesystem paths, and raw media URLs
  are never returned through Cloud metadata responses.
- Cloud remains a control plane. Media processing stays on the home server.

## Cloud traffic improvements

- Added a two-second single-flight/recent-result window for identical remote
  metadata requests. Concurrent callers now share one request.
- Reduced concurrent Cloud artwork work from eight requests to four while
  preserving URL de-duplication and failure backoff.
- Kept previously loaded episode rows visible during transient refresh errors.
- Added bounded retry for season and episode metadata rather than unbounded
  request loops.
- Playback progress is sent at a bounded interval and does not poll for a Cloud
  response after every update.
- Command priorities now protect interactive work from artwork bursts:

  - `0`: playback preparation
  - `1`: playback started/progress/stopped
  - `10-12`: item, season, and episode details
  - `30`: library snapshots
  - `90`: artwork

## Playback and audio transcoding

- Playback negotiation is codec-aware.
- Compatible video is copied whenever possible.
- Unsupported video requests local Jellyfin H.264 transcoding.
- Unsupported audio requests local Jellyfin AAC transcoding.
- Unsupported audio can therefore use AAC HLS while compatible video remains
  stream-copied.
- Cellular and Wi-Fi use the same functional playback path. Network-specific
  bitrate policy can remain separate without disabling features.
- Transcoding happens on the Jellyfin home server, not in AWS.

## Two-way Jellyfin playback state

- iOS now creates bounded Cloud commands for:

  - `jellyfin.playback_started`
  - `jellyfin.playback_progress`
  - `jellyfin.playback_stopped`

- Commands include safe item, media-source, play-session, position, and pause
  fields. Progress commands use time-bucketed idempotency.
- Plugin `0.2.20` translates these commands to Jellyfin session endpoints.
- Kaevo continues reading Jellyfin `UserData` during metadata refresh, so
  progress created in Jellyfin can flow back into Kaevo.
- Final end-to-end validation requires plugin `0.2.20` to be installed.

## TV detail and Seerr reliability

- TV season and episode loads use bounded retries.
- A temporary Cloud/Jellyfin error no longer erases already visible episodes.
- Remote Seerr detail and request commands use the plugin-backed Cloud route
  instead of attempting an unreachable LAN URL on cellular.
- Terminal failed, declined, or unavailable Seerr records no longer permanently
  block a fresh request.
- Safe exact-match cancellation is available for terminal stale records.
- Focused Seerr tests cover canonical TMDb identity, duplicate protection,
  stale correlation cleanup, and exact HTTP error preservation.

## Security and request validation

- Playback-report commands require an active profile-authorized Cloud session.
- Item IDs, media-source IDs, play-session IDs, positions, and pause state are
  validated and bounded before queueing.
- Provider commands remain allowlisted.
- API keys and provider credentials remain local to the plugin secret store.
- No credentials or private tokens were added to documentation.

## Implementation files

### iOS

- `iOS Kaevo v2/Cloud/KaevoCloudRemoteMetadataStore.swift`
- `iOS Kaevo v2/Integrations/HTTP/KaevoJellyfinPrimaryImageLoader.swift`
- `iOS Kaevo v2/Playback/KaevoJellyfinPlaybackRouteBuilder.swift`
- `iOS Kaevo v2/Playback/KaevoPlayerView.swift`
- `iOS Kaevo v2/Screens/Requests/SeerrRequestDetailScreen.swift`
- `iOS Kaevo v2/Screens/Settings/Connections/JellyfinItemDetailScreen.swift`
- `iOS Kaevo v2Tests/KaevoCloudPlaybackTests.swift`
- `iOS Kaevo v2Tests/KaevoSeerrRequestTests.swift`
- `iOS Kaevo v2.xcodeproj/project.pbxproj` (build `16`)

### Jellyfin Plugin

- `src/Kaevo.Plugin.KaevoForJellyfin/Services/KaevoCloudConnectorService.cs`
- `src/Kaevo.Plugin.KaevoForJellyfin/Api/KaevoController.cs`
- `src/Kaevo.Plugin.KaevoForJellyfin/Kaevo.Plugin.KaevoForJellyfin.csproj`
- `scripts/package-plugin.sh`
- `manifest.json`

### Kaevo Cloud

- `api/src/handler.py`
- `api/tests/test_remote_command_contract.py`
- Related playback, image, and infrastructure contract tests remain in the
  existing dirty worktree.

## Validation completed

- Plugin Docker build: passed.
- Plugin Docker package: passed.
- Plugin tests: `40 passed`.
- Cloud and relay tests: `42 passed`.
- SAM template validation with lint: passed.
- SAM build: passed.
- SAM deployment: passed.
- Live Cloud health: passed, version `0.0.29`.
- iOS Simulator compile: passed.
- Focused playback and Seerr run: `56 tests passed`.
- Physical iPhone build/sign/install/launch: passed for build `16`.
- The broader shared iOS suite still contains unrelated pre-existing fixture,
  production-flag, and shared-state failures. Do not treat those as regressions
  from this focused change without isolating them first.

## Artifacts

- Plugin DLL:
  `Kaevo Jellyfin Plugin/artifacts/build/Kaevo.Plugin.KaevoForJellyfin.dll`
- Plugin ZIP:
  `Kaevo Jellyfin Plugin/artifacts/package/Kaevo.Plugin.KaevoForJellyfin.zip`
- Plugin repository metadata:
  `Kaevo Jellyfin Plugin/artifacts/repository/`
- iPhone app build:
  `/tmp/kaevo-build20-device/Build/Products/Debug-iphoneos/iOS Kaevo v2.app`
- Focused Xcode result:
  `~/Library/Developer/Xcode/DerivedData/iOS_Kaevo_v2-dxyjliqmgdjufgepjhxbzsoobugc/Logs/Test/Test-iOS Kaevo v2-2026.07.15_20-42-29--0700.xcresult`

## Required next step

1. Install Kaevo Jellyfin Plugin `0.2.21` through the existing Jellyfin plugin
   catalog flow.
2. Restart Jellyfin once.
3. Confirm `/kaevo/status` reports `0.2.21` and `PlaybackRelayProtocol` is
   `hls-bounded-buffer-v3`.
4. Run the physical checks below.

## Physical verification on Jefferson's iPhone

### Audio and playback

1. Disable Wi-Fi and use cellular.
2. Play an item with DTS, TrueHD, AC3, or EAC3 audio.
3. Confirm video and audio start without HTTP `503`.
4. Let playback run for at least two minutes.
5. Rotate the phone to landscape and back to portrait; confirm the player fills
   the screen in both orientations.
6. Repeat one item on Wi-Fi.

### TV metadata

1. Open a multi-season show.
2. Change seasons.
3. Confirm existing episode rows remain visible during refresh.
4. Confirm no persistent `jellyfinHttp503` error.

### Seerr

1. On cellular, search for a previously stale/failed title.
2. Open its request page.
3. Confirm the page refreshes through Cloud and permits a new request when the
   old record is terminal.

### Two-way progress

1. Play in Kaevo for at least 60 seconds, stop, and reopen the item.
2. Confirm Jellyfin and Kaevo show the updated resume position.
3. Play a different item directly in Jellyfin for at least 60 seconds.
4. Pull to refresh Kaevo and confirm the Jellyfin-created progress appears.

## Workspace safety

- iOS branch currently checked out: `feature/media-optimizer-sidecar-app-integration`.
- The iOS, Cloud, and plugin worktrees contain many pre-existing and user-owned
  edits.
- Do not run `git reset --hard`, `git checkout --`, broad cleanup, or
  `git add -A`.
- Stage only explicitly reviewed files if a later conversation publishes this
  work.
- Do not revive the retired Kaevo Home Server/sidecar path for Cloud playback.

## Suggested new-conversation prompt

> Continue from `docs/KAEVO_CLOUD_PLAYBACK_HANDOFF_2026-07-15.md`. First verify
> the current branches and dirty worktrees. Install plugin `0.2.20`, restart
> Jellyfin, confirm version `0.2.20` and protocol `hls-body-ack-v2`, then perform the single controlled
> cellular/Wi-Fi audio playback and two-way progress test. Do not modify approved
> UI or unrelated sidecar work.
