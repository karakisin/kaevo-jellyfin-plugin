# Travel Downloads — Phased Implementation Checklist

## Phase 1 — App foundation, no real media work

Goal: Build the settings and flow foundation without touching FFmpeg/Jellyfin media transfer.

- [ ] Add `TravelDownloadQuality` enum.
- [ ] Add `TravelDownloadIssueHandlingMode` enum.
- [ ] Add `TravelDownloadSettings` model.
- [ ] Add `LastTravelDownloadSetup` model.
- [ ] Add `TravelDownloadJob` model.
- [ ] Add dynamic quality option builder.
- [ ] Add estimate placeholder model.
- [ ] Add Kaevo Assist safe action policy.
- [ ] Add `Settings > Downloads > Travel Downloads` screen.
- [ ] Add first-time setup state.
- [ ] Add Use Last Setup sheet.
- [ ] Add Ask Every Time behavior.
- [ ] Add unit tests.
- [ ] Update docs.

## Phase 2 — Cloud preference sync

Goal: Persist Travel Download settings in Kaevo Cloud profile settings.

- [ ] Add profile settings fields.
- [ ] Add GET settings endpoint.
- [ ] Add PUT settings endpoint.
- [ ] Add Cloud sync model in iOS.
- [ ] Handle offline/local fallback.
- [ ] Add migration/default settings.
- [ ] Add backend tests.

## Phase 3 — Job metadata foundation

Goal: Create jobs without real media preparation.

- [ ] Add job creation endpoint.
- [ ] Add job status endpoint.
- [ ] Add job cancel endpoint.
- [ ] Add failure reason enum.
- [ ] Add audit events.
- [ ] Add placeholder job queue UI.
- [ ] Add tests for retry limits and Kaevo Assist permissions.

## Phase 4 — Local Bridge inspect and estimate

Goal: Local server can inspect media and provide metadata.

- [ ] Add Local Bridge health endpoint.
- [ ] Add media inspect endpoint.
- [ ] Pull source resolution, runtime, size, codecs.
- [ ] Return available quality options.
- [ ] Add estimate endpoint.
- [ ] Add security/token gate.
- [ ] Add tests with fixture metadata.

## Phase 5 — Real prepare and download

Goal: Prepare files locally and download to iPhone.

- [ ] Add local prepare endpoint.
- [ ] Add background worker.
- [ ] Add duration validation.
- [ ] Add range-request file endpoint.
- [ ] Use background-capable download on iOS.
- [ ] Store offline file safely on device.
- [ ] Handle pause/resume.
- [ ] Add progress UI.
- [ ] Add failure and retry UI.

## Phase 6 — Preview comparison

Goal: Show real 480p vs 720p comparison.

- [ ] Add static bundled comparison images first.
- [ ] Add local preview frame endpoint later.
- [ ] Generate same frame per quality locally.
- [ ] Never upload preview frames to Kaevo Cloud.
- [ ] Cache temporarily on device.

## Phase 7 — Polish

- [ ] Per-profile defaults.
- [ ] Kids profile storage saver mode.
- [ ] Travel Mode.
- [ ] Auto-remove watched downloads after sync.
- [ ] Better server-specific preparation estimates.
- [ ] Audit history screen.
