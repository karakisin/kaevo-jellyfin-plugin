# Kaevo Next Phases

## Phase J1/J2 — Plugin foundation

- Build and package the Jellyfin plugin with Docker.
- Install it in Jellyfin 10.11.x.
- Validate `GET /kaevo/status`.
- Validate `GET /kaevo/media-scan`.
- Validate `GET /kaevo/main-snapshot`.

Status: completed for the current local Jellyfin installation; retain these as
release checks.

## Phase J3 — Kaevo app integration

- Detect the plugin from iOS.
- Show in-app installation guidance when it is missing.
- Show dynamic installed status when detection succeeds.
- Add automatic Jellyfin discovery and a focused first-run flow.

Status: plugin detection and dynamic status are complete; discovery remains.

## Phase J4 — Read-only hardening

- Use bounded, paginated scans for large libraries.
- Harden retry and timeout behavior.
- Validate image metadata without returning image binaries.
- Validate collections and Continue Watching snapshots.
- Add safe diagnostics that never reveal credentials.

Status: the authoritative Recently Added feed, visible refresh feedback,
last-known-good retention, bounded snapshots, and prioritized Cloud requests are
implemented. Transient artwork recovery and large-library coverage continue.

## Phase P1 — Playback experience

- Preserve the locked Home and library presentation.
- Polish video detail and internal player presentation.
- Validate playback start and recovery on Wi-Fi and cellular.
- Validate pause, resume, seeking, and local progress persistence.
- Validate direct-compatible audio and local audio transcoding.
- Keep remote mutations disabled.

## Future Cloud

- Plugin-backed activation, metadata, and images are implemented.
- Existing-device migration and session rotation are complete.
- Cloud `0.0.26` and Plugin `0.2.13` support controlled remote playback tests.
- Physically validate the trial flow with a fresh profile.
- Add App Store subscription receipt validation.
- Harden remote playback before public release.
- Add remote mutations later with separate safeguards and approval.
