# Kaevo Cloud Parity V1

## Purpose

This document records the verified Cloud prototype so work can resume later
without treating Cloud as the current product path.

## Verified state

| Capability | Prototype status | Current product status |
|---|---|---|
| Provider read | E2E passed | Active through plugin |
| Jellyfin main snapshot | E2E passed | Active through plugin |
| Image proxy | E2E passed | Active through plugin |
| Remote metadata | Live | Read-only |
| Cloud trial session | 0.0.19 live | Session-based |
| Remote playback | Not a supported V1 capability | Deferred |
| Remote mutations | Not a supported V1 capability | Deferred |

## Completed resume criteria

- Jellyfin plugin installation is reliable.
- iOS detects the plugin and presents correct dynamic status.
- Local scan and snapshot behavior is hardened for large libraries.
- Cloud activation occurs through the plugin without a separate home app.
- Metadata and artwork retain strict read-only and response bounds.

## Remaining order

1. Physically validate the new-user trial flow with a fresh profile.
2. Add production subscription receipt validation.
3. Validate remote playback separately.
4. Validate remote mutations separately.

Cloud remains a future premium layer. Jellyfin and the Kaevo plugin remain the
local source of truth.
