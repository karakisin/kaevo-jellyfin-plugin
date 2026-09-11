Adds an optional **Capture Next Playback** button under **Cloud Connection → Playback diagnostics**. It records timing for one playback preparation and up to 16 media requests within five minutes. Capture is off by default and excludes credentials, media URLs, file paths and profile details.

The timings separate connector preparation, Jellyfin response headers and first media bytes from relay delivery. Playback routing, codec selection, buffering, permissions, resume behavior and the player interface are unchanged. This is a diagnostic update; it does not claim faster playback or a completed migration.

Validation: 542 tests passed against the release source, 15 configuration-page tests passed, and package dependency checks passed. The exact package is verified in an isolated, network-disabled Jellyfin 10.11.11 instance before publication. This does not verify playback on a physical iPhone.

Update using the existing Kaevo catalog, then restart Jellyfin manually. Keep the existing pairing and saved configuration. Do not start another diagnostic playback until the matching relay timing update is confirmed ready.
