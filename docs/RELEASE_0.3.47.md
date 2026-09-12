# Kaevo 0.3.47

This diagnostic release separates more of the remaining hardware-transcode startup delay. The previous capture measured a long interval between FFmpeg process startup and initial output but could not distinguish input discovery from output initialization. No speed improvement is claimed.

The existing administrator-armed, five-minute capture now observes FFmpeg driver opening, input discovery, stream mapping, HLS output initialization and first progress. It reads Jellyfin's existing flushed log for the exact source/device/play-session job, verifies the complete command line internally, and emits only named phases and elapsed timings. It never consumes FFmpeg's standard-error stream or records raw log text, source paths or credentials.

File discovery, reads and observation lifetime are bounded: at most 64 candidate names per search, eight searches, 512 KiB total reads, and the existing maximum 30-second origin operation. Unrelated, ambiguous, old, truncated or symbolic-link logs are rejected. A verified file handle prevents pathname replacement from switching to another log. Errors disable log observation without failing playback. Sampling and log flush timing mean these are observations, not exact CPU/GPU execution timestamps.

The native player, video detail page, direct-play negotiation, hardware encoder configuration, source files, quality, resume, Family Sync, Firebase authority and capacity remain unchanged. No prepared video copies or new recurring service are introduced. Regular app build 209 remains compatible; no app update or pairing repair is required.

Install from the existing Kaevo Jellyfin catalog, update to 0.3.47.0, restart Jellyfin manually, and confirm the version is Active. Keep the existing plugin pairing and repository URL. The diagnostic control remains off until explicitly armed for a capture.
