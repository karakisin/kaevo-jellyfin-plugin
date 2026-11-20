# Kaevo plugin 0.3.92

Adds explicit per-video preview-thumbnail generation for readable video files, DVD folders, Blu-ray folders and disc images. Kaevo can show queued, running, completed and failed generation instead of treating a generic metadata-refresh acceptance as completion. Requires the companion Kaevo app update; installing this plugin alone does not add the new app controls.

Generation requires elevated Jellyfin permission or the existing authorized Cloud management path, checks the exact server and video, and runs one bounded job at a time. It uses Jellyfin's existing encoding configuration. Original media, playback settings and library-wide generation settings remain unchanged. Encrypted or unreadable media is not supported. Existing previews are preserved when regeneration fails before committing replacement output.

Validation: all 1,051 plugin tests passed; real DVD, Blu-ray folder and ISO generation passed on isolated Jellyfin 10.11.11 and 12.1.0, with native JPEG readback. Source media hashes remained unchanged. Unauthenticated/non-admin requests and changed-server requests were rejected. A forced write failure preserved existing previews. The companion app passed 38 focused tests and its device build/signature checks.

Personal Alvin playback and preview verification, and live Cloud/iPhone acceptance of this new generation flow, remain pending. This release does not claim those checks have passed. Install from Jellyfin's Kaevo catalog entry and restart Jellyfin to load the new plugin.
