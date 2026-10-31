# Plugin 0.3.86

When a rejected Jellyfin key is successfully repaired, existing playback connections now use the same verified and saved replacement as library requests. Previously they could retain the rejected key and return HTTP 401 even while browsing worked.

The replacement stays limited to the original in-memory connector session, server address and configured Jellyfin user. Explicit keys remain authoritative. Recovery still requires the existing plugin-owned key, exact paired server verification and an atomic save; it never creates a replacement for a revoked key. Playback signatures, profiles, media selection, quality and bitrate settings are unchanged.

This fixes a reproduced stale-key defect. The affected tester must still update and confirm playback on their own server; their latest report does not independently prove that this defect is the only cause of their HTTP 401.
