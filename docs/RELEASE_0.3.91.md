# Kaevo plugin 0.3.91

Fixes connector startup after upgrading an existing V3 pairing with retired legacy transport fields. The session previously cleared those fields only in memory, so the heartbeat's saved-credential consistency check could reject the unchanged pairing before reaching Cloud.

The upgrade now rechecks the same active V3 connector, compares the saved credential snapshot under the store lock, and atomically clears only the retired transport fields. It preserves Jellyfin credentials and current provider configuration. Missing/corrupt state, changed pairing or credentials, and cancellation still fail closed. No revoked key is recreated and no account, profile, media, request, design, or playback setting is changed.

Includes 0.3.90's owner-only verified Seerr request removal. The pre-fix restart regression reproduced the failure; all 1,036 plugin tests passed after correction. Physical request-removal acceptance remains pending until the corrective plugin is running on the personal server.
