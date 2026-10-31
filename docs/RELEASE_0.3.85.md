# Kaevo plugin 0.3.85

Fixes intermittent Cloud connection admission failures when the server clock differs slightly from the credential issuer. Ticket and Firebase token lifetimes are measured from their issue times, retaining the existing 30-second tolerance, original channel expiry, exact identity/channel checks, and listener time limit. Adds fixed-stage diagnostics without credentials or raw provider responses.

Validation: 981 plugin tests passed. The isolated review server completed admission, recovery, fallback, and a five-minute renewal. The affected tester’s post-update cellular verification remains pending.

Install this plugin update and restart Jellyfin, then retry Kaevo’s Connection Health check. No Kaevo app update is required for this plugin fix. Original media, design, and playback settings are unchanged.
