# Kaevo for Jellyfin 0.3.29

Fixes a Home preparation failure when Cloud's current exact profile binding conflicts with a stale local mapping for a deleted profile. Authenticated Jellyfin GET claims now use their Cloud-supplied connector-confined profile binding for that request only. They no longer attempt to persist that edge over an older local mapping before reading media. Stored identities and bindings, provider settings, command authorization and compare-and-swap protections remain unchanged. No identity or deletion receipt is fabricated.

Validation: 494 plugin tests passed, including reproduction of stale ownership, request isolation, preservation of metadata enablement, and rejection of wrong provider/connector/method/user scope. The exact dependency package is verified; see attached isolated Jellyfin 10.11.11 compatibility evidence. Physical Home loading and decoded playback remain unverified until installation.

Install 0.3.29.0 through the same existing Kaevo catalog, then manually restart Jellyfin. Keep your existing connection; no QR scan is required. Open Home in regular Kaevo on the iPhone 14 Pro Max. Expected: the stale local mapping no longer blocks the authenticated Home media read.

Retains 0.3.28's automatic exact-QR success confirmation. Firebase acceptance remains disabled; this is not a completed AWS-to-Firebase migration release.
