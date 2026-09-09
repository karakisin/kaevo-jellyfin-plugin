# Kaevo for Jellyfin 0.3.28

The plugin settings page now follows the exact QR pairing transaction and automatically replaces its QR with a successful connection message after Cloud redemption is recorded locally. An existing paired connection cannot falsely complete a new repair QR. Polling stops on completion, expiration, page exit, or after five minutes. Uncertain status reads never show success.

Adds redacted Home failure logging using fixed stage and error categories only. This is diagnostic support, not a verified fix for the reported Jellyfin Connection Needed screen. No credentials, provider payloads, exception messages, or stack traces are included in this new log.

Validation: 488 plugin tests and four JavaScript monitor tests passed. See the attached isolated Jellyfin compatibility evidence. These tests do not establish physical pairing-screen behavior or iPhone media playback.

Update through the same Kaevo Jellyfin catalog to 0.3.28.0, then manually restart Jellyfin. Keep all existing pairing and provider settings. To physically verify automatic confirmation, create a fresh Repair Kaevo Connection QR and scan it with regular Kaevo on the iPhone 14 Pro Max while leaving the plugin page open. Expected: the QR disappears and the page confirms that this pairing completed. Then open Home so its media request can be checked.

Firebase acceptance remains disabled. This release does not complete the AWS-to-Firebase migration or establish Home/playback recovery.
