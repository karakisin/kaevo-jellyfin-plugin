# Kaevo Cloud iOS Development Integration

## Current scope

Cloud integration work currently targets **iOS only**. tvOS is deferred.

- Live Cloud API: `0.0.19`
- Local foundation: Kaevo Jellyfin Plugin `0.2.1`
- First remote capabilities: metadata and artwork
- Playback and mutations: disabled pending later validation

## Intended user flow

1. Connect Jellyfin.
2. Confirm **Kaevo Jellyfin Plugin Installed**.
3. Choose **Start Cloud Trial**.
4. Kaevo activates the local plugin automatically.
5. Show **Remote Access Ready**.

Normal UI must not request Cloud URLs, connector IDs, pairing codes, API keys,
or server environment variables.

## Cloud session

Version `0.0.19` creates a short-lived trial activation, waits for the installed
plugin to confirm it, and returns a revocable profile-bound session stored in
iOS Keychain. Existing devices completed one-time migration; the retired app
credential and public migration route are disabled.

## App boundaries

- Keep provider secrets in Keychain or inside Jellyfin.
- Never log credentials or pairing material.
- Never send filesystem paths or local service URLs to Cloud.
- Prefer the local Jellyfin route while at home.
- Use Cloud only after the plugin reports online.
