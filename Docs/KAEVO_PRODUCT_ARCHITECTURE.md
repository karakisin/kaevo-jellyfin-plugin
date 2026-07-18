# Kaevo Product Architecture

## Product components

```text
Kaevo App
   |
   | local authenticated access
   v
Kaevo Jellyfin Plugin
   |
   | future outbound activation
   v
Kaevo Cloud (later)
```

## Kaevo app

- Presents Home, Library, Search, Requests, Downloads, Profiles, and Playback.
- Finds Jellyfin, signs the user in, and checks plugin readiness.
- Keeps normal setup simple and family-friendly.
- Stores sensitive sign-in material in the device Keychain.

## Kaevo Jellyfin Plugin

- Runs inside the user's existing Jellyfin installation.
- Provides bounded scan, metadata, image-tag, and snapshot access.
- Keeps local media processing with Jellyfin and the home server.
- Becomes the future secure local foundation for optional Kaevo Cloud features.

## Why plugin-first

- Users already understand Jellyfin and its plugin catalog.
- There is no separate Kaevo server product to install or maintain.
- Kaevo can detect readiness and guide setup from the app.
- Local metadata remains close to Jellyfin.
- Advanced remote features can be added without complicating first-run setup.

## Kaevo Cloud

Cloud has resumed through the plugin-backed path. The active experience is:

1. The user chooses **Start Cloud Trial** in Kaevo.
2. Kaevo confirms the plugin is installed.
3. The plugin securely activates outbound Cloud access.
4. Kaevo shows **Remote Access Ready**.

Cloud settings, infrastructure addresses, and credentials are not normal
user-facing setup fields. Remote metadata and images are active; remote playback
and mutations require later, separately approved phases.

## Boundaries

- No provider secrets in app-visible payloads or documentation.
- No image binaries from the initial snapshot endpoints.
- No stream URLs from the initial snapshot endpoints.
- No Cloud relay, remote playback, or remote mutations in the current phase.
