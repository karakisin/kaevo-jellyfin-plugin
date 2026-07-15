# Kaevo Cloud Plan

## Goal

Offer optional, simple remote access through the installed Kaevo Jellyfin
Plugin while keeping normal family setup free of server terminology.

## C1 — Friction-free activation

- Present **Start Cloud Trial** in Kaevo iOS.
- Create a short-lived pairing request.
- Activate the local Kaevo plugin from the signed-in app.
- Show **Remote Access Ready** after the plugin is online.
- Hide URLs, IDs, tokens, and pairing codes from normal UI.

Status: working live in `0.0.19` with plugin-confirmed app sessions.

## C2 — Remote library

- Bounded metadata snapshots
- Artwork proxying with strict type and size limits
- Continue Watching metadata
- Cache and retry behavior for large libraries

Status: metadata and artwork are live; cache and image completeness continue
as client quality work.

## C3 — Production identity and billing

- Replace temporary development authentication with a profile-bound app
  session. Completed in `0.0.19`.
- Remove the one-time migration route and retired app credential. Completed.
- Activate, inspect, and revoke plugin-confirmed trial sessions. Implemented.
- Add App Store subscription receipt validation. Pending.

## Later approvals

- Remote playback through a dedicated secure relay
- Reversible Jellyfin user-data writes
- Additional providers

## Non-goals

- No media storage in Cloud
- No separate Home Connector product
- No provider secrets in the app or Cloud responses
- No optimizer execution through Cloud
