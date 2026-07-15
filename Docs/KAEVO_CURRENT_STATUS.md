# Kaevo Current Status

Updated: 2026-07-15

This is the authoritative cross-project status. Older implementation plans and
historical project logs remain useful evidence but do not override this product
direction.

## Product vision

Kaevo is a premium, Apple-like self-hosted media app for iOS and tvOS. It is
Jellyfin-first, with Plex and Emby planned later. Kaevo should make a household's
own media library feel calm, polished, and easy to use.

## Current direction

- Jellyfin Plugin-first.
- iOS is the active client focus; tvOS follows the same product direction.
- Kaevo Cloud implementation has resumed through the plugin-backed path.
- The plugin is part of Kaevo setup, not a separate server product.
- Normal setup must avoid infrastructure language and manual Cloud fields.

## Intended setup

1. Download Kaevo.
2. Find or enter Jellyfin.
3. Sign in to Jellyfin.
4. Let Kaevo check for the Kaevo Jellyfin Plugin.
5. Install and activate the plugin when prompted.
6. Use local library features.
7. Start a Kaevo Cloud trial later when remote access is ready.

## Component status

### Kaevo app

- iOS can sign in to Jellyfin and keep the access token in Keychain.
- iOS checks `/kaevo/status` and shows dynamic install or installed wording.
- Current physical checkpoint: Kaevo `1.0 (3)` on Jefferson's iPhone.
- Home pull-to-refresh has visible `Refreshing…` and `Updated` feedback and a
  queued forced refresh survives SwiftUI gesture cancellation.
- Recently Added uses the plugin's authoritative feed, collapses episode batches
  to one card per series, and uses the tagged main series poster.
- Plugin-backed remote metadata and playback are active for controlled testing.
- Automatic Jellyfin discovery remains a next step.
- tvOS is not part of the current implementation pass.

### Kaevo Jellyfin Plugin

- Foundation baseline: `0.1.0`.
- Current built, published, installed, and locally verified version: `0.2.13`.
- Target: Jellyfin `10.11.x`, .NET `net8.0`.
- Supported current product scope: bounded metadata, artwork, Cloud control
  requests, and remote playback routing. Remote writes remain disabled.
- Active endpoints: `/kaevo/status`, `/kaevo/media-scan`, and
  `/kaevo/main-snapshot`.
- Cloud connector and playback channels are online. Remote mutations remain
  disabled.

### Kaevo Cloud

- Version `0.0.26` is live with plugin-backed metadata, artwork, and playback
  request routing.
- iOS has physically verified **Remote Access Ready** over cellular.
- Plugin-confirmed Cloud trials and revocable, profile-bound app sessions are
  live.
- The physical iPhone completed one-time migration and session rotation; the
  retired app credential and public migration route are disabled.
- Live health, guarded session routes, existing app compatibility, and the
  existing plugin connector passed after deployment.
- Playback and interactive metadata requests are prioritized over artwork.
- Remote playback is enabled for controlled iPhone testing. Remote mutations
  remain disabled.

## Next phases

- Harden automatic Jellyfin discovery and first-run setup.
- Polish the video detail and player UI without changing the locked Home,
  Recently Added, Hero, or Continue Watching treatments.
- Validate playback start, pause/resume, seeking, audio compatibility, and
  recovery on Wi-Fi and cellular.
- Continue hardening transient Cloud artwork `500/502` recovery without putting
  artwork ahead of playback or metadata.
- Physically validate the new-user Cloud trial flow with a fresh profile.

See [KAEVO_NEXT_PHASES.md](KAEVO_NEXT_PHASES.md) for the phased plan.
