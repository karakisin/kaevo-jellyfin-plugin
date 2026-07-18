# Kaevo Current Status

Updated: 2026-07-16 (PiP complete; season cards and crash-safe local resume)

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
- Current physical checkpoint: Kaevo `1.0 (26)` is signed and installed on
  Jefferson's iPhone.
- Jefferson physically confirmed Picture in Picture complete.
- Season Selector behavior is complete. Its episode cards now match the approved
  dark-card reference with functional Play, Details, overflow, and watched
  actions, plus a thumbnail watched icon and the same progress indicator used by
  Home Continue Watching. Physical visual verification of this refinement is
  still pending.
- Local Kaevo resume persistence is now the shipping default. Eligible playback
  is atomically checkpointed every five seconds before remote reporting so an
  unexpected termination can recover near the last playhead position. Jellyfin
  progress writes and watched/completed provider mutations remain separately
  gated.
- When multiple selected household profiles have different valid saved watch
  times, Kaevo asks where everyone should start and lists each eligible profile
  with its timestamp. Identical timestamps continue without an unnecessary
  prompt. Jefferson physically verified this flow on iPhone; the household
  resume picker is complete.
- Series More Options now includes a confirmed `Rewatch Series` action. It clears
  episode progress for the active Kaevo profile, clears the connected Jellyfin
  account's watched state for that series, and begins again from Season 1 Episode
  1. Other Kaevo profiles and unrelated series are preserved. Physical
  verification is pending.
- Playback is presented by a UIKit-owned full-screen hosting controller that
  explicitly supports portrait and both landscape orientations.
- Build 19's detail-owned zero-size presentation anchor was rejected after it
  caused immediate player teardown and a clipped warning overlay. Build 20 owns
  the transient playback descriptor and presenter at the persistent app root
  and presents from the real window controller.
- Playback requests Apple-compatible H.264/HEVC + AAC HLS. Jellyfin remuxes
  compatible video, converts unsupported audio to AAC, and software-transcodes
  video when the source cannot be safely played by AVPlayer.
- Multi-language audio choices now rebuild the approved HLS route with the
  selected Jellyfin audio stream while preserving the playhead and play state.
- Text captions use a grant-bound WebVTT overlay and do not replace or restart
  the active video session. Rewinding while captions
  are off temporarily enables the preferred caption track until the amount
  rewound has replayed, plus five additional seconds.
- Library restores its last selected filter set instead of preselecting
  Trending on every new screen instance.
- Home pull-to-refresh has visible `Refreshing…` and `Updated` feedback and a
  queued forced refresh survives SwiftUI gesture cancellation.
- Recently Added uses the plugin's authoritative feed, collapses episode batches
  to one card per series, and uses the tagged main series poster.
- Plugin-backed remote metadata and playback are active for controlled testing.
- Automatic Jellyfin discovery remains a next step.
- tvOS is not part of the current implementation pass.

### Kaevo Jellyfin Plugin

- Foundation baseline: `0.1.0`.
- Current built, packaged, published, and active server version: `0.2.28`.
- Plugin `0.2.28` securely relays media-source-bound WebVTT captions without
  restarting HLS playback and leaves Jellyfin transcoding available as the
  compatibility fallback.
- Target: Jellyfin `10.11.x`, .NET `net8.0`.
- Supported current product scope: bounded metadata, artwork, Cloud control
  requests, and remote playback routing. Remote writes remain disabled.
- Active endpoints: `/kaevo/status`, `/kaevo/media-scan`, and
  `/kaevo/main-snapshot`.
- Cloud connector and playback channels are online. Remote mutations remain
  disabled.

### Kaevo Cloud

- Version `0.0.29` is live with plugin-backed metadata, artwork, and playback
  request routing.
- Playback relay `0.2.12` is live and publicly healthy. It uses bounded response
  queues, waits for available capacity, and automatically removes expired HLS
  requests so abandoned AVPlayer work cannot permanently block new playback.
- iOS has physically verified **Remote Access Ready** over cellular.
- Plugin-confirmed Cloud trials and revocable, profile-bound app sessions are
  live.
- The physical iPhone completed one-time migration and session rotation; the
  retired app credential and public migration route are disabled.
- Live health, guarded session routes, existing app compatibility, and the
  existing plugin connector passed after deployment.
- The post-deployment signed-stream gate passed the master playlist, child
  playlist, a real 4.67 MB segment, and `10/10` rapid starts.
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

See
[KAEVO_CLOUD_PLAYBACK_HANDOFF_2026-07-15.md](KAEVO_CLOUD_PLAYBACK_HANDOFF_2026-07-15.md)
for the exact implementation, validation evidence, artifacts, and next physical
test.
