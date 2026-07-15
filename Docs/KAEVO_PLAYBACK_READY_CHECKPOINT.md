# Kaevo Playback-Ready Checkpoint

Date: 2026-07-15

This checkpoint records the working product state before the next video-detail
and player UI phase.

## Locked product behavior

- Home shows a visible `Refreshing…` indicator during pull-to-refresh and
  briefly confirms `Updated` when complete.
- A forced refresh queued behind an automatic refresh still runs if SwiftUI
  cancels the original pull gesture task.
- Recently Added is ordered from Jellyfin's authoritative movie and episode
  feed.
- Multiple new episodes from one show appear as one series card using the
  tagged main series poster.
- The approved Hero, Continue Watching, Library, Search, navigation, and
  progress-overlay treatments are unchanged unless explicitly reopened.
- User-facing wording stays simple and Apple-like; infrastructure terminology
  remains in diagnostics only.

## Live stack

- Kaevo iOS: `1.0 (3)`, installed and launched on Jefferson's iPhone.
- Jellyfin: `10.11.11` at the current HomeLab server.
- Kaevo Jellyfin Plugin: `0.2.13`, active.
- Kaevo Cloud: `0.0.26`, healthy.
- Plugin Cloud connector: online.
- Remote metadata: enabled.
- Remote playback: enabled with three live playback channels at checkpoint.
- Remote mutations: disabled.

## Validation evidence

- iOS focused media-provider and shared-library-store tests passed.
- The queued-refresh cancellation regression test passed.
- The series-collapse and tagged-poster regression test passed.
- Physical iPhone build and installation succeeded.
- Scoped `git diff --check` passed.
- Cloud health and `/kaevo/status` passed after deployment and plugin restart.
- Earlier deployment gates passed: Cloud/relay `34` tests and Plugin `28` tests.
- Jefferson physically confirmed the refresh feedback and Recently Added result.

## Diagnostic notes

- The prior invisible refresh was real but queued behind a roughly 15-second
  Cloud refresh. The UI now exposes that state.
- The previous repeated TV artwork came from episode-level recent items and
  untagged parent image requests. The display layer now resolves the known
  Series object and its main poster tag.
- Cloud artwork can still produce transient `500/502` responses and ImageIO
  `-17102` messages. Cached artwork commonly succeeds; this remains a separate
  hardening item and must not block playback or metadata requests.

## Next phase

Polish the video detail and internal player experience, then physically test:

1. Player presentation and dismissal.
2. Playback start on Wi-Fi and cellular.
3. Pause, resume, seeking, and progress persistence.
4. Direct-compatible audio and local audio transcoding.
5. Graceful recovery from a temporary playback interruption.

Do not change the locked behaviors above unless Jefferson explicitly reopens
them.
