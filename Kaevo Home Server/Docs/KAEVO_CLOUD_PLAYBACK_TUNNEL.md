# Kaevo Cloud Playback Tunnel Contract

Status: design boundary for the first secure implementation. This document does
not enable remote playback by itself.

## Responsibility split

- Kaevo Cloud authenticates the Kaevo profile and device, selects an online Home
  Connector, and issues a short-lived opaque playback grant.
- The Home Connector creates an outbound encrypted connection. No Jellyfin or
  Home Server port is opened to the public internet.
- Jellyfin selects direct play, live remux, or live transcoding and runs its own
  local FFmpeg process when conversion is required.
- The tunnel transports manifests, byte ranges, and media segments between the
  authenticated Kaevo client and that one Jellyfin playback session.
- Kaevo Cloud's API and database never receive or store media bytes, provider
  API keys, local filesystem paths, or reusable Jellyfin stream URLs.
- Library optimization remux is a separate Home Server job. It is never implied
  by starting playback and is never performed by Kaevo Cloud.

## Grant contents

The signed grant identifies only:

- Kaevo profile and device
- Home Connector
- Jellyfin item and media-source identifiers
- Jellyfin playback-session identifier
- allowed playback mode: direct play, remux, or transcode
- maximum concurrent streams and optional bandwidth ceiling
- issued-at, not-before, and expiry (60–300 seconds)
- random nonce for one-time redemption

The grant must not contain a local URL, API key, filesystem path, or provider
secret. A redeemed grant becomes bound to the resulting tunnel connection and
cannot be replayed on another device or connector.

## Local route policy

The connector accepts playback intents, not arbitrary URLs. It resolves those
intents locally into the Jellyfin playback-info, manifest, segment, and bounded
byte-range operations required by the selected session. It must reject:

- an arbitrary host, port, URL, or filesystem path
- Jellyfin administration, plugin, user-management, or provider routes
- a different item, media source, session, profile, or device
- range requests beyond the selected media resource
- expired, reused, unsigned, or mismatched grants
- requests above per-profile concurrency or bandwidth limits

Artwork and metadata use separate bounded read-only paths; they do not share a
playback grant.

## Transcoding lifecycle

1. The client requests playback for a selected Jellyfin item.
2. Jellyfin returns playback information and chooses direct play, remux, or
   transcode based on client capabilities.
3. For transcode/remux, Jellyfin starts local FFmpeg and exposes the session's
   manifest and segments only to the Home Connector.
4. The client fetches those resources through the encrypted tunnel. Range,
   cancellation, and backpressure signals are preserved.
5. Disconnect, expiry, or client cancellation closes the tunnel and stops the
   corresponding local Jellyfin session when it has no remaining consumer.
6. Playback progress is reported through the genuine Jellyfin session contract,
   not a free-form Cloud write command.

## Required proof before release

- TLS and grant-signature verification, nonce replay tests, and device binding
- direct-play byte-range and seek tests
- live-remux and live-transcode manifest/segment tests
- disconnect and cancellation stop local work promptly
- bandwidth, concurrency, and request-size limits
- a negative suite proving the tunnel cannot reach arbitrary LAN services
- audit records containing only safe identifiers, outcome, byte count, duration,
  and sanitized error category
- verification that no Cloud log, database, trace, or error payload contains
  media bytes, local paths, provider secrets, or reusable playback URLs
