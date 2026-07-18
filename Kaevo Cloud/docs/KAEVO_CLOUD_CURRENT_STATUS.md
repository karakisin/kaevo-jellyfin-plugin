# Kaevo Cloud Current Status

Updated: 2026-07-15

> Current detailed handoff:
> `../../docs/KAEVO_CLOUD_PLAYBACK_HANDOFF_2026-07-15.md`

## Decision

Cloud work has been explicitly resumed after the Jellyfin Plugin foundation
was installed and validated. New work must use the plugin-backed architecture;
the retired standalone Home Connector is not supported.

## Current implementation

- Live Cloud API version: `0.0.29`
- Built, packaged, and published Kaevo Jellyfin Plugin version: `0.2.22`
- Pairing exchange and hashed connector-token storage are implemented.
- Authenticated outbound plugin registration and status are implemented.
- Bounded remote metadata requests are implemented.
- Remote image proxying is working live.
- iOS displays **Remote Access Ready** and loads remote metadata and artwork.
- Provider-read, Jellyfin snapshot, and image-proxy E2E passed.
- Plugin-confirmed trial activation and hashed, revocable app sessions are
  live.
- The existing physical iPhone migrated once, rotated its session, removed the
  retired credential, and successfully verified the new session after launch.
- The public migration route is removed and the legacy app credential is
  rejected.

## Version 0.0.19 flow

1. Choose **Start Cloud Trial** in Kaevo.
2. Create a short-lived activation without showing technical fields.
3. Let the installed plugin confirm the activation.
4. Store the returned profile-bound app session in Keychain.
5. Show **Remote Access Ready** and use the session for metadata and artwork.

App sessions cannot edit entitlements, create remote commands, request
playback grants, or read another profile.

## Current playback work

- Playback preparation and codec-aware local transcoding are implemented.
- Unsupported audio requests local AAC transcoding.
- Compatible video remains stream-copied when possible.
- Multi-language audio and subtitle track metadata now stays bounded inside the
  plugin response; text captions are delivered as native HLS renditions.
- Playback relay `0.2.12` is live. It recovered the physical iPhone failure
  where abandoned AVPlayer requests filled all three channels and new streams
  returned `429 connectorBusy`. Each channel now has adequate Apple-player
  concurrency, waits briefly for capacity, and prunes expired HLS work.
- Profile-authorized started, progress, and stopped commands are deployed.
- Cloud request coalescing and priority controls protect interactive metadata
  and playback from artwork bursts.
- Final two-way playback reporting validation remains separate from the
  audio/caption playback pass.

## Deferred

- Remote mutations
- Optimizer execution
- tvOS Cloud UI
- Production subscription activation

## Validation

- Relay transport/security tests: `20 passed`
- Python compilation: passed
- SAM validation and build: passed
- Physical iPhone build: passed
- Live deployment: passed
- Live health and guarded-route checks: passed
- Existing app and plugin connector compatibility: passed
- Live signed HLS gate: master playlist, child playlist, real media segment,
  and `10/10` rapid new starts passed after relay `0.2.12` deployment.
- Existing-device session migration and post-retirement launch: passed

## Safety

- No secrets in source control or documentation.
- No local URLs, provider credentials, or filesystem paths in Cloud responses.
- No separate Home Connector installation.
- No port forwarding required for the plugin connection.
