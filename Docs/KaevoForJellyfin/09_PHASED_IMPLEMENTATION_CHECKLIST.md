# Phased Implementation Checklist — Kaevo for Jellyfin

## Phase 0 — Foundation Docs

- [x] Decide product direction: one Jellyfin plugin install
- [x] Define architecture
- [x] Define setup wizard
- [x] Define API contract
- [x] Define safety boundaries
- [x] Define Codex prompt

## Phase 1 — Plugin Skeleton

Build:
- [ ] Jellyfin plugin project
- [ ] Plugin name/version
- [ ] Plugin configuration
- [ ] Dashboard setup page placeholder
- [ ] Status service
- [ ] Setup service
- [ ] Local API controller
- [ ] Tests

Stop before:
- FFmpeg
- file writes
- downloads
- Sonarr/Radarr write actions

## Phase 2 — Jellyfin Read Layer

Build:
- [ ] Read Jellyfin users
- [ ] Read Jellyfin libraries
- [ ] Select users
- [ ] Select libraries
- [ ] Save setup config
- [ ] Tests for user/library mapping

## Phase 3 — Pairing Foundation

Build:
- [ ] Generate pairing code
- [ ] Expiration
- [ ] Pairing status
- [ ] Cloud pairing placeholder
- [ ] Redaction tests

## Phase 4 — Read-Only Compatibility Scan

Build:
- [ ] Scan selected libraries
- [ ] Read media source info
- [ ] Classify likely direct play/remux/transcode
- [ ] Store scan summary
- [ ] Show scan status
- [ ] Tests proving no file writes

## Phase 5 — Apple App Handoff

Build in iOS/tvOS later:
- [ ] Add Kaevo for Jellyfin connection type
- [ ] Pairing screen
- [ ] Plugin status screen
- [ ] Server setup state
- [ ] Library selection reflection
- [ ] Travel Downloads foundation status
