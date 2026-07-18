# Codex Prompt — Kaevo for Jellyfin Plugin Foundation

We are building the foundation for Kaevo for Jellyfin.

Product direction:
Kaevo should be installable through a single Jellyfin plugin. The user should not need to manually install multiple plugins, Docker containers, workers, scripts, or command-line tools for the basic Kaevo experience.

User-facing goal:
1. Add Kaevo plugin repository in Jellyfin.
2. Install Kaevo for Jellyfin.
3. Restart Jellyfin.
4. Open Kaevo setup page.
5. Pair with Kaevo.
6. Select Jellyfin users.
7. Select Jellyfin libraries.
8. Done.

Important architecture:
- The Jellyfin plugin is the primary local bridge.
- The plugin owns Jellyfin integration.
- The plugin owns optional provider connections later.
- Kaevo Cloud stores settings, pairing, entitlements, device status, and job metadata.
- Kaevo Cloud must not host, store, stream, transcode, or download user media.
- iOS/tvOS must not store Seerr/Sonarr/Radarr/TMDb API keys directly.
- Provider secrets must stay server-side.

Read these docs first:
- Docs/KaevoForJellyfin/README.md
- Docs/KaevoForJellyfin/01_PRODUCT_SPEC.md
- Docs/KaevoForJellyfin/02_SETUP_WIZARD_UX.md
- Docs/KaevoForJellyfin/03_ARCHITECTURE.md
- Docs/KaevoForJellyfin/04_PLUGIN_API_CONTRACT.md
- Docs/KaevoForJellyfin/05_JELLYFIN_PLUGIN_IMPLEMENTATION.md
- Docs/KaevoForJellyfin/06_PROVIDER_INTEGRATIONS.md
- Docs/KaevoForJellyfin/07_MEDIA_PREP_AND_WORKER_POLICY.md
- Docs/KaevoForJellyfin/08_SECURITY_PRIVACY_SAFETY.md
- Docs/KaevoForJellyfin/09_PHASED_IMPLEMENTATION_CHECKLIST.md

Task:
Create the Phase 1 plugin foundation.

Build:
1. A Jellyfin plugin project skeleton using the current Jellyfin plugin template conventions.
2. Plugin name: Kaevo for Jellyfin.
3. Internal namespace suggestion: Kaevo.Plugin.KaevoForJellyfin.
4. Plugin configuration model.
5. Setup status model.
6. A setup/config dashboard page placeholder if supported by the current template.
7. A Kaevo status endpoint.
8. Placeholder endpoints for:
   - GET /kaevo/status
   - GET /kaevo/setup
   - PUT /kaevo/setup
   - POST /kaevo/pair/start
   - POST /kaevo/pair/complete
   - GET /kaevo/users
   - GET /kaevo/libraries
   - POST /kaevo/scan/start
   - GET /kaevo/scan/status
   - GET /kaevo/providers/status
   - POST /kaevo/providers/test
9. Services:
   - KaevoStatusService
   - KaevoSetupService
   - KaevoPairingService
   - JellyfinUserBridge
   - JellyfinLibraryBridge
   - KaevoCompatibilityScanService
   - KaevoProviderHealthService
   - KaevoSecretRedactionService
10. Tests for:
   - status response
   - setup config save/load
   - pairing code expiration
   - pairing code redaction
   - user/library response shape
   - provider secrets never returned
   - scan placeholder is read-only
   - no destructive actions exist in Phase 1

Do not implement:
- FFmpeg
- MKV to MP4 conversion
- real Travel Downloads
- transcoding
- media file writes
- media file deletion
- Sonarr/Radarr write actions
- Seerr request actions
- cloud media storage
- Apple app provider secret storage

Stop after Phase 1 and summarize:
- files created
- files changed
- tests added
- build/test command used
- build/test results
- any blockers or unknowns
