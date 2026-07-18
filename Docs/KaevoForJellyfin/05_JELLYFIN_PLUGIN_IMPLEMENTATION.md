# Jellyfin Plugin Implementation Plan

## Goal

Create a Jellyfin plugin named:

Kaevo for Jellyfin

Internal namespace suggestion:
Kaevo.Plugin.KaevoForJellyfin

## Phase 1 Implementation Areas

Plugin Entry:
- Plugin name
- Plugin description
- Plugin version
- Configuration storage
- Dashboard page registration if supported by current template

Configuration should store:
- setup_complete
- cloud_paired
- kaevo_server_id
- selected_user_ids
- selected_library_ids
- enabled_features
- provider config metadata
- protected provider secrets if supported
- last_scan_status
- last_scan_timestamp

Dashboard Page:
- Status
- Pairing
- Jellyfin Users
- Libraries
- Optional Services
- Compatibility Scan
- Diagnostics

API Controller:
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

Suggested services:
- KaevoStatusService
- KaevoSetupService
- KaevoPairingService
- JellyfinUserBridge
- JellyfinLibraryBridge
- KaevoCompatibilityScanService
- KaevoProviderHealthService
- KaevoSecretRedactionService

Tests:
- Status response
- Setup config save/load
- Pairing code expiration
- Pairing code redaction
- Users mapping
- Libraries mapping
- Provider secrets never returned
- Scan service does not write files
- Dangerous actions unavailable in Phase 1

Important:
Do not assume a route, API, package version, or manifest structure without checking the current Jellyfin plugin template.
